#![no_main]
sp1_zkvm::entrypoint!(main);

use core::ops::BitXor;

use rkyv::rancor;
use sha2::{Digest, Sha256};

#[path = "../../src/types.rs"]
pub mod types;
pub use types::*;

#[inline(always)]
fn hash_label_into(hasher: &mut Sha256, label: &rkyv::rend::u128_le, out: &mut [u8; 32]) {
    hasher.update(label.to_native().to_be_bytes().as_slice());
    hasher.finalize_into_reset(out.into());
}

pub fn main() {
    let input_bytes = sp1_zkvm::io::read_vec();

    // Safety:
    //
    // Crate that is used under the hood for consistency checking - does not work in sp1 env.
    // Outside for consistency of ser/deser, the same logic code is executed for checking
    // correctness.
    let archived = unsafe { rkyv::access_unchecked::<ArchivedWiresInput>(input_bytes.as_slice()) };

    let (base_instance, remaining) = archived.instances_wires.split_first().unwrap();
    let soldered_instances_count = remaining.len();
    let nonce = archived.nonce;

    let wires_count = base_instance.len();

    let mut base_commitment = vec![([0u8; 32], [0u8; 32]); wires_count];
    let mut base_nonce_commitment = vec![([0u8; 32], [0u8; 32]); wires_count];

    // Initialize commitments for each instance with proper capacity
    let mut commitments: Vec<Vec<([u8; 32], [u8; 32])>> =
        vec![vec![([0u8; 32], [0u8; 32]); wires_count]; soldered_instances_count];

    let mut deltas = vec![Vec::with_capacity(wires_count); soldered_instances_count];

    // Reuse single hasher for all operations
    let mut hasher = Sha256::new();

    for wire_id in 0..wires_count {
        let base_wire = &base_instance[wire_id];

        // Compute base commitments
        hash_label_into(&mut hasher, &base_wire.0, &mut base_commitment[wire_id].0);
        hash_label_into(&mut hasher, &base_wire.1, &mut base_commitment[wire_id].1);

        // Compute base nonce commitments in the same loop
        let label0_with_nonce = base_wire.0.bitxor(nonce);
        let label0_le = rkyv::rend::u128_le::from_native(label0_with_nonce);
        hash_label_into(
            &mut hasher,
            &label0_le,
            &mut base_nonce_commitment[wire_id].0,
        );

        let label1_with_nonce = base_wire.1.bitxor(nonce);
        let label1_le = rkyv::rend::u128_le::from_native(label1_with_nonce);
        hash_label_into(
            &mut hasher,
            &label1_le,
            &mut base_nonce_commitment[wire_id].1,
        );

        // Get corresponding wire from each remaining instance
        for idx in 0..soldered_instances_count {
            let instance_wire = &remaining[idx][wire_id];

            // Hash each label individually like base instance, reusing the hasher
            hash_label_into(
                &mut hasher,
                &instance_wire.0,
                &mut commitments[idx][wire_id].0,
            );
            hash_label_into(
                &mut hasher,
                &instance_wire.1,
                &mut commitments[idx][wire_id].1,
            );

            let delta0 = base_wire.0.bitxor(instance_wire.0);
            let delta1 = base_wire.1.bitxor(instance_wire.1);
            deltas[idx].push((delta0, delta1));
        }
    }

    let data = SolderedLabelsData {
        deltas,
        base_commitment,
        base_nonce_commitment,
        commitments,
        nonce: nonce.to_native(),
    };

    sp1_zkvm::io::commit(&rkyv::to_bytes::<rancor::Error>(&data).unwrap().as_slice());
}
