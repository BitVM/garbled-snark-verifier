#![no_main]
sp1_zkvm::entrypoint!(main);

use core::ops::BitXor;

use bincode::{config, config::Configuration};
use sha2::{Digest, Sha256};

pub mod types;
pub use types::*;

#[inline(always)]
fn hash_label_into(hasher: &mut Sha256, label: u128, out: &mut [u8; 32]) {
    hasher.update(label.to_be_bytes().as_slice());
    hasher.finalize_into_reset(out.into());
}

pub fn main() {
    let input_bytes = sp1_zkvm::io::read_vec();

    // Use fixed-int encoding to support u128 in SP1
    let config = config::standard().with_fixed_int_encoding();
    let (input, _len): (WiresInput, usize) = bincode::decode_from_slice(&input_bytes, config).unwrap();

    let (base_instance, remaining) = input.instances_wires.split_first().unwrap();
    let soldered_instances_count = remaining.len();
    let nonce = input.nonce;

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
        hash_label_into(&mut hasher, base_wire.0, &mut base_commitment[wire_id].0);
        hash_label_into(&mut hasher, base_wire.1, &mut base_commitment[wire_id].1);

        // Compute base nonce commitments in the same loop
        let label0_with_nonce = base_wire.0.bitxor(nonce);
        hash_label_into(
            &mut hasher,
            label0_with_nonce,
            &mut base_nonce_commitment[wire_id].0,
        );

        let label1_with_nonce = base_wire.1.bitxor(nonce);
        hash_label_into(
            &mut hasher,
            label1_with_nonce,
            &mut base_nonce_commitment[wire_id].1,
        );

        // Get corresponding wire from each remaining instance
        for idx in 0..soldered_instances_count {
            let instance_wire = &remaining[idx][wire_id];

            // Hash each label individually like base instance, reusing the hasher
            hash_label_into(
                &mut hasher,
                instance_wire.0,
                &mut commitments[idx][wire_id].0,
            );
            hash_label_into(
                &mut hasher,
                instance_wire.1,
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
        nonce,
    };

    // Use fixed-int encoding to support u128 in SP1
    let config = config::standard().with_fixed_int_encoding();
    let output_bytes = bincode::encode_to_vec(&data, config).unwrap();
    sp1_zkvm::io::commit_slice(&output_bytes);
}
