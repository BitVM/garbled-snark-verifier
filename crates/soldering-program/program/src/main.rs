#![no_main]
sp1_zkvm::entrypoint!(main);

use core::ops::BitXor;
use sha2::{Digest, Sha256};
use soldering_types::{Input, InstanceCommitment, Label};

fn xor_labels(base: &Label, other: &Label) -> Label {
    core::array::from_fn(|byte_index| base[byte_index].bitxor(other[byte_index]))
}

fn aggregate_labels_sha256(instance: &soldering_types::InstanceWires) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for wire in instance.labels.iter() {
        hasher.update(wire.label0);
        hasher.update(wire.label1);
    }
    hasher.finalize().into()
}

pub fn main() {
    let input = sp1_zkvm::io::read::<Input>();

    let core_instance = &input.private_param.input_labels[0];

    for (instance_index, instance) in input.private_param.input_labels.iter().enumerate().skip(1) {
        let soldering_types::WireLabels(delta0_box) = &input.public_param.deltas0[instance_index];
        let soldering_types::WireLabels(delta1_box) = &input.public_param.deltas1[instance_index];

        let delta0 = delta0_box.as_ref();
        let delta1 = delta1_box.as_ref();

        for (wire_index, instance_wire) in instance.labels.iter().enumerate() {
            let base_wire = &core_instance.labels[wire_index];

            let expected_delta0 = xor_labels(&base_wire.label0, &instance_wire.label0);
            let expected_delta1 = xor_labels(&base_wire.label1, &instance_wire.label1);

            assert_eq!(
                expected_delta0, delta0[wire_index],
                "delta0 mismatch for instance {instance_index}, wire {wire_index}"
            );

            assert_eq!(
                expected_delta1, delta1[wire_index],
                "delta1 mismatch for instance {instance_index}, wire {wire_index}"
            );
        }
    }

    for (instance_index, commitment) in input.public_param.commitments.iter().enumerate() {
        match commitment {
            InstanceCommitment::Core { sha256_commit } => {
                assert_eq!(instance_index, 0, "core commitment must be first");
                for (commit, wire) in sha256_commit.iter().zip(core_instance.labels.iter()) {
                    let [label0_commit, label1_commit] = &commit;
                    let calculated_label0_commit = Sha256::digest(wire.label0);
                    let calculated_label1_commit = Sha256::digest(wire.label1);

                    assert_eq!(
                        calculated_label0_commit.as_slice(),
                        label0_commit.as_slice()
                    );
                    assert_eq!(
                        calculated_label1_commit.as_slice(),
                        label1_commit.as_slice()
                    );
                }
            }
            InstanceCommitment::Additional { poseidon_commit } => {
                let instance = &input.private_param.input_labels[instance_index];
                let aggregate_commit = aggregate_labels_sha256(instance);
                assert_eq!(
                    aggregate_commit, *poseidon_commit,
                    "aggregate commitment mismatch for instance {instance_index}"
                );
            }
        }
    }

    sp1_zkvm::io::commit(&input.public_param);
}
