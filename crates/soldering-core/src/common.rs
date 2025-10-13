use sha2::{Digest, Sha256};

use crate::types::{
    Commit, InstanceWires, Label, PrivateParams, PublicParams, ShaDigest, Wire, WireLabels,
};

fn boxed_array_from_vec<T, const N: usize>(vec: Vec<T>) -> Box<[T; N]> {
    assert_eq!(vec.len(), N, "expected array of length {}", N);
    vec.into_boxed_slice()
        .try_into()
        .ok()
        .expect("length checked above; qed")
}

pub(crate) fn xor_labels(base: &Label, other: &Label) -> Label {
    base ^ other
}

pub(crate) fn aggregate_labels_sha256<const INPUT_WIRE_COUNT: usize>(
    instance: &InstanceWires<INPUT_WIRE_COUNT>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for wire in instance.labels.iter() {
        use core::ops::BitOr;
        hasher.update(wire.label0.bitor(wire.label1).to_be_bytes());
    }
    hasher.finalize().into()
}

fn compute_core_commitment<const INPUT_WIRE_COUNT: usize>(
    core_instance: &InstanceWires<INPUT_WIRE_COUNT>,
) -> Box<[[ShaDigest; 2]; INPUT_WIRE_COUNT]> {
    let commitments: Vec<[ShaDigest; 2]> = core_instance
        .labels
        .iter()
        .map(|wire| {
            let label0_commit: ShaDigest = Sha256::digest(wire.label0.to_be_bytes()).into();
            let label1_commit: ShaDigest = Sha256::digest(wire.label1.to_be_bytes()).into();
            [label0_commit, label1_commit]
        })
        .collect();
    boxed_array_from_vec(commitments)
}

fn compute_additional_commitments<const INPUT_WIRE_COUNT: usize, const SOLDERED_INSTANCE: usize>(
    additional_instances: &[InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE],
) -> [Commit; SOLDERED_INSTANCE] {
    core::array::from_fn(|index| aggregate_labels_sha256(&additional_instances[index]))
}

fn compute_wire_delta<const INPUT_WIRE_COUNT: usize>(
    base: &InstanceWires<INPUT_WIRE_COUNT>,
    candidate: &InstanceWires<INPUT_WIRE_COUNT>,
    selector: fn(&Wire) -> &Label,
) -> WireLabels<INPUT_WIRE_COUNT> {
    let delta_labels: Vec<Label> = base
        .labels
        .iter()
        .zip(candidate.labels.iter())
        .map(|(base_wire, candidate_wire)| {
            let base_label = selector(base_wire);
            let candidate_label = selector(candidate_wire);
            xor_labels(base_label, candidate_label)
        })
        .collect();
    WireLabels(boxed_array_from_vec(delta_labels))
}

fn compute_wire_deltas<const INPUT_WIRE_COUNT: usize, const SOLDERED_INSTANCE: usize>(
    core_instance: &InstanceWires<INPUT_WIRE_COUNT>,
    additional_instances: &[InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE],
    selector: fn(&Wire) -> &Label,
) -> Box<[WireLabels<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE]> {
    let deltas: Vec<WireLabels<INPUT_WIRE_COUNT>> = additional_instances
        .iter()
        .map(|instance| compute_wire_delta(core_instance, instance, selector))
        .collect();
    boxed_array_from_vec(deltas)
}

pub(crate) fn compute_public_params<
    const INPUT_WIRE_COUNT: usize,
    const SOLDERED_INSTANCE: usize,
>(
    private_params: &PrivateParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
) -> PublicParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE> {
    let core_instance = &private_params.core_instance;
    let additional_instances = private_params.additional_instances.as_ref();

    let core_commitment = compute_core_commitment(core_instance);
    let additional_commitments = compute_additional_commitments(additional_instances);
    let deltas0 = compute_wire_deltas(core_instance, additional_instances, |wire| &wire.label0);
    let deltas1 = compute_wire_deltas(core_instance, additional_instances, |wire| &wire.label1);

    PublicParams {
        core_commitment,
        commitments: Box::new(additional_commitments),
        deltas0,
        deltas1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{InstanceWires, PrivateParams, Wire, INPUT_WIRE_COUNT, SOLDERED_INSTANCE};

    fn make_instances() -> PrivateParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE> {
        let base_wire = Wire {
            label0: 1,
            label1: 2,
        };
        let wires: [Wire; INPUT_WIRE_COUNT] = core::array::from_fn(|i| Wire {
            label0: base_wire.label0.wrapping_add(i as u128),
            label1: base_wire.label1.wrapping_add(i as u128),
        });
        PrivateParams {
            core_instance: InstanceWires {
                labels: Box::new(wires.clone()),
            },
            additional_instances: Box::new(core::array::from_fn(|_| InstanceWires {
                labels: Box::new(wires.clone()),
            })),
        }
    }

    #[test]
    fn compute_public_params_is_deterministic() {
        let instances = make_instances();
        let params1 = compute_public_params(&instances);
        let params2 = compute_public_params(&instances);
        assert_eq!(params1.commitments.len(), params2.commitments.len());
        assert_eq!(params1.deltas0.len(), params2.deltas0.len());
        assert_eq!(params1.deltas1.len(), params2.deltas1.len());
    }
}
