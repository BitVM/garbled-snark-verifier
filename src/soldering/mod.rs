//#![allow(dead_code)]
//
//use std::{array, convert::TryInto};
//
//use soldering_core::{
//    SolderingOutput,
//    types::{self},
//};
//
//use crate::{GarbledWire, S};
//
//pub type Sha256Commit = [u8; 32];
//
//pub struct SolderedLabelsData<const INPUT_WIRES_COUNT: usize, const SOLDERED_INSTANCES: usize> {
//    /// Deltas for all instances
//    deltas: [[(S, S); INPUT_WIRES_COUNT]; SOLDERED_INSTANCES],
//    core_commitment: [[Sha256Commit; 2]; INPUT_WIRES_COUNT],
//    commitments: [Sha256Commit; SOLDERED_INSTANCES],
//    proof: Vec<u8>,
//}
//
//#[derive(Debug)]
//pub struct Error(soldering_core::SolderingError);
//
//impl From<soldering_core::SolderingError> for Error {
//    fn from(value: soldering_core::SolderingError) -> Self {
//        Self(value)
//    }
//}
//
//pub fn do_soldering<const LABELS_COUNT: usize, const SOLDERED_INSTANCES: usize>(
//    core_instance: [GarbledWire; LABELS_COUNT],
//    all_instances_wires: [[GarbledWire; LABELS_COUNT]; SOLDERED_INSTANCES],
//) -> Result<SolderedLabelsData<LABELS_COUNT, SOLDERED_INSTANCES>, Error> {
//    assert_eq!(
//        LABELS_COUNT,
//        types::INPUT_WIRE_COUNT,
//        "unexpected label count"
//    );
//    assert_eq!(
//        SOLDERED_INSTANCES,
//        types::SOLDERED_INSTANCE,
//        "unexpected instance count"
//    );
//
//    let to_instance =
//        |wires: &[GarbledWire; LABELS_COUNT]| -> types::InstanceWires<{ types::INPUT_WIRE_COUNT }> {
//            let labels_vec = wires
//                .iter()
//                .map(|wire| types::Wire {
//                    label0: wire.label0.to_u128(),
//                    label1: wire.label1.to_u128(),
//                })
//                .collect::<Vec<_>>();
//            let labels_box: Box<[types::Wire]> = labels_vec.into_boxed_slice();
//            let labels = labels_box
//                .try_into()
//                .expect("invalid soldering label count");
//            types::InstanceWires { labels }
//        };
//
//    let core_instance = to_instance(&core_instance);
//    let additional_instances: [types::InstanceWires<{ types::INPUT_WIRE_COUNT }>; {
//        types::SOLDERED_INSTANCE
//    }] = array::from_fn(|idx| to_instance(&all_instances_wires[idx]));
//
//    let SolderingOutput {
//        public_params,
//        proof,
//        execution: _,
//    } = soldering_core::do_soldering(core_instance, additional_instances)?;
//
//    let types::PublicParams {
//        core_commitment,
//        commitments,
//        deltas0,
//        deltas1,
//    } = public_params;
//
//    // Convert the deltas from soldering_core format to our S type
//    let mut deltas = [[(S::ZERO, S::ZERO); LABELS_COUNT]; SOLDERED_INSTANCES];
//    for instance_idx in 0..SOLDERED_INSTANCES {
//        for wire_idx in 0..LABELS_COUNT {
//            deltas[instance_idx][wire_idx] = (
//                S::from_u128(deltas0[instance_idx].0[wire_idx]),
//                S::from_u128(deltas1[instance_idx].0[wire_idx]),
//            );
//        }
//    }
//
//    let core_commitment_slice = core_commitment.as_ref();
//    let mut core_commitment_result = [[Sha256Commit::default(); 2]; LABELS_COUNT];
//    for wire_idx in 0..LABELS_COUNT {
//        core_commitment_result[wire_idx] = core_commitment_slice[wire_idx];
//    }
//
//    let additional_commitments = commitments.as_ref();
//    let mut commitments_result = [Sha256Commit::default(); SOLDERED_INSTANCES];
//    for instance_idx in 0..SOLDERED_INSTANCES {
//        commitments_result[instance_idx] = additional_commitments[instance_idx];
//    }
//
//    Ok(SolderedLabelsData {
//        deltas,
//        core_commitment: core_commitment_result,
//        commitments: commitments_result,
//        proof: proof.proof,
//    })
//}
//
//pub fn verify_soldering<const INPUT_WIRES_COUNT: usize, const SOLDERED_INSTANCES: usize>(
//    _data: SolderedLabelsData<INPUT_WIRES_COUNT, SOLDERED_INSTANCES>,
//) -> Result<(), Error> {
//    //core_impl::verify_soldering
//    todo!()
//}
//
//#[cfg(test)]
//mod tests {
//    use std::array;
//
//    use test_log::test;
//
//    use super::*;
//    use crate::Delta;
//
//    #[ignore = "slow"]
//    #[test]
//    fn prove() {
//        let mut rng = rand::thread_rng();
//        let delta = Delta::generate(&mut rng);
//        let mut issue = move || GarbledWire::random(&mut rng, &delta);
//
//        let core: [GarbledWire; 1093] = array::from_fn(|_| issue());
//        let to_solder: [[GarbledWire; 1093]; 6] = array::from_fn(|_| array::from_fn(|_| issue()));
//
//        do_soldering(core, to_solder).unwrap();
//    }
//}
