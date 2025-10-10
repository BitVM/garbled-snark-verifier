use sp1_sdk::{
    ExecutionReport, Prover, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1PublicValues,
    SP1Stdin, SP1VerifyingKey,
};

pub use crate::{
    guest,
    types::{ArchivedSolderedLabelsData, SolderedLabelsData, WiresInput},
};

/// Result of executing the soldering guest without producing a proof.
#[derive(Debug)]
pub struct ExecuteReport {
    pub public_values: SP1PublicValues,
    pub report: ExecutionReport,
}

fn cpu_prover() -> sp1_sdk::CpuProver {
    ProverClient::builder().cpu().build()
}

fn build_stdin(input: &WiresInput) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    let input_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(input).unwrap();

    stdin.write(&input_bytes.as_slice());

    stdin
}

pub fn execute(private_input: &WiresInput) -> ExecuteReport {
    let prover = cpu_prover();
    let stdin = build_stdin(private_input);

    prover
        .execute(guest::elf(), &stdin)
        .run()
        .map(|(public_values, report)| ExecuteReport {
            public_values,
            report,
        })
        .unwrap()
}

pub struct ProvenSolderedLabelsData {
    data: SolderedLabelsData,
    proof: SP1Proof,
    vk: SP1VerifyingKey,
}

pub fn prove(private_input: &WiresInput) -> ProvenSolderedLabelsData {
    let prover = cpu_prover();
    let stdin = build_stdin(private_input);

    tracing::info!("start setup");
    let (pk, vk) = prover.setup(guest::elf());
    tracing::info!("start prove");
    let proof = prover.prove(&pk, &stdin).core().run().unwrap();

    let archived = unsafe {
        rkyv::access_unchecked::<ArchivedSolderedLabelsData>(proof.public_values.as_slice())
    };

    let data = rkyv::deserialize::<SolderedLabelsData, rkyv::rancor::Error>(archived).unwrap();

    ProvenSolderedLabelsData {
        data,
        proof: proof.proof,
        vk,
    }
}

pub fn verify(data: ProvenSolderedLabelsData) -> SolderedLabelsData {
    let pp_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&data.data).unwrap();

    let proof = SP1ProofWithPublicValues {
        proof: data.proof,
        public_values: SP1PublicValues::from(&pp_bytes),
        sp1_version: "".to_owned(),
        tee_proof: None,
    };

    cpu_prover().verify(&proof, &data.vk).unwrap();

    data.data
}

#[cfg(test)]
mod test {
    use std::{
        iter,
        ops::{BitOr, BitXor},
        time::Instant,
    };

    use rand::{rng, Rng};
    use sha2::Digest;
    use test_log::test;

    use crate::types::{ArchivedSolderedLabelsData, SolderedLabelsData, WiresInput};

    fn precalculate_soldered_labels_data(archived: &WiresInput) -> SolderedLabelsData {
        let instances_count = archived.instances_wires.len();

        // Split first instance as base, keep rest as iterator
        let (base_instance, remaining) = archived.instances_wires.split_first().unwrap();
        let wires_count = base_instance.len();

        let mut base_commitment = Vec::with_capacity(wires_count);
        let mut commitments = vec![sha2::Sha256::new(); instances_count - 1];
        let mut deltas = vec![Vec::with_capacity(wires_count); instances_count - 1];

        // Use multizip to lazily iterate through corresponding positions
        // This transposes the iteration: instead of iterating instances then wires,
        // we iterate wires then instances (all at the same position)
        let all_instances = std::iter::once(base_instance).chain(remaining.iter());

        // Create iterators for each instance
        let mut iters: Vec<_> = all_instances.map(|instance| instance.iter()).collect();

        // Process wire by wire across all instances
        for _wire_id in 0..wires_count {
            // Get next wire from base instance
            let base_wire = iters[0].next().unwrap();

            base_commitment.push((
                sha2::Sha256::digest(base_wire.0.to_be_bytes()).into(),
                sha2::Sha256::digest(base_wire.1.to_be_bytes()).into(),
            ));

            // Get corresponding wire from each remaining instance
            for (idx, iter) in iters[1..].iter_mut().enumerate() {
                let instance_wire = iter.next().unwrap();

                commitments[idx].update(instance_wire.0.bitor(instance_wire.1).to_be_bytes());

                let delta0 = base_wire.0.bitxor(instance_wire.0);
                let delta1 = base_wire.1.bitxor(instance_wire.1);
                deltas[idx].push((delta0, delta1));
            }
        }

        SolderedLabelsData {
            deltas,
            base_commitment,
            commitments: commitments
                .into_iter()
                .map(|h| h.finalize().into())
                .collect(),
        }
    }

    fn rnd_input() -> WiresInput {
        let mut rng = rng();

        WiresInput {
            instances_wires: iter::repeat_with(|| {
                iter::repeat_with(|| rng.random()).take(1019).collect()
            })
            .take(7)
            .collect(),
        }
    }

    #[test]
    fn execute() {
        let input = rnd_input();
        let report = super::execute(&input);
        let bytes = report.public_values.as_slice();

        let archived = unsafe { rkyv::access_unchecked::<ArchivedSolderedLabelsData>(bytes) };

        let on_circuit =
            rkyv::deserialize::<SolderedLabelsData, rkyv::rancor::Error>(archived).unwrap();

        let off_circuit = precalculate_soldered_labels_data(&input);

        assert_eq!(on_circuit, off_circuit);
        println!("{}", report.report);
    }

    #[test]
    fn prove_verify_e2e() {
        let input = rnd_input();
        let timer = Instant::now();
        let data = super::prove(&input);
        tracing::info!("prove time is {}", timer.elapsed().as_secs());

        super::verify(data);
        tracing::info!("verify time is {}", timer.elapsed().as_secs());
    }
}

//fn input_from_instances(
//    core_instance: InstanceWires<INPUT_WIRE_COUNT>,
//    additional_instances: [InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE],
//) -> (
//    Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
//    PublicParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
//) {
//    let private_param = PrivateParams::<INPUT_WIRE_COUNT, SOLDERED_INSTANCE> {
//        core_instance,
//        additional_instances: Box::new(additional_instances),
//    };
//    let public_params = common::compute_public_params(&private_param);
//    let input = Input::<INPUT_WIRE_COUNT, SOLDERED_INSTANCE> {
//        public_param: public_params.clone(),
//        private_param,
//    };
//    (input, public_params)
//}
//
///// Execute the soldering guest for a fully constructed input without proving.
//pub fn execute(
//    input: &Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
//) -> Result<ExecuteReport, SolderingError> {
//    execute_internal(input)
//}
//
//fn prove_uncompressed(
//    input: &Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
//) -> Result<SolderingProof, SolderingError> {
//    let prover = cpu_prover();
//    let stdin = build_stdin(input);
//    let (pk, vk) = prover.setup(guest::elf());
//    let proof = prover
//        .prove(&pk, &stdin)
//        .core()
//        .run()
//        .map_err(|err| SolderingError::Proving(err.to_string()))?;
//
//    let proof_bytes = rmp_serde::to_vec(&proof)?;
//    let vk_bytes = rmp_serde::to_vec(&vk)?;
//    Ok(SolderingProof {
//        proof: proof_bytes,
//        verifying_key: vk_bytes,
//    })
//}
//
///// Compute public parameters, execute the guest, and prove soldering for the supplied instances.
//pub fn do_soldering(
//    core_instance: InstanceWires<INPUT_WIRE_COUNT>,
//    additional_instances: [InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE],
//) -> Result<SolderingOutput, SolderingError> {
//    let (input, public_params) = input_from_instances(core_instance, additional_instances);
//
//    let execution = execute_internal(&input)?;
//    let proof = prove_uncompressed(&input)?;
//
//    Ok(SolderingOutput {
//        public_params,
//        proof,
//        execution,
//    })
//}
//
///// Verify that the supplied proof is valid and binds to the provided public parameters.
//pub fn verify_soldering(
//    expected_public: &PublicParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
//    proof: &SolderingProof,
//) -> Result<(), SolderingError> {
//    // Deserialize proof & vk for SP1 verification.
//    let decoded_proof: SP1ProofWithPublicValues =
//        rmp_serde::from_slice(&proof.proof).map_err(SolderingError::SerializationDecode)?;
//    let decoded_vk: SP1VerifyingKey =
//        rmp_serde::from_slice(&proof.verifying_key).map_err(SolderingError::SerializationDecode)?;
//
//    // Verify core proof.
//    cpu_prover()
//        .verify(&decoded_proof, &decoded_vk)
//        .map_err(|err| SolderingError::Verification(err.to_string()))?;
//
//    // Extract the committed public parameters and compare.
//    let mut encoded_expected = SP1PublicValues::new();
//    encoded_expected.write(expected_public);
//
//    if decoded_proof.public_values.as_slice() != encoded_expected.as_slice() {
//        return Err(SolderingError::PublicParamMismatch);
//    }
//
//    Ok(())
//}
//
///// Construct deterministic instances for testing/demo purposes.
//pub fn make_dummy_instances(
//    failed: bool,
//) -> (
//    InstanceWires<INPUT_WIRE_COUNT>,
//    [InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE],
//) {
//    let wires_for_instance: [Wire; INPUT_WIRE_COUNT] = core::array::from_fn(|i| Wire {
//        label0: i as u128,
//        label1: (i + 1) as u128,
//    });
//
//    let mut core_instance = InstanceWires {
//        labels: Box::new(wires_for_instance.clone()),
//    };
//    let additional_instances: [InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE] =
//        core::array::from_fn(|_| InstanceWires {
//            labels: Box::new(wires_for_instance.clone()),
//        });
//
//    if failed {
//        let last_idx = INPUT_WIRE_COUNT - 1;
//        core_instance.labels[last_idx].label1 = 0xFF;
//    }
//
//    (core_instance, additional_instances)
//}
//
///// Build a dummy input directly, primarily for testing.
//pub fn make_dummy_input(failed: bool) -> Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE> {
//    let (core_instance, additional_instances) = make_dummy_instances(failed);
//    let (input, _) = input_from_instances(core_instance, additional_instances);
//    input
//}
//
//#[cfg(test)]
//mod tests {
//    use super::*;
//
//    #[test]
//    #[ignore = "requires SP1 artifact downloads"]
//    fn do_soldering_round_trip() {
//        let (core_instance, additional_instances) = make_dummy_instances(false);
//        let output =
//            do_soldering(core_instance, additional_instances).expect("soldering proof generation");
//        verify_soldering(&output.public_params, &output.proof).expect("soldering verification");
//    }
//}
