use rmp_serde::{decode::Error as RmpDecodeError, encode::Error as RmpEncodeError};
use serde::{Deserialize, Serialize};
use sp1_sdk::{
    ExecutionReport, Prover, ProverClient, SP1ProofWithPublicValues, SP1PublicValues, SP1Stdin,
    SP1VerifyingKey,
};
use thiserror::Error;

use crate::{
    common, guest,
    types::{
        Input, InstanceWires, PrivateParams, PublicParams, Wire, INPUT_WIRE_COUNT,
        SOLDERED_INSTANCE,
    },
};

/// Errors produced by soldering host helpers.
#[derive(Debug, Error)]
pub enum SolderingError {
    #[error("proving failed: {0}")]
    Proving(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("serialization encode failed: {0}")]
    SerializationEncode(#[from] RmpEncodeError),
    #[error("serialization decode failed: {0}")]
    SerializationDecode(#[from] RmpDecodeError),
    #[error("public params mismatch between proof and expected input")]
    PublicParamMismatch,
}

/// Wrapper around the binary representation of an SP1 core proof for the soldering program.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SolderingProof {
    pub proof: Vec<u8>,
    pub verifying_key: Vec<u8>,
}

/// Combined output of a soldering proof generation run.
#[derive(Debug)]
pub struct SolderingOutput {
    pub public_params: PublicParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
    pub proof: SolderingProof,
    pub execution: ExecuteReport,
}

/// Result of executing the soldering guest without producing a proof.
#[derive(Debug)]
pub struct ExecuteReport {
    pub public_values: SP1PublicValues,
    pub report: ExecutionReport,
}

fn cpu_prover() -> sp1_sdk::CpuProver {
    ProverClient::builder().cpu().build()
}

fn build_stdin(input: &Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>) -> SP1Stdin {
    let mut stdin = SP1Stdin::new();
    stdin.write(input);
    stdin
}

fn execute_internal(
    input: &Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
) -> Result<ExecuteReport, SolderingError> {
    let prover = cpu_prover();
    let stdin = build_stdin(input);
    prover
        .execute(guest::elf(), &stdin)
        .run()
        .map(|(public_values, report)| ExecuteReport {
            public_values,
            report,
        })
        .map_err(|err| SolderingError::Execution(err.to_string()))
}

fn input_from_instances(
    core_instance: InstanceWires<INPUT_WIRE_COUNT>,
    additional_instances: [InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE],
) -> (
    Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
    PublicParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
) {
    let private_param = PrivateParams::<INPUT_WIRE_COUNT, SOLDERED_INSTANCE> {
        core_instance,
        additional_instances: Box::new(additional_instances),
    };
    let public_params = common::compute_public_params(&private_param);
    let input = Input::<INPUT_WIRE_COUNT, SOLDERED_INSTANCE> {
        public_param: public_params.clone(),
        private_param,
    };
    (input, public_params)
}

/// Execute the soldering guest for a fully constructed input without proving.
pub fn execute(
    input: &Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
) -> Result<ExecuteReport, SolderingError> {
    execute_internal(input)
}

fn prove_uncompressed(
    input: &Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
) -> Result<SolderingProof, SolderingError> {
    let prover = cpu_prover();
    let stdin = build_stdin(input);
    let (pk, vk) = prover.setup(guest::elf());
    let proof = prover
        .prove(&pk, &stdin)
        .core()
        .run()
        .map_err(|err| SolderingError::Proving(err.to_string()))?;

    let proof_bytes = rmp_serde::to_vec(&proof)?;
    let vk_bytes = rmp_serde::to_vec(&vk)?;
    Ok(SolderingProof {
        proof: proof_bytes,
        verifying_key: vk_bytes,
    })
}

/// Compute public parameters, execute the guest, and prove soldering for the supplied instances.
pub fn do_soldering(
    core_instance: InstanceWires<INPUT_WIRE_COUNT>,
    additional_instances: [InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE],
) -> Result<SolderingOutput, SolderingError> {
    let (input, public_params) = input_from_instances(core_instance, additional_instances);

    let execution = execute_internal(&input)?;
    let proof = prove_uncompressed(&input)?;

    Ok(SolderingOutput {
        public_params,
        proof,
        execution,
    })
}

/// Verify that the supplied proof is valid and binds to the provided public parameters.
pub fn verify_soldering(
    expected_public: &PublicParams<INPUT_WIRE_COUNT, SOLDERED_INSTANCE>,
    proof: &SolderingProof,
) -> Result<(), SolderingError> {
    // Deserialize proof & vk for SP1 verification.
    let decoded_proof: SP1ProofWithPublicValues =
        rmp_serde::from_slice(&proof.proof).map_err(SolderingError::SerializationDecode)?;
    let decoded_vk: SP1VerifyingKey =
        rmp_serde::from_slice(&proof.verifying_key).map_err(SolderingError::SerializationDecode)?;

    // Verify core proof.
    cpu_prover()
        .verify(&decoded_proof, &decoded_vk)
        .map_err(|err| SolderingError::Verification(err.to_string()))?;

    // Extract the committed public parameters and compare.
    let mut encoded_expected = SP1PublicValues::new();
    encoded_expected.write(expected_public);

    if decoded_proof.public_values.as_slice() != encoded_expected.as_slice() {
        return Err(SolderingError::PublicParamMismatch);
    }

    Ok(())
}

/// Construct deterministic instances for testing/demo purposes.
pub fn make_dummy_instances(
    failed: bool,
) -> (
    InstanceWires<INPUT_WIRE_COUNT>,
    [InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE],
) {
    let wires_for_instance: [Wire; INPUT_WIRE_COUNT] = core::array::from_fn(|i| Wire {
        label0: i as u128,
        label1: (i + 1) as u128,
    });

    let mut core_instance = InstanceWires {
        labels: Box::new(wires_for_instance.clone()),
    };
    let additional_instances: [InstanceWires<INPUT_WIRE_COUNT>; SOLDERED_INSTANCE] =
        core::array::from_fn(|_| InstanceWires {
            labels: Box::new(wires_for_instance.clone()),
        });

    if failed {
        let last_idx = INPUT_WIRE_COUNT - 1;
        core_instance.labels[last_idx].label1 = 0xFF;
    }

    (core_instance, additional_instances)
}

/// Build a dummy input directly, primarily for testing.
pub fn make_dummy_input(failed: bool) -> Input<INPUT_WIRE_COUNT, SOLDERED_INSTANCE> {
    let (core_instance, additional_instances) = make_dummy_instances(failed);
    let (input, _) = input_from_instances(core_instance, additional_instances);
    input
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires SP1 artifact downloads"]
    fn do_soldering_round_trip() {
        let (core_instance, additional_instances) = make_dummy_instances(false);
        let output =
            do_soldering(core_instance, additional_instances).expect("soldering proof generation");
        verify_soldering(&output.public_params, &output.proof).expect("soldering verification");
    }
}
