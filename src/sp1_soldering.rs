use std::{path::PathBuf, time::Instant};

use bincode::config;
use sp1_core_executor::SP1ContextBuilder;
use sp1_core_machine::io::SP1Stdin;
use sp1_prover::{SP1Prover, SP1PublicValues, build, components::CpuProverComponents};
use sp1_stark::SP1ProverOpts;
use tracing::{info, instrument};

#[path = "../sp1-soldering-program/src/types.rs"]
mod types;

pub use sp1_prover::Groth16Bn254Proof;
pub use types::{Sha256Commit, SolderedLabelsData as SolderedLabels};

/// Type alias for wire deltas (delta0, delta1) for backward compatibility
pub type WireDelta = (u128, u128);

use crate::{GarbledWire, S, Sha256LabelCommitHasher, circuit::CircuitInput, commit_label_with};

/// Hash a label to create a SHA256 commitment using the standard label commit hasher
pub fn hash_label(label: u128) -> Sha256Commit {
    commit_label_with::<Sha256LabelCommitHasher>(S::from_u128(label))
}

/// Trait for inputs that can be soldered with deltas to create derived instances
pub trait SolderInput: CircuitInput {
    /// Apply per-wire deltas to create a new instance
    fn solder(&self, per_wire_deltas: &[(S, S)]) -> Self;
}

/// Returns the compiled soldering guest ELF bytes.
pub fn elf() -> &'static [u8] {
    include_bytes!(env!("SP1_ELF_sp1-soldering-guest"))
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SolderingProof {
    pub proof: Groth16Bn254Proof,
    pub deltas: Vec<Vec<(u128, u128)>>,
}

/// Serializes the wires input into the format expected by the SP1 guest.
pub fn serialize_wires_input(
    input: &types::WiresInput,
) -> Result<Vec<u8>, bincode::error::EncodeError> {
    // Use fixed-int encoding to support u128 in SP1
    let config = config::standard().with_fixed_int_encoding();
    bincode::encode_to_vec(input, config)
}

/// Serializes the soldering public parameters.
pub fn serialize_public_params(
    params: &types::SolderedLabelsData,
) -> Result<Vec<u8>, bincode::error::EncodeError> {
    // Use fixed-int encoding to support u128 in SP1
    let config = config::standard().with_fixed_int_encoding();
    bincode::encode_to_vec(params, config)
}

/// Deserializes the soldering public parameters emitted by the SP1 guest.
pub fn deserialize_public_params(
    bytes: &[u8],
) -> Result<types::SolderedLabelsData, bincode::error::DecodeError> {
    // Use fixed-int encoding to support u128 in SP1
    let config = config::standard().with_fixed_int_encoding();
    let (decoded, _len) =
        bincode::decode_from_slice::<types::SolderedLabelsData, _>(bytes, config)?;
    Ok(decoded)
}

fn groth16_artifacts_dir() -> PathBuf {
    std::env::var("SP1_GROTH16_CIRCUIT_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dirs::home_dir().unwrap().join(".sp1/circuits/groth16"))
        .join(sp1_prover::SP1_CIRCUIT_VERSION.trim())
}

#[instrument(skip_all)]
pub fn prove_soldering(instances: Vec<Vec<GarbledWire>>, nonce: u128) -> SolderingProof {
    let input = types::WiresInput {
        instances_wires: instances
            .into_iter()
            .map(|instance| {
                instance
                    .into_iter()
                    .map(|gw| (gw.label0.to_u128(), gw.label1.to_u128()))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>(),
        nonce,
    };

    let prover = SP1Prover::<CpuProverComponents>::new();

    let input_bytes = serialize_wires_input(&input).expect("failed to serialize wires input");

    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&input_bytes);

    // 3. Create proving/verification keys.
    let (_pk, pk_device, program, vk) = prover.setup(elf());

    // 4. Optional: customise proving opts/context.
    let opts = SP1ProverOpts::default();
    let context = SP1ContextBuilder::default().build();

    // 5. Prove the core execution.
    let prove_time = Instant::now();
    let core_proof = prover
        .prove_core(&pk_device, program, &stdin, opts, context)
        .unwrap();
    info!("Proved in {}", prove_time.elapsed().as_secs());
    let public_values = core_proof.public_values.clone();

    let data = deserialize_public_params(public_values.as_slice())
        .expect("failed to deserialize `SolderedLabelsData`");

    // 6. Compress → shrink → wrap (PLONK/STARK outer proof).
    let compress_time = Instant::now();
    let deferred = stdin.proofs.iter().map(|(p, _)| p.clone()).collect();
    let reduced = prover.compress(&vk, core_proof, deferred, opts).unwrap();
    let shrunk = prover.shrink(reduced, opts).unwrap();
    let wrapped = prover.wrap_bn254(shrunk, opts).unwrap();
    info!("Compressed in {}", compress_time.elapsed().as_secs());

    // 7. Build/download Groth16 artifacts and produce Groth16 proof.
    let wrap_time = Instant::now();

    let artifacts = if sp1_prover::build::sp1_dev_mode() {
        build::try_build_groth16_bn254_artifacts_dev(&wrapped.vk, &wrapped.proof)
    } else {
        groth16_artifacts_dir()
    };

    let groth16_proof = prover.wrap_groth16_bn254(wrapped, &artifacts);
    info!("Wrapped in {}", wrap_time.elapsed().as_secs());

    SolderingProof {
        proof: groth16_proof,
        deltas: data.deltas,
    }
}

#[instrument(skip_all)]
pub fn verify_soldering(
    proof: SolderingProof,
    base_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    base_nonce_commitment: Vec<(Sha256Commit, Sha256Commit)>,
    nonce: u128,
    commitments: Vec<Vec<(Sha256Commit, Sha256Commit)>>,
) -> bool {
    info!("start");
    let SolderingProof { proof, deltas } = proof;

    let pp = types::SolderedLabelsData {
        deltas,
        base_commitment,
        base_nonce_commitment,
        nonce,
        commitments,
    };

    let input_bytes = serialize_public_params(&pp).expect("failed to serialize public params");

    let prover = SP1Prover::<CpuProverComponents>::new();
    let (_pk, _pk_device, _program, vk) = prover.setup(elf());

    let artifacts = groth16_artifacts_dir();

    prover
        .verify_groth16_bn254(
            &proof,
            &vk,
            &SP1PublicValues::from(&input_bytes[..]),
            &artifacts,
        )
        .unwrap();

    info!("end");

    true
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use sp1_core_executor::{ExecutionError, ExecutionReport, SP1Context};
    use test_log::test;
    use tracing::info;

    use super::*;
    use crate::S;

    /// Build the expected public parameters for a set of raw wire labels.
    fn build_expected_public_params(
        raw_instances: &[Vec<(u128, u128)>],
        nonce: u128,
    ) -> SolderedLabels {
        let (base, rest) = raw_instances
            .split_first()
            .expect("at least one instance required");

        let mut base_commitment = Vec::with_capacity(base.len());
        let mut base_nonce_commitment = Vec::with_capacity(base.len());

        for &(label0, label1) in base {
            base_commitment.push((hash_label(label0), hash_label(label1)));
            base_nonce_commitment.push((hash_label(label0 ^ nonce), hash_label(label1 ^ nonce)));
        }

        let mut commitments = Vec::with_capacity(rest.len());
        let mut deltas = Vec::with_capacity(rest.len());

        for instance in rest {
            let mut instance_commitment = Vec::with_capacity(instance.len());
            let mut instance_deltas = Vec::with_capacity(instance.len());

            for ((base0, base1), (label0, label1)) in base.iter().zip(instance.iter()) {
                instance_commitment.push((hash_label(*label0), hash_label(*label1)));
                instance_deltas.push((base0 ^ label0, base1 ^ label1));
            }

            commitments.push(instance_commitment);
            deltas.push(instance_deltas);
        }

        SolderedLabels {
            deltas,
            base_commitment,
            base_nonce_commitment,
            nonce,
            commitments,
        }
    }

    #[test]
    #[ignore]
    fn test_core_public_params_roundtrip() {
        use rand::{Rng, SeedableRng, rngs::StdRng};

        let wires = 1;
        let instances = 1;

        let mut rng = StdRng::seed_from_u64(42);
        let nonce: u128 = rng.r#gen();
        let delta: u128 = rng.r#gen::<u128>() | 1;

        let mut raw_instances = Vec::with_capacity(1 + instances);

        for _ in 0..=instances {
            let mut raw_labels = Vec::with_capacity(wires);

            for _ in 0..wires {
                let label0: u128 = rng.r#gen();
                let label1: u128 = label0 ^ delta;
                raw_labels.push((label0, label1));
            }

            raw_instances.push(raw_labels);
        }

        let input = types::WiresInput {
            instances_wires: raw_instances.clone(),
            nonce,
        };

        let input_bytes =
            serialize_wires_input(&input).expect("failed to serialize wires input for core test");

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input_bytes);

        let prover = SP1Prover::<CpuProverComponents>::new();
        let (_pk, pk_device, program, _vk) = prover.setup(elf());
        let opts = SP1ProverOpts::default();
        let context = SP1ContextBuilder::default().build();

        let core_proof = prover
            .prove_core(&pk_device, program, &stdin, opts, context)
            .expect("core proving failed");

        let public_values = core_proof.public_values;

        let recovered =
            deserialize_public_params(public_values.as_slice()).expect("failed to deserialize pp");
        let expected = build_expected_public_params(&raw_instances, nonce);

        assert_eq!(
            recovered, expected,
            "deserialized public params differ from expected output"
        );

        let reserialized =
            serialize_public_params(&recovered).expect("failed to reserialize public params");
        let decoded = deserialize_public_params(&reserialized)
            .expect("failed to deserialize reserialized params");
        assert_eq!(
            decoded, recovered,
            "reserialized params differ from original deserialize output"
        );
    }

    fn execute_only(
        elf: &[u8],
        stdin: &SP1Stdin,
    ) -> Result<(SP1PublicValues, ExecutionReport), ExecutionError> {
        let prover = SP1Prover::<CpuProverComponents>::new();

        // Mirror the defaults from the SDK.
        let mut ctx_builder = SP1Context::builder();
        ctx_builder.calculate_gas(true);
        let context = ctx_builder.build();

        let (public_values, _digest, report) = prover.execute(elf, stdin, context)?;
        Ok((public_values, report))
    }

    #[test]
    fn execute_guest_emits_expected_public_values() {
        use rand::{Rng, SeedableRng, rngs::StdRng};

        let wires = 1019;
        let total_instances = 7;
        let additional_instances = total_instances - 1;

        let mut rng = StdRng::seed_from_u64(1337);
        let nonce: u128 = rng.r#gen();
        let delta: u128 = rng.r#gen::<u128>() | 1;

        let mut raw_instances = Vec::with_capacity(total_instances);

        for _ in 0..=additional_instances {
            let mut raw_labels = Vec::with_capacity(wires);

            for _ in 0..wires {
                let label0: u128 = rng.r#gen();
                let label1: u128 = label0 ^ delta;
                raw_labels.push((label0, label1));
            }

            raw_instances.push(raw_labels);
        }

        let input = types::WiresInput {
            instances_wires: raw_instances.clone(),
            nonce,
        };

        let input_bytes =
            serialize_wires_input(&input).expect("failed to serialize wires input for execution");

        let mut stdin = SP1Stdin::new();
        stdin.write_slice(&input_bytes);

        let (public_values, report) =
            execute_only(elf(), &stdin).expect("guest execution should succeed");

        assert!(
            report.total_instruction_count() > 0,
            "execution report should record instructions"
        );

        let recovered = deserialize_public_params(public_values.as_slice())
            .expect("failed to decode public params");
        let expected = build_expected_public_params(&raw_instances, nonce);
        assert_eq!(
            recovered, expected,
            "unexpected public params from execution"
        );
    }

    /// Helper function to test prove and verify with configurable parameters
    fn test_soldering_with_params(wires: usize, instances: usize) {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let nonce: u128 = rng.r#gen();

        // Generate garbled wires with consistent delta
        let delta: u128 = rng.r#gen::<u128>() | 1; // Ensure odd for Free-XOR

        let mut all_instances = Vec::with_capacity(1 + instances);
        let mut all_raw_labels = Vec::with_capacity(1 + instances);

        // Generate all instances (base + additional)
        for i in 0..=instances {
            let mut instance: Vec<GarbledWire> = Vec::with_capacity(wires);
            let mut raw_labels: Vec<(u128, u128)> = Vec::with_capacity(wires);

            for _ in 0..wires {
                let label0: u128 = rng.r#gen();
                let label1: u128 = label0 ^ delta;

                instance.push(GarbledWire {
                    label0: S::from_u128(label0),
                    label1: S::from_u128(label1),
                });

                raw_labels.push((label0, label1));
            }

            all_instances.push(instance);
            all_raw_labels.push(raw_labels);

            if i == 0 {
                info!("Generated base instance: {} wires", wires);
            }
        }

        info!("Generated {} additional instances", instances);

        // Prove using the public API
        let prove_start = Instant::now();
        let proof = prove_soldering(all_instances.clone(), nonce);
        info!(
            "Total proving time: {} seconds",
            prove_start.elapsed().as_secs()
        );

        // Now create the commitments exactly as the SP1 program does
        let SolderedLabels {
            base_commitment,
            base_nonce_commitment,
            commitments,
            ..
        } = build_expected_public_params(&all_raw_labels, nonce);

        // Verify using the public API
        let verify_start = Instant::now();
        let is_valid = verify_soldering(
            proof,
            base_commitment,
            base_nonce_commitment,
            nonce,
            commitments,
        );

        info!(
            "Verification time: {} ms",
            verify_start.elapsed().as_millis()
        );

        assert!(is_valid, "Proof verification failed");
        println!("Groth16 proof generated and verified successfully!");
    }

    #[test]
    #[ignore] // Run with: cargo test test_soldering_quick -- --ignored
    fn test_soldering_quick() {
        println!("Running quick soldering test with minimal parameters (1 wire, 1 instance)");
        println!("This test should complete in a few seconds");
        test_soldering_with_params(1, 1);
    }

    #[test]
    #[ignore] // Run with: cargo test test_soldering_full -- --ignored
    fn test_soldering_full() {
        println!("Running full soldering test with real payload size (1019 wires, 6 instances)");
        println!("WARNING: This test takes approximately 74 minutes to complete!");
        test_soldering_with_params(1019, 6);
    }
}
