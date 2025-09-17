// Integration test that demonstrates garbler-evaluator connection using channels
// Run with: cargo test garbler_evaluator_connection -- --ignored --nocapture

use std::thread;

use garbled_snark_verifier::{
    EvaluatedWire, GarbledWire,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{
        CircuitBuilder, StreamingResult,
        modes::{EvaluateMode, GarbleMode},
    },
    garbled_groth16,
    hashers::{AesNiHasher, Blake3Hasher, GateHasher},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

// Simple multiplicative circuit for testing
#[derive(Copy, Clone)]
struct TestCircuit<F: ark::PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: ark::PrimeField> ark::ConstraintSynthesizer<F> for TestCircuit<F> {
    fn generate_constraints(
        self,
        cs: ark::ConstraintSystemRef<F>,
    ) -> Result<(), ark::SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(ark::SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(ark::SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        // Pad witnesses
        for _ in 0..(self.num_variables - 3) {
            let _ =
                cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        }

        // Repeat multiplicative constraint
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(ark::lc!() + a, ark::lc!() + b, ark::lc!() + c)?;
        }

        // Final no-op constraint
        cs.enforce_constraint(ark::lc!(), ark::lc!(), ark::lc!())?;
        Ok(())
    }
}

fn hash(inp: &impl AsRef<[u8]>) -> [u8; 32] {
    blake3::hash(inp.as_ref()).as_bytes().to_owned()
}

const CAPACITY: usize = 150_000;

fn run_garbler_evaluator_test<H: GateHasher + 'static>(garbling_seed: u64) {
    // Setup Groth16 proof
    let k = 6; // 2^k constraints
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = TestCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).expect("setup");

    // Generate proof
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");
    let public_param = vec![circuit.a.unwrap() * circuit.b.unwrap()];

    // First pass to get initial values needed for evaluation
    let inputs_for_initial = garbled_groth16::GarblerInput {
        public_params_len: 1,
        vk: vk.clone(),
    };

    // Create channels for communication
    let (ciphertext_sender, ciphertext_receiver) = crossbeam::channel::unbounded();

    let mut preallocated_wires =
        GarbleMode::<AesNiHasher, ()>::preallocate_input(garbling_seed, &inputs_for_initial);
    let false_wire = preallocated_wires.remove(0);
    let true_wire = preallocated_wires.remove(0);

    // Clone inputs for both threads
    let vk_garbler = vk.clone();
    let vk_evaluator = vk.clone();
    let proof_clone = proof.clone();

    // Garbler thread
    let garbler = thread::spawn(move || {
        let inputs = garbled_groth16::GarblerInput {
            public_params_len: 1,
            vk: vk_garbler,
        };

        let garbling_result: StreamingResult<GarbleMode<H, _>, _, GarbledWire> =
            CircuitBuilder::streaming_garbling_with_sender(
                inputs,
                CAPACITY,
                garbling_seed,
                ciphertext_sender,
                garbled_groth16::verify,
            );

        garbling_result
    });

    // Evaluator thread
    let evaluator = thread::spawn(move || {
        let input_labels = garbled_groth16::EvaluatorInput::new(
            public_param,
            proof_clone,
            vk_evaluator,
            preallocated_wires,
        );

        let evaluator_result: StreamingResult<EvaluateMode<H, _>, _, EvaluatedWire> =
            CircuitBuilder::streaming_evaluation(
                input_labels,
                CAPACITY,
                true_wire.select(true).to_u128(),
                false_wire.select(false).to_u128(),
                ciphertext_receiver,
                garbled_groth16::verify,
            );

        evaluator_result
    });

    // Wait for both threads to complete
    let garbling_result = garbler.join().unwrap();
    let evaluator_result = evaluator.join().unwrap();

    // Verify results
    let GarbledWire { label0: _, label1 } = *garbling_result.output_labels();
    let EvaluatedWire {
        active_label: possible_secret,
        value: is_proof_correct,
    } = evaluator_result.output_value;

    let result_hash = hash(&possible_secret.to_bytes());
    let output_label1_hash = hash(&label1.to_bytes());

    assert!(is_proof_correct);
    assert_eq!(result_hash, output_label1_hash);
}

#[test]
#[ignore]
fn test_garbler_evaluator_connection_aes() {
    garbled_snark_verifier::init_tracing();
    let garbling_seed: u64 = rand::thread_rng().r#gen();
    run_garbler_evaluator_test::<AesNiHasher>(garbling_seed);
}

#[test]
#[ignore]
fn test_garbler_evaluator_connection_blake3() {
    garbled_snark_verifier::init_tracing();
    let garbling_seed: u64 = rand::thread_rng().r#gen();
    run_garbler_evaluator_test::<Blake3Hasher>(garbling_seed);
}
