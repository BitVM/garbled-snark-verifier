// Integration test that demonstrates garbler-evaluator connection using channels
// Run with: cargo test garbler_evaluator_connection -- --ignored --nocapture

use std::thread;

use garbled_snark_verifier::{
    CiphertextHashAcc, EvaluatedWire, GarbledWire,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::{
        CircuitBuilder, StreamingResult,
        modes::{EvaluateMode, GarbleMode},
    },
    garbled_groth16,
    hashers::{AesNiHasher, Blake3Hasher, GateHasher},
};
use rand::SeedableRng;
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
    let public_param = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = garbled_groth16::Proof::new(proof, vec![public_param]);

    // Create channels for communication
    let (ciphertext_to_evaluator_sender, ciphertext_to_evaluator_receiver) =
        crossbeam::channel::unbounded();

    // Clone inputs for both threads
    let vk_garbler = vk.clone();
    let vk_evaluator = vk.clone();
    let proof_clone = proof.clone();

    // Garbler thread - runs garbling and sends ciphertexts in real-time
    let garbler = thread::spawn(move || {
        let inputs = garbled_groth16::GarblerInput {
            public_params_len: 1,
            vk: vk_garbler,
        };

        // Garbling with sender - this will stream ciphertexts as they're generated
        let garbling_result: StreamingResult<GarbleMode<H, _>, _, GarbledWire> =
            CircuitBuilder::streaming_garbling_with_sender(
                inputs,
                CAPACITY,
                garbling_seed,
                ciphertext_to_evaluator_sender,
                garbled_groth16::verify,
            );

        // Return garbling results for verification
        (
            garbling_result.output_labels().clone(),
            garbling_result.input_wire_values.clone(),
            garbling_result.true_wire_constant.clone(),
            garbling_result.false_wire_constant.clone(),
        )
    });

    // Evaluator thread - starts evaluation immediately with streamed ciphertexts
    let evaluator = thread::spawn(move || {
        // Create proxy for ciphertext streaming and hash calculation
        let (proxy_sender, proxy_receiver) = crossbeam::channel::unbounded();

        // Hash calculation in separate thread
        let hash_calculator = std::thread::spawn(move || {
            let mut hasher = CiphertextHashAcc::default();
            let mut count = 0;

            while let Ok((index, ciphertext)) = ciphertext_to_evaluator_receiver.recv() {
                proxy_sender.send((index, ciphertext)).unwrap();
                hasher.update(ciphertext);
                count += 1;
            }

            (hasher.finalize(), count)
        });

        // Wait for garbler to provide wire values and constants
        // In a real scenario, this would be communicated separately
        let (output_labels, input_values, true_wire_constant, false_wire_constant) =
            garbler.join().unwrap();

        let GarbledWire { label0, label1 } = *output_labels;
        let input_labels =
            garbled_groth16::EvaluatorInput::new(proof_clone, vk_evaluator, input_values);

        // Start evaluation with streaming ciphertexts
        let evaluator_result: StreamingResult<EvaluateMode<H, _>, _, EvaluatedWire> =
            CircuitBuilder::streaming_evaluation(
                input_labels,
                CAPACITY,
                true_wire_constant.select(true).to_u128(),
                false_wire_constant.select(false).to_u128(),
                proxy_receiver,
                garbled_groth16::verify,
            );

        let EvaluatedWire {
            active_label: possible_secret,
            value: is_proof_correct,
        } = evaluator_result.output_value;

        let (ciphertext_hash, ciphertext_count) = hash_calculator.join().unwrap();

        // Verify results
        let result_hash = hash(&possible_secret.to_bytes());
        let output_label0_hash = hash(&label0.to_bytes());
        let output_label1_hash = hash(&label1.to_bytes());

        println!("Processed {} ciphertexts", ciphertext_count);
        println!("Ciphertext hash: {:?}", ciphertext_hash);
        println!("Proof verification: {}", is_proof_correct);

        // Assertions
        if is_proof_correct {
            assert_eq!(result_hash, output_label1_hash);
        } else {
            assert_eq!(result_hash, output_label0_hash);
        }
    });

    // Wait for evaluator to complete
    evaluator.join().unwrap();
}

#[test]
#[ignore]
fn test_garbler_evaluator_connection_aes() {
    garbled_snark_verifier::init_tracing();
    let garbling_seed: u64 = 42;
    run_garbler_evaluator_test::<AesNiHasher>(garbling_seed);
}

#[test]
#[ignore]
fn test_garbler_evaluator_connection_blake3() {
    garbled_snark_verifier::init_tracing();
    let garbling_seed: u64 = 42;
    run_garbler_evaluator_test::<Blake3Hasher>(garbling_seed);
}
