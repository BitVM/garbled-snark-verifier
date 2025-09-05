// An example that creates a Groth16 proof (BN254),
// then garbles the verification circuit using the new streaming garble mode.
// Run with: `RUST_LOG=info cargo run --example groth16_garble --release`

use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use garbled_snark_verifier::{
    AesNiHasher, CiphertextHasher, EvaluatedWire, GarbledWire,
    circuit::streaming::{
        CircuitBuilder, StreamingResult,
        modes::{EvaluateMode, GarbleMode},
    },
    groth16_proof::{GarbledInputs, Groth16EvaluatorInputs, groth16_proof_verify},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

// Simple multiplicative circuit used to produce a valid Groth16 proof.
#[derive(Copy, Clone)]
struct DummyCircuit<F: ark_ff::PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: ark_ff::PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        // pad witnesses
        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        // repeat the same multiplicative constraint
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        // final no-op constraint keeps ark-relations happy
        cs.enforce_constraint(lc!(), lc!(), lc!())?;
        Ok(())
    }
}

#[allow(dead_code)]
enum G2EMsg {
    Commit {
        /// Hash of the label that proof is wrong
        /// Use as a secret
        output_label0_hash: [u8; 32],
        /// Hash of the label that proof is correct
        /// Just a marker of correctness
        output_label1_hash: [u8; 32],
        ciphertext_hash: u128,

        input_labels: Groth16EvaluatorInputs,
        true_wire: u128,
        false_wire: u128,
    },
}

fn hash(inp: &impl AsRef<[u8]>) -> [u8; 32] {
    blake3::hash(inp.as_ref()).as_bytes().to_owned()
}

const CAPACITY: usize = 150_000;

fn main() {
    // Initialize logging (default to info if RUST_LOG not set)
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    let garbling_seed: u64 = rand::thread_rng().r#gen();

    println!("Setting up Groth16 proof...");

    // 1) Build and prove a tiny multiplicative circuit
    let k = 6; // 2^k constraints
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark_bn254::Fr> {
        a: Some(ark_bn254::Fr::rand(&mut rng)),
        b: Some(ark_bn254::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).expect("setup");

    println!("Proof generated successfully");

    let inputs = GarbledInputs {
        public_params_len: 1,
    };

    // Create channel for garbled tables
    let (ciphertext_acc_hash_sender, ciphertext_acc_hash_receiver) =
        crossbeam::channel::unbounded();

    let ciphertext_hash = std::thread::spawn(move || {
        println!("Starting ciphertext hashing thread...");

        CiphertextHasher::new_batched().run(ciphertext_acc_hash_receiver)
    });

    println!("Starting garbling of Groth16 verification circuit...");

    let mut garbling_result: StreamingResult<GarbleMode<AesNiHasher>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(
            inputs.clone(),
            CAPACITY,
            garbling_seed,
            ciphertext_acc_hash_sender,
            |ctx, wires| groth16_proof_verify(ctx, wires, &vk),
        );

    let GarbledWire { label0, label1 } = garbling_result.output_wires.remove(0);

    let ciphertext_hash: u128 = ciphertext_hash.join().unwrap();

    let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");

    let public_param = circuit.a.unwrap() * circuit.b.unwrap();

    println!(
        "[GARBLER]
            Label0: {:?},
            Label1: {:?},
            CiphertextHash: {ciphertext_hash}
        ",
        &garbling_result.output_wires[0].label0, &garbling_result.output_wires[0].label1,
    );

    let input_labels = Groth16EvaluatorInputs::new(
        proof.a.into_group(),
        proof.b.into_group(),
        proof.c.into_group(),
        vec![public_param],
        garbling_result.input_values,
    );

    let msg = G2EMsg::Commit {
        output_label0_hash: hash(&label0.to_bytes()),
        output_label1_hash: hash(&label1.to_bytes()),
        ciphertext_hash,
        input_labels,
        true_wire: garbling_result.true_constant.select(true).to_u128(),
        false_wire: garbling_result.false_constant.select(false).to_u128(),
    };

    // Create channel for garbled tables
    let (evaluator_sender, evaluator_receiver) = crossbeam::channel::unbounded::<G2EMsg>();
    let (ciphertext_to_evaluator_sender, ciphertext_to_evaluator_receiver) =
        crossbeam::channel::unbounded();

    let vk_garbler = vk.clone();
    let vk_evaluator = vk;

    let garbler = std::thread::spawn(move || {
        evaluator_sender.send(msg).unwrap();

        let _regarbling_result: StreamingResult<GarbleMode<AesNiHasher>, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling(
                inputs,
                CAPACITY,
                42,
                ciphertext_to_evaluator_sender,
                |ctx, wires| groth16_proof_verify(ctx, wires, &vk_garbler),
            );
    });

    let evaluator = std::thread::spawn(move || {
        let G2EMsg::Commit {
            output_label0_hash,
            output_label1_hash,
            ciphertext_hash,
            input_labels,
            true_wire,
            false_wire,
        } = evaluator_receiver.recv().unwrap();

        let (sender1, receiver1) = crossbeam::channel::unbounded();
        let (sender2, receiver2) = crossbeam::channel::unbounded();

        std::thread::spawn(move || {
            while let Ok(msg) = ciphertext_to_evaluator_receiver.recv() {
                sender1.send(msg).unwrap();
                sender2.send(msg).unwrap();
            }
        });

        // TODO Change API for `run and have one thread
        let calculated_ciphertext_hash = std::thread::spawn(move || {
            println!("Starting ciphertext hashing thread...");

            CiphertextHasher::new_batched().run(receiver2)
        });

        let mut evaluator_result: StreamingResult<
            EvaluateMode<AesNiHasher>,
            _,
            Vec<EvaluatedWire>,
        > = CircuitBuilder::streaming_evaluation(
            input_labels,
            CAPACITY,
            true_wire,
            false_wire,
            receiver1,
            |ctx, wires| groth16_proof_verify(ctx, wires, &vk_evaluator),
        );

        let EvaluatedWire {
            active_label: possible_secret,
            value: is_proof_correct,
        } = evaluator_result.output_wires.remove(0);

        let calculated_ciphertext_hash = calculated_ciphertext_hash.join().unwrap();
        let result_hash = hash(&possible_secret.to_bytes());

        println!(
            "[EVALUATOR]
            Is Proof Correct: {is_proof_correct},
            Result Hash: {result_hash:?},
            Label: {possible_secret:?},
            CiphertextHash: {calculated_ciphertext_hash}
        "
        );

        if is_proof_correct {
            assert_eq!(result_hash, output_label1_hash);
        } else {
            assert_eq!(result_hash, output_label0_hash);
        }

        assert!(is_proof_correct);
        assert_eq!(calculated_ciphertext_hash, ciphertext_hash);
    });

    garbler.join().unwrap();
    evaluator.join().unwrap();
}
