// An example that creates a Groth16 proof (BN254),
// then garbles the verification circuit using the new streaming garble mode.
// Run with:
//   Default (AES): `RUST_LOG=info cargo run --example groth16_garble --release`
//   Blake3:        `RUST_LOG=info cargo run --example groth16_garble --release -- --hasher blake3`

use std::{env, thread, time::Instant};

use garbled_snark_verifier::{
    AesNiHasher, Blake3Hasher, CiphertextHashAcc, EvaluatedWire, GarbledWire, GateHasher,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::streaming::{
        CircuitBuilder, StreamingResult,
        modes::{EvaluateMode, GarbleMode},
    },
    garbled_groth16,
};
use log::info;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

// Simple multiplicative circuit used to produce a valid Groth16 proof.
#[derive(Copy, Clone)]
struct DummyCircuit<F: ark::PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: ark::PrimeField> ark::ConstraintSynthesizer<F> for DummyCircuit<F> {
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

        // pad witnesses
        for _ in 0..(self.num_variables - 3) {
            let _ =
                cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        }

        // repeat the same multiplicative constraint
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(ark::lc!() + a, ark::lc!() + b, ark::lc!() + c)?;
        }

        // final no-op constraint keeps ark-relations happy
        cs.enforce_constraint(ark::lc!(), ark::lc!(), ark::lc!())?;
        Ok(())
    }
}

enum G2EMsg {
    Commit {
        /// Hash of the label that proof is wrong
        output_label0_hash: [u8; 32],
        /// Hash of the label that proof is correct
        output_label1_hash: [u8; 32],
        ciphertext_hash: u128,

        input_labels: garbled_groth16::Evaluator,
        true_wire: u128,
        false_wire: u128,
    },
}

fn hash(inp: &impl AsRef<[u8]>) -> [u8; 32] {
    blake3::hash(inp.as_ref()).as_bytes().to_owned()
}

const CAPACITY: usize = 150_000;

fn run_with_hasher<H: GateHasher + 'static>(garbling_seed: u64) {
    info!("Setting up Groth16 proof...");

    // 1) Build and prove a tiny multiplicative circuit
    let k = 6; // 2^k constraints
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).expect("setup");

    info!("Proof generated successfully");

    let inputs = garbled_groth16::GarbledInputs {
        public_params_len: 1,
        vk: vk.clone(),
    };

    // Create channel for garbled tables
    let (ciphertext_acc_hash_sender, ciphertext_acc_hash_receiver) =
        crossbeam::channel::unbounded();

    let ciphertext_hash = thread::spawn(move || {
        info!("Starting ciphertext hashing thread...");

        let mut hasher = CiphertextHashAcc::default();
        while let Ok((_index, ciphertext)) = ciphertext_acc_hash_receiver.recv() {
            hasher.update(ciphertext)
        }
        hasher.finalize()
    });

    info!("Starting garbling of Groth16 verification circuit...");

    // Measure first garbling pass performance
    let garble_start = Instant::now();

    let garbling_result: StreamingResult<GarbleMode<H>, _, GarbledWire> =
        CircuitBuilder::streaming_garbling(
            inputs.clone(),
            CAPACITY,
            garbling_seed,
            ciphertext_acc_hash_sender,
            garbled_groth16::verify,
        );

    info!("garbling: in {:.3}s", garble_start.elapsed().as_secs_f64());

    // Take input labels first to avoid borrow conflicts
    let (&label0, &label1) = garbling_result.output_labels();
    let input_values = garbling_result.input_wire_values;

    let ciphertext_hash: u128 = ciphertext_hash.join().unwrap();

    // NOTE For the SetupPhase, we must use a random set of bytes and compare
    // them with the hash provided earlier.
    //
    // For PegOut, we try to prove the incorrectness of the claimer's
    // action. If we succeed, then we will send the correct proof and receive the secret label.
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");

    // NOTE If you want to break the proof, the easiest thing to do is just replace this value with whatever you want.
    let public_param = circuit.a.unwrap() * circuit.b.unwrap();

    info!(
        "[GARBLER]
            Label0: {:?},
            Label1: {:?},
            CiphertextHash: {ciphertext_hash}
        ",
        label0, label1
    );

    let proof = garbled_groth16::Proof::new(proof, vec![public_param]);

    let input_labels = garbled_groth16::Evaluator::new(proof, vk.clone(), input_values);

    let msg = G2EMsg::Commit {
        output_label0_hash: hash(&label0.to_bytes()),
        output_label1_hash: hash(&label1.to_bytes()),
        ciphertext_hash,
        input_labels,
        true_wire: garbling_result.true_wire_constant.select(true).to_u128(),
        false_wire: garbling_result.false_wire_constant.select(false).to_u128(),
    };
    info!("Commit sent");

    // Create channel for garbled tables
    let (evaluator_sender, evaluator_receiver) = crossbeam::channel::unbounded::<G2EMsg>();
    let (ciphertext_to_evaluator_sender, ciphertext_to_evaluator_receiver) =
        crossbeam::channel::unbounded();

    let garbler = thread::spawn(move || {
        evaluator_sender.send(msg).unwrap();

        let regarble_start = Instant::now();

        let _regarbling_result: StreamingResult<GarbleMode<H>, _, GarbledWire> =
            CircuitBuilder::streaming_garbling(
                inputs,
                CAPACITY,
                garbling_seed,
                ciphertext_to_evaluator_sender,
                garbled_groth16::verify,
            );

        info!(
            "regarbling: in {:.3}s",
            regarble_start.elapsed().as_secs_f64()
        );
    });

    let evaluator = thread::spawn(move || {
        let G2EMsg::Commit {
            output_label0_hash,
            output_label1_hash,
            ciphertext_hash: commit_ciphertext_hash,
            input_labels,
            true_wire,
            false_wire,
        } = evaluator_receiver.recv().unwrap();

        // We need to send ciphertexts to `Evaluator` and calculate the hash.
        let (proxy_sender, proxy_receiver) = crossbeam::channel::unbounded();

        let calculated_ciphertext_hash = std::thread::spawn(move || {
            let mut hasher = CiphertextHashAcc::default();

            while let Ok((index, ciphertext)) = ciphertext_to_evaluator_receiver.recv() {
                proxy_sender.send((index, ciphertext)).unwrap();
                hasher.update(ciphertext);
            }

            hasher.finalize()
        });

        let eval_start = Instant::now();

        let evaluator_result: StreamingResult<EvaluateMode<H>, _, EvaluatedWire> =
            CircuitBuilder::streaming_evaluation(
                input_labels,
                CAPACITY,
                true_wire,
                false_wire,
                proxy_receiver,
                garbled_groth16::verify,
            );

        info!("evaluation: in {:.3}s", eval_start.elapsed().as_secs_f64());

        let EvaluatedWire {
            active_label: possible_secret,
            value: is_proof_correct,
        } = evaluator_result.output_value;

        let calculated_ciphertext_hash = calculated_ciphertext_hash.join().unwrap();
        let result_hash = hash(&possible_secret.to_bytes());

        info!(
            "[EVALUATOR]
            Is Proof Correct: {is_proof_correct},
            Result Hash: {result_hash:?},
            Label: {possible_secret:?},
            CiphertextHash: {calculated_ciphertext_hash}
        "
        );

        assert_eq!(calculated_ciphertext_hash, commit_ciphertext_hash);

        if is_proof_correct {
            assert_eq!(result_hash, output_label1_hash);
        } else {
            assert_eq!(result_hash, output_label0_hash);
        }

        assert_eq!(calculated_ciphertext_hash, commit_ciphertext_hash);
    });

    garbler.join().unwrap();
    evaluator.join().unwrap();
}

fn main() {
    // Initialize logging (default to info if RUST_LOG not set)
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    let garbling_seed: u64 = rand::thread_rng().r#gen();

    // Simple parser for `--hasher <name>` or `--hasher=<name>`; defaults to AES
    let mut hasher_choice: Option<String> = None;
    let mut args = env::args().skip(1); // skip binary name
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--hasher=") {
            hasher_choice = Some(value.to_lowercase());
            break;
        } else if arg == "--hasher" {
            if let Some(value) = args.next() {
                hasher_choice = Some(value.to_lowercase());
            }
            break;
        }
    }

    match hasher_choice.as_deref() {
        Some("blake3") => {
            info!("Using Blake3 hasher");
            run_with_hasher::<Blake3Hasher>(garbling_seed);
        }
        Some("aes") | None => {
            // Warn if hardware AES is not available or not used by this build
            garbled_snark_verifier::warn_if_software_aes();
            info!("Using AES-NI hasher (or software fallback)");
            run_with_hasher::<AesNiHasher>(garbling_seed);
        }
        Some(other) => {
            panic!(
                "Unknown hasher '{}'. Supported: aes, blake3. Defaulting to aes.",
                other
            );
        }
    }
}
