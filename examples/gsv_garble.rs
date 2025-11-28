// An example that creates a Groth16 proof (BN254),
// then garbles the verification circuit using the new streaming garble mode.
// Run with:
//   Default (Swanky AES): `RUST_LOG=info cargo run --example groth16_garble --release`
//   Blake3:               `RUST_LOG=info cargo run --example groth16_garble --release -- --hasher blake3`

use std::{env, fmt::Write as _, thread, time::Instant};

use garbled_snark_verifier::{
    Blake3AccumulatingHash, EvaluatedWire, GarbledWire,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    ciphertext_hasher::HASH_OUTPUT_SIZE,
    circuit::{
        CircuitBuilder, StreamingResult,
        modes::{EvaluateMode, GarbleMode},
    },
    garbled_groth16,
    hashers::{AesCcrGateHasher, Blake3Hasher, GateHasher},
    test_utils::DummyCircuit,
};
use rand::{Rng, SeedableRng};
use rand_chacha::{ChaCha20Rng, ChaChaRng};
use tracing::{info, info_span};

enum G2EMsg {
    Commit {
        /// Hash of the label that proof is wrong
        output_label0_hash: [u8; 32],
        /// Hash of the label that proof is correct
        output_label1_hash: [u8; 32],
        ciphertext_hash: [u8; HASH_OUTPUT_SIZE],

        input_labels: garbled_groth16::EvaluatorInput,
        true_wire: u128,
        false_wire: u128,
    },
}

fn hash(inp: &impl AsRef<[u8]>) -> [u8; 32] {
    blake3::hash(inp.as_ref()).as_bytes().to_owned()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut s, "{:02x}", byte);
    }
    s
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

    let inputs = garbled_groth16::GarblerInput {
        public_params_len: 1,
        vk: vk.clone(),
    };

    let ciphertext_hasher = Blake3AccumulatingHash::default();

    info!("Starting garbling of Groth16 verification circuit...");

    // Measure first garbling pass performance
    let garble_start = Instant::now();

    let garbling_result: StreamingResult<GarbleMode<H, _>, _, GarbledWire> = {
        let _span = info_span!("garble").entered();
        CircuitBuilder::streaming_garbling(
            inputs.clone(),
            CAPACITY,
            garbling_seed,
            ciphertext_hasher,
            garbled_groth16::verify,
        )
    };

    info!("garbling: in {:.3}s", garble_start.elapsed().as_secs_f64());

    // Take input labels first to avoid borrow conflicts
    let GarbledWire { label0, label1 } = *garbling_result.output_labels();
    let input_values = garbling_result.input_wire_values;

    let ciphertext_hash = garbling_result.ciphertext_handler_result;
    let ciphertext_hash_hex = to_hex(&ciphertext_hash);

    // NOTE For the SetupPhase, we must use a random set of bytes and compare
    // them with the hash provided earlier.
    //
    // For PegOut, we try to prove the incorrectness of the claimer's
    // action. If we succeed, then we will send the correct proof and receive the secret label.
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");

    // NOTE If you want to break the proof, the easiest thing to do is just replace this value with whatever you want.
    let public_param = vec![circuit.a.unwrap() * circuit.b.unwrap()];

    info!(
        "[GARBLER]
            Label0: {:?},
            Label1: {:?},
            CiphertextHash: 0x{ciphertext_hash_hex}
        ",
        label0, label1
    );

    let input_labels =
        garbled_groth16::EvaluatorInput::new(public_param, proof, vk.clone(), input_values);

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

    // Derive same gate_hasher from same seed as garbling (for evaluator)
    let gate_hasher = {
        let mut rng = ChaChaRng::seed_from_u64(garbling_seed);
        H::from_rng(&mut rng)
    };

    let garbler = thread::spawn(move || {
        evaluator_sender.send(msg).unwrap();

        let regarble_start = Instant::now();

        let _regarbling_result: StreamingResult<GarbleMode<H, _>, _, GarbledWire> = {
            let _span = info_span!("regarble").entered();
            CircuitBuilder::streaming_garbling_with_sender(
                inputs,
                CAPACITY,
                garbling_seed,
                ciphertext_to_evaluator_sender,
                garbled_groth16::verify,
            )
        };

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
            let mut hasher = Blake3AccumulatingHash::default();

            while let Ok(ciphertext) = ciphertext_to_evaluator_receiver.recv() {
                proxy_sender.send(ciphertext).unwrap();
                hasher.update(ciphertext);
            }

            hasher.finalize()
        });

        let eval_start = Instant::now();

        let evaluator_result: StreamingResult<EvaluateMode<H, _>, _, EvaluatedWire> = {
            let _span = info_span!("evaluate").entered();
            CircuitBuilder::streaming_evaluation(
                input_labels,
                CAPACITY,
                true_wire,
                false_wire,
                gate_hasher,
                proxy_receiver,
                garbled_groth16::verify,
            )
        };

        info!("evaluation: in {:.3}s", eval_start.elapsed().as_secs_f64());

        let EvaluatedWire {
            active_label: possible_secret,
            value: is_proof_correct,
        } = evaluator_result.output_value;

        let calculated_ciphertext_hash = calculated_ciphertext_hash.join().unwrap();
        let calculated_ciphertext_hash_hex = to_hex(&calculated_ciphertext_hash);
        let result_hash = hash(&possible_secret.to_bytes());

        info!(
            "[EVALUATOR]
            Is Proof Correct: {is_proof_correct},
            Result Hash: {result_hash:?},
            Label: {possible_secret:?},
            CiphertextHash: 0x{calculated_ciphertext_hash_hex}
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
    garbled_snark_verifier::init_tracing();

    let garbling_seed: u64 = rand::thread_rng().r#gen();

    // Simple parser for `--hasher <name>` or `--hasher=<name>`; defaults to Swanky AES
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
        Some("swankyaes") | None => {
            info!("Using Swanky AES hasher");
            run_with_hasher::<AesCcrGateHasher>(garbling_seed);
        }
        Some(other) => {
            panic!(
                "Unknown hasher '{}'. Supported: aes/swankyaes, blake3. Defaulting to aes.",
                other
            );
        }
    }
}
