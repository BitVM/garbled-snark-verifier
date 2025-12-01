//! High-level driver showcasing the cut-and-choose Setup/Evaluate flow from
//! `docs/gsv_spec.md` using the Groth16 verifier gadget.
use std::{path::PathBuf, thread};

use ark_ff::AdditiveGroup;
use ccn::{DEFAULT_CAPACITY, Evaluator, EvaluatorCaseInput};
use crossbeam::channel::{self};
use garbled_snark_verifier::{
    EvaluatedWire,
    ark::{
        self, Bn254, CircuitSpecificSetupSNARK, Groth16 as ArkGroth16, ProvingKey as ArkProvingKey,
        SNARK, UniformRand,
    },
    circuit::CiphertextSender,
    cut_and_choose::vsss::{
        Challenge, EvaluatorAdaptorSigs, FileCiphertextHandlerProvider, FinalizeChallenge,
        SetupBroadcast, SetupResponse, VsssStreamReceivers, groth16 as ccn,
    },
    garbled_groth16::{self, EvaluatorCompressedInput},
    hashers::{AesCcrGateHasher, Sha256LabelCommitHasher},
    test_utils::DummyCircuit,
};
use itertools::Itertools;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tracing::info;

// Configuration constants - modify these as needed
const TOTAL_INSTANCES: usize = 4;
const FINALIZE_INSTANCES: usize = 2;
const OUT_DIR: &str = "target/cut_and_choose";
const K_CONSTRAINTS: u32 = 5; // 2^k constraints
const IS_PROOF_CORRECT: bool = true;
const STREAM_PREALLOC_BYTES: u64 = 43_400_000_000; // ~43.4 GB per ciphertext stream (matches expected file size)
const STREAM_BOUND_CIPHERTEXTS: usize = (1 << 30) / 16; // cap in-flight ciphertexts to ~1 GiB

// Calculate and display total gates to process
const GATES_PER_INSTANCE: u64 = 11_174_708_821;

// note: uncomment to use a dummy circuit for faster testing. Note that the evaluation will fail
// due to the input being incorrect.
use garbled_groth16::verify_compressed as circuit_verify;

mod dummy_circuit {
    use garbled_snark_verifier::{
        CircuitContext, Gate, WireId,
        circuit::{TRUE_WIRE, WiresObject},
        gadgets::groth16::Groth16VerifyCompressedInputWires,
    };

    #[allow(unused)]
    pub fn verify_compressed<C: CircuitContext>(
        circuit: &mut C,
        input: &Groth16VerifyCompressedInputWires,
    ) -> WireId {
        let input_wires = input.to_wires_vec();
        let output_wire = circuit.issue_wire();

        let mut it = input_wires.iter();
        let mut one_bits: Vec<WireId> = Vec::new();
        let mut zero_bits: Vec<WireId> = Vec::new();
        for i in 0.. {
            zero_bits.extend(it.by_ref().take(i));
            match it.next() {
                Some(wire) => {
                    one_bits.push(*wire);
                }
                None => {
                    break;
                }
            }
        }

        let ones_ok = one_bits
            .into_iter()
            .reduce(|a, b| {
                let c = circuit.issue_wire();
                circuit.add_gate(Gate::and(a, b, c));
                c
            })
            .unwrap();

        let zeroes_not_ok = zero_bits
            .into_iter()
            .reduce(|a, b| {
                let c = circuit.issue_wire();
                circuit.add_gate(Gate::or(a, b, c));
                c
            })
            .unwrap();

        let zeroes_ok = circuit.issue_wire();
        circuit.add_gate(Gate::xor(zeroes_not_ok, TRUE_WIRE, zeroes_ok));

        circuit.add_gate(Gate::and(ones_ok, zeroes_ok, output_wire));

        output_wire
    }
}

fn main() {
    if !garbled_snark_verifier::hardware_aes_available() {
        eprintln!(
            "Warning: AES hardware acceleration not detected; using software AES (not constant-time)."
        );
    }

    garbled_snark_verifier::init_tracing();

    // Configuration
    let total = TOTAL_INSTANCES;
    let finalize = FINALIZE_INSTANCES;
    let out_dir: PathBuf = OUT_DIR.into();
    let k = K_CONSTRAINTS; // 2^k constraints

    // 1) Build and prove a tiny multiplicative circuit
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).expect("setup");
    let public_input = if IS_PROOF_CORRECT {
        circuit.a.unwrap() * circuit.b.unwrap()
    } else {
        ark::Fr::ZERO
    };

    // Package inputs for garbling/evaluation gadgets
    let g_input = garbled_groth16::GarblerInput {
        public_params_len: 1,
        vk: vk.clone(),
    }
    .compress();

    let total_gates = GATES_PER_INSTANCE * total as u64;
    info!("Starting cut-and-choose with {} instances", total);

    info!(
        "Total gates to process in first stage: {:.2}B",
        total_gates as f64 / 1_000_000_000.0
    );

    info!(
        "Gates per instance: {:.2}B",
        GATES_PER_INSTANCE as f64 / 1_000_000_000.0
    );

    let (g2e_tx, g2e_rx) =
        channel::unbounded::<SetupBroadcast<AesCcrGateHasher, Sha256LabelCommitHasher>>();
    let (e2g_tx, e2g_rx) = channel::unbounded::<SetupResponse<CiphertextSender>>();

    let garbler_cfg = ccn::Config::new(total, finalize, g_input.clone());
    let evaluator_cfg = garbler_cfg.clone();

    let garbler = thread::spawn(move || {
        run_garbler(
            garbler_cfg,
            pk.clone(),
            circuit,
            public_input,
            g2e_tx,
            e2g_rx,
        );
    });

    let evaluator = thread::spawn(move || run_evaluator(evaluator_cfg, out_dir, g2e_rx, e2g_tx));

    garbler.join().unwrap();
    let evaluator = evaluator.join().unwrap();

    let errors = evaluator
        .iter()
        .filter_map(|(i, ew)| (ew.value != IS_PROOF_CORRECT).then_some(i))
        .collect::<Vec<_>>();

    assert!(errors.is_empty(), "errors: {errors:?}")
}

#[allow(unused)]
fn run_garbler(
    cfg: ccn::Config,
    pk: ArkProvingKey<Bn254>,
    circuit: DummyCircuit<ark::Fr>,
    public_input: ark::Fr,
    g2e_tx: channel::Sender<SetupBroadcast<AesCcrGateHasher, Sha256LabelCommitHasher>>,
    e2g_rx: channel::Receiver<SetupResponse<CiphertextSender>>,
) {
    let mut seed_rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());

    info!(
        "Garbler: {total}/{finalized_count}",
        total = cfg.total(),
        finalized_count = cfg.finalized_count(),
    );

    info!("Garbler: creating instances...");
    let mut g = ccn::Garbler::create(&mut seed_rng, cfg.clone(), DEFAULT_CAPACITY, circuit_verify);

    info!("Garbler: generating commits...");
    let commits = g.commit::<Sha256LabelCommitHasher>();
    let circuit_commits = commits.circuit_commits.clone();
    info!("Garbler: sending commits...");
    g2e_tx
        .send(SetupBroadcast::Commit(commits))
        .expect("send commits");

    // Step 2 — Evaluator challenges the Garbler with the finalize set.
    info!("Garbler: waiting for FinalizeChallenge...");
    let SetupResponse::FinalizeChallenge(challenge) = e2g_rx.recv().expect("recv finalize senders");
    info!("Garbler: received FinalizeChallenge...");

    info!("Garbler: opening instances...");
    let finalize_indices = challenge.finalized.iter().map(|x| x.index).collect_vec();
    let (opened_instance_data, finalized_instance_data) =
        g.open_commit(challenge.finalized.clone(), circuit_verify);

    let finalized_instance_data_indices = finalized_instance_data
        .iter()
        .map(|x| x.index)
        .collect_vec();

    let opened_instance_data_indices = opened_instance_data.iter().map(|x| x.index).collect_vec();

    let (garbling_threads, wide_label_looksup): (Vec<_>, Vec<_>) = finalized_instance_data
        .into_iter()
        .map(|x| (x.garbling_thread, (x.index, x.wide_label_lookup)))
        .unzip();

    info!("Garbler: sending OpenInstances...");

    g2e_tx
        .send(SetupBroadcast::OpenInstances(
            opened_instance_data,
            wide_label_looksup,
        ))
        .expect("send open instances");

    garbling_threads.into_iter().for_each(|thread| {
        thread.join().unwrap();
    });

    info!("Garbler: generating proof...");
    let challenge_proof =
        ArkGroth16::<Bn254>::prove(&pk, circuit, &mut ChaCha20Rng::seed_from_u64(42))
            .expect("prove");
    info!("Garbler: finished generating proof...");

    // Verify the proof is valid before garbling
    let is_valid = ArkGroth16::<Bn254>::verify(&cfg.input().vk, &[public_input], &challenge_proof)
        .expect("verify");

    assert_eq!(
        is_valid, IS_PROOF_CORRECT,
        "Proof must be valid before garbling!"
    );

    info!("Garbler: generating adaptor signatures...");
    let inputs = ccn::prepare_input_labels(
        &g,
        vec![public_input],
        challenge_proof,
        challenge.assert_index,
    )
    .input;
    let wide_labels = g.wide_labels_for(challenge.assert_index);
    let gate_hasher_seed = circuit_commits[challenge.assert_index].gate_hasher_seed();
    let sigs = challenge.compute_signatures::<AesCcrGateHasher, _>(
        &wide_labels,
        &inputs,
        *gate_hasher_seed,
    );
    info!("Garbler: finished generating adaptor signatures...");

    info!("Garbler: sending Assert...");
    g2e_tx
        .send(SetupBroadcast::Assert(sigs))
        .expect("send open instances");
}

#[allow(unused)]
fn run_evaluator(
    cfg: ccn::Config,
    out_dir: PathBuf,
    g2e_rx: channel::Receiver<SetupBroadcast<AesCcrGateHasher, Sha256LabelCommitHasher>>,
    e2g_tx: channel::Sender<SetupResponse<CiphertextSender>>,
) -> Vec<(usize, EvaluatedWire)> {
    let mut rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());

    let finalize = cfg.finalized_count();

    // Step 1 — receive Commits.
    info!("Evaluator: waiting for commits...");
    let SetupBroadcast::Commit(commits) = g2e_rx.recv().expect("recv commits") else {
        panic!("unexpected message; expected commits")
    };
    info!("Evaluator: received commits...");

    // Evaluator chooses which instances to finalize with first commits
    info!("Evaluator: setting up evaluator...");
    let mut eval: Evaluator<AesCcrGateHasher, Sha256LabelCommitHasher> =
        Evaluator::create(&mut rng, cfg.clone(), commits.clone());
    let finalize_indices: Vec<usize> = eval.finalized_indexes().to_vec();

    let (tx_data, receivers): (Vec<_>, Vec<_>) = finalize_indices
        .iter()
        .map(|&index| {
            let (label_tx, label_rx) = channel::bounded(STREAM_BOUND_CIPHERTEXTS);
            let tx = FinalizeChallenge {
                index,
                ciphertext_handler: label_tx,
            };
            let rx = VsssStreamReceivers {
                index,
                ciphertext_receiver: label_rx,
            };
            (tx, rx)
        })
        .unzip();

    info!("Evaluator: setting up adaptor sigs...");
    let adaptor_sigs = {
        let dummy_sighashes = (0..commits.share_commits.len().div_ceil(256))
            .map(|i| i.to_be_bytes().to_vec())
            .collect_vec();
        EvaluatorAdaptorSigs::new(
            &mut rng,
            &finalize_indices,
            &commits.share_commits,
            &dummy_sighashes,
        )
    };

    info!("Evaluator: sending FinalizeChallenge...");
    e2g_tx
        .send(SetupResponse::FinalizeChallenge(Challenge {
            finalized: tx_data,
            adaptor_sigs: adaptor_sigs.adaptor_sigs.clone(),
            assert_index: adaptor_sigs.assert_index,
        }))
        .expect("send finalize challenge");

    info!("Evaluator: waiting for OpenInstances...");
    let SetupBroadcast::OpenInstances(open_instance_data, wide_label_lookups) =
        g2e_rx.recv().expect("recv commits")
    else {
        panic!("unexpected message; expected commits")
    };
    info!("Evaluator: received OpenInstances...");

    let out_dir = PathBuf::from("target/cut_and_choose_test_simple");
    let handler_provider =
        FileCiphertextHandlerProvider::new(out_dir.clone(), Some(STREAM_PREALLOC_BYTES))
            .expect("create sink provider");

    info!("Evaluator: regarbling...");
    eval.run_regarbling(
        &open_instance_data,
        &receivers,
        &handler_provider,
        DEFAULT_CAPACITY,
        circuit_verify,
        &wide_label_lookups,
    )
    .expect("regarbling ok");

    info!("Evaluator: waiting for asserts...");
    let SetupBroadcast::Assert(signatures) = g2e_rx.recv().expect("recv asserts") else {
        panic!("unexpected message; expected asserts")
    };
    info!("Evaluator: received asserts...");

    info!("Evaluator: evaluating wires...");
    let inputs = adaptor_sigs
        .evaluated_wires(
            &signatures,
            &wide_label_lookups,
            &open_instance_data,
            cfg.total(),
        )
        .into_iter()
        .map(|(index, wires)| {
            let input =
                EvaluatorCompressedInput::from_evaluated_inputs(1, wires, cfg.input().vk.clone());
            EvaluatorCaseInput { index, input }
        })
        .collect();

    info!("Evaluator: circuits...");
    eval.evaluate_from(&out_dir, inputs, DEFAULT_CAPACITY, circuit_verify)
        .expect("consistency checks should pass for true inputs")
}
