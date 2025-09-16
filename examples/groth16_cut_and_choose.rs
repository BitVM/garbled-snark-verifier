use std::{path::PathBuf, thread};

use ark_bn254::Bn254;
use ark_groth16::{
    Groth16 as ArkGroth16, ProvingKey as ArkProvingKey, VerifyingKey as ArkVerifyingKey,
};
use crossbeam::channel;
use garbled_snark_verifier::{
    CiphertextHashAcc, GarbledInstanceCommit, OpenForInstance, S,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    garbled_groth16, groth16_cut_and_choose as ccn,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tracing::{error, info};

// Configuration constants - modify these as needed
const TOTAL_INSTANCES: usize = 3;
const FINALIZE_INSTANCES: usize = 1;
const OUT_DIR: &str = "target/cut_and_choose";
const K_CONSTRAINTS: u32 = 6; // 2^k constraints
// Default pipeline capacity matching library default
const CAPACITY_EVAL: usize = 160_000;

// Lightweight control-plane messages between parties.
// Compact type for finalized-evaluation input sent by Garbler
struct FinalizedCase {
    index: usize,
    input: garbled_groth16::EvaluatorCompressedInput,
    consts: (u128, u128), // (true_const, false_const)
}

enum G2EMsg {
    // Garbler -> Evaluator: commitments for all instances
    Commits(Vec<GarbledInstanceCommit>),
    // Garbler -> Evaluator: indices and seeds for instances to open
    OpenSeeds(Vec<(usize, ccn::Seed)>),
    // Garbler -> Evaluator: fully built evaluator inputs for finalized instances
    FinalizedInputs(Vec<FinalizedCase>),
}

enum E2GMsg {
    // Evaluator -> Garbler: senders to forward ciphertexts for finalized instances
    FinalizeSenders(Vec<(usize, channel::Sender<(usize, S)>)>),
}

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

// Calculate and display total gates to process
const GATES_PER_INSTANCE: u64 = 11_174_708_821;

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
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();

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

    // Control-plane channels
    let (g2e_tx, g2e_rx) = channel::unbounded::<G2EMsg>();
    let (e2g_tx, e2g_rx) = channel::unbounded::<E2GMsg>();

    // Create configs for both parties
    let garbler_cfg = ccn::Config::new(total, finalize, g_input.clone());
    let evaluator_cfg = ccn::Config::new(total, finalize, g_input.clone());

    // Spawn both parties
    let garbler = thread::spawn(move || {
        run_garbler(
            garbler_cfg,
            pk.clone(),
            vk.clone(),
            circuit,
            c_val,
            g2e_tx,
            e2g_rx,
        );
    });

    let evaluator = thread::spawn(move || {
        run_evaluator(evaluator_cfg, out_dir, g2e_rx, e2g_tx);
    });

    garbler.join().unwrap();
    evaluator.join().unwrap();
}

fn run_garbler(
    cfg: ccn::Config<garbled_groth16::GarblerCompressedInput>,
    pk: ArkProvingKey<Bn254>,
    vk: ArkVerifyingKey<Bn254>,
    circuit: DummyCircuit<ark::Fr>,
    c_val: ark::Fr,
    g2e_tx: channel::Sender<G2EMsg>,
    e2g_rx: channel::Receiver<E2GMsg>,
) {
    let mut seed_rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());

    let total = cfg.total();
    let finalize = cfg.to_finalize();

    info!(
        "Garbler: Creating {} instances ({} to finalize)",
        total, finalize
    );
    let g = ccn::Garbler::create(&mut seed_rng, cfg.clone());

    let commits = g.commit();
    g2e_tx.send(G2EMsg::Commits(commits)).expect("send commits");

    let E2GMsg::FinalizeSenders(finalize_senders) = e2g_rx.recv().expect("recv finalize senders");

    let mut seeds = vec![];
    let mut threads = vec![];
    let finalized_indices: Vec<usize> = finalize_senders.iter().map(|(i, _)| *i).collect();

    for commit in g.open_commit(finalize_senders) {
        match commit {
            OpenForInstance::Closed {
                index: _index,
                garbling_thread,
            } => threads.push(garbling_thread),
            OpenForInstance::Open(index, seed) => seeds.push((index, seed)),
        }
    }

    g2e_tx
        .send(G2EMsg::OpenSeeds(seeds))
        .expect("send open_result");

    threads.into_iter().for_each(|th| {
        if let Err(err) = th.join() {
            error!("while regarbling: {err:?}")
        }
    });

    let mut proof_rng = ChaCha20Rng::seed_from_u64(42);
    let eval_proof = garbled_groth16::Proof::new(
        ArkGroth16::<Bn254>::prove(&pk, circuit, &mut proof_rng).expect("prove"),
        vec![c_val],
    );

    let fin_inputs: Vec<FinalizedCase> = finalized_indices
        .into_iter()
        .map(|idx| {
            let (t, f) = g.constants_for(idx);
            let labels = g.input_labels_for(idx);
            let input = garbled_groth16::EvaluatorCompressedInput::new(
                eval_proof.clone(),
                vk.clone(),
                labels,
            );
            FinalizedCase {
                index: idx,
                input,
                consts: (t, f),
            }
        })
        .collect();

    g2e_tx
        .send(G2EMsg::FinalizedInputs(fin_inputs))
        .expect("send finalized evaluator inputs");
}

fn run_evaluator(
    cfg: ccn::Config<garbled_groth16::GarblerCompressedInput>,
    out_dir: PathBuf,
    g2e_rx: channel::Receiver<G2EMsg>,
    e2g_tx: channel::Sender<E2GMsg>,
) {
    let mut rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());

    let finalize = cfg.to_finalize();

    let commits = match g2e_rx.recv().expect("recv commits") {
        G2EMsg::Commits(c) => c,
        _ => panic!("unexpected message; expected commits"),
    };
    let commits_for_check = commits.clone();

    let mut receivers = Vec::with_capacity(finalize);
    let mut senders = Vec::with_capacity(finalize);
    for _ in 0..finalize {
        let (tx, rx) = channel::unbounded::<(usize, S)>();
        senders.push(tx);
        receivers.push(rx);
    }
    let eval = ccn::Evaluator::create(&mut rng, cfg.clone(), commits, receivers);
    let finalize_indices: Vec<usize> = eval.get_indexes_to_finalize().to_vec();
    assert_eq!(
        finalize_indices.len(),
        finalize,
        "unexpected finalize count"
    );
    info!(
        "Evaluator selected to finalize index {}",
        finalize_indices[0]
    );

    let finalize_senders: Vec<(usize, channel::Sender<(usize, S)>)> =
        finalize_indices.iter().copied().zip(senders).collect();
    e2g_tx
        .send(E2GMsg::FinalizeSenders(finalize_senders))
        .expect("send finalize senders to garbler");

    let open_result = match g2e_rx.recv().expect("recv open_result") {
        G2EMsg::OpenSeeds(s) => s,
        _ => panic!("unexpected message; expected open seeds"),
    };
    info!("Output dir: {}", out_dir.display());
    eval.run_regarbling(open_result, &out_dir)
        .expect("regarbling checks");

    let cases: Vec<(
        usize,
        garbled_groth16::EvaluatorCompressedInput,
        (u128, u128),
    )> = match g2e_rx.recv() {
        Ok(G2EMsg::FinalizedInputs(v)) => v
            .into_iter()
            .map(|c| (c.index, c.input, c.consts))
            .collect(),
        _ => panic!("unexpected message; expected finalized inputs"),
    };

    let results = ccn::Evaluator::evaluate_from_saved_all(cases, CAPACITY_EVAL, &out_dir);
    for (idx, out) in results {
        info!(
            "Finalized instance {}: is_proof_correct = {}",
            idx, out.value
        );
        assert!(out.value, "Groth16 verification should succeed");
        let mut h = CiphertextHashAcc::default();
        h.update(out.active_label);
        let out_label_commit = h.finalize();
        let expected_commit = if out.value {
            commits_for_check[idx].output_commit_label1()
        } else {
            commits_for_check[idx].output_commit_label0()
        };
        assert_eq!(
            out_label_commit, expected_commit,
            "Output label commit mismatch for finalized instance"
        );
    }
}
