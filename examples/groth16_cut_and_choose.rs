use std::{path::PathBuf, thread};

use ark_ec::AffineRepr;
use ark_ff::AdditiveGroup;
use crossbeam::channel;
use garbled_snark_verifier::{
    EvaluatedWire, GarbledInstanceCommit, OpenForInstance, S,
    ark::{
        self, Bn254, CircuitSpecificSetupSNARK, Groth16 as ArkGroth16, ProvingKey as ArkProvingKey,
        SNARK, UniformRand,
    },
    circuit::{CiphertextHandler, CiphertextSender, CircuitBuilder},
    cut_and_choose::FileCiphertextHandlerProvider,
    garbled_groth16,
    groth16_cut_and_choose::{self as ccn, EvaluatorCaseInput},
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tracing::{error, info};

// Configuration constants - modify these as needed
const TOTAL_INSTANCES: usize = 3;
const FINALIZE_INSTANCES: usize = 1;
const OUT_DIR: &str = "target/cut_and_choose";
const K_CONSTRAINTS: u32 = 5; // 2^k constraints
const IS_PROOF_CORRECT: bool = true;
const IS_PRE_BOOLEAN_EXEC: bool = false;

enum G2EMsg {
    // Garbler -> Evaluator: commitments for all instances
    Commits(Vec<GarbledInstanceCommit>),
    // Garbler -> Evaluator: indices and seeds for instances to open
    OpenSeeds(Vec<(usize, ccn::Seed)>),
    // Garbler -> Evaluator: fully built evaluator inputs for finalized instances
    OpenLabels(Vec<EvaluatorCaseInput>),
}

enum E2GMsg<CTH: 'static + Send + CiphertextHandler> {
    // Evaluator -> Garbler: senders to forward ciphertexts for finalized instances
    Challenge(Vec<(usize, CTH)>),
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

    let (g2e_tx, g2e_rx) = channel::unbounded::<G2EMsg>();
    let (e2g_tx, e2g_rx) = channel::unbounded::<E2GMsg<CiphertextSender>>();

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

fn run_garbler(
    cfg: ccn::Config,
    pk: ArkProvingKey<Bn254>,
    circuit: DummyCircuit<ark::Fr>,
    public_input: ark::Fr,
    g2e_tx: channel::Sender<G2EMsg>,
    e2g_rx: channel::Receiver<E2GMsg<CiphertextSender>>,
) {
    let mut seed_rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());

    info!(
        "Garbler: {total}/{to_finalize}",
        total = cfg.total(),
        to_finalize = cfg.to_finalize(),
    );

    let mut g = ccn::Garbler::create(&mut seed_rng, cfg.clone());

    g2e_tx
        .send(G2EMsg::Commits(g.commit()))
        .expect("send commits");

    let E2GMsg::Challenge(finalize_senders) = e2g_rx.recv().expect("recv finalize senders");

    let mut seeds = vec![];
    let mut threads = vec![];

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

    let challenge_proof =
        ArkGroth16::<Bn254>::prove(&pk, circuit, &mut ChaCha20Rng::seed_from_u64(42))
            .expect("prove");

    // Verify the proof is valid before garbling
    let is_valid = ArkGroth16::<Bn254>::verify(&cfg.input().vk, &[public_input], &challenge_proof)
        .expect("verify");

    assert_eq!(
        is_valid, IS_PROOF_CORRECT,
        "Proof must be valid before garbling!"
    );

    let is_valid = ArkGroth16::<Bn254>::verify(&cfg.input().vk, &[public_input], &challenge_proof)
        .expect("verify");

    info!("Proof is_valid: {is_valid}");
    assert_eq!(
        is_valid, IS_PROOF_CORRECT,
        "Proof must be {IS_PROOF_CORRECT} before garbling!"
    );

    // Test only
    if IS_PRE_BOOLEAN_EXEC {
        let streaming_result: garbled_snark_verifier::circuit::StreamingResult<_, _, bool> =
            CircuitBuilder::streaming_execute(
                garbled_groth16::VerifierInput {
                    public: vec![public_input],
                    a: challenge_proof.a.into_group(),
                    b: challenge_proof.b.into_group(),
                    c: challenge_proof.c.into_group(),
                    vk: cfg.input().vk.clone(),
                }
                .compress(),
                150_000,
                garbled_groth16::verify_compressed,
            );

        assert_eq!(
            streaming_result.output_value, IS_PROOF_CORRECT,
            "Streaming verification result should match IS_PROOF_CORRECT flag"
        );
    }

    let fin_inputs = g.prepare_input_labels(vec![public_input], challenge_proof);

    g2e_tx
        .send(G2EMsg::OpenLabels(fin_inputs))
        .expect("send finalized evaluator inputs");
}

fn run_evaluator(
    cfg: ccn::Config,
    out_dir: PathBuf,
    g2e_rx: channel::Receiver<G2EMsg>,
    e2g_tx: channel::Sender<E2GMsg<CiphertextSender>>,
) -> Vec<(usize, EvaluatedWire)> {
    let mut rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());

    let finalize = cfg.to_finalize();

    let G2EMsg::Commits(commits) = g2e_rx.recv().expect("recv commits") else {
        panic!("unexpected message; expected commits")
    };

    let eval = ccn::Evaluator::create(&mut rng, cfg.clone(), commits);

    let finalize_indices: Vec<usize> = eval.finalized_indexes().to_vec();

    // Build channels for finalized instances using iterator + unzip
    let (senders, receivers): (Vec<_>, Vec<_>) = finalize_indices
        .iter()
        .map(|&index| {
            let (tx, rx) = channel::unbounded::<S>();
            ((index, tx), (index, rx))
        })
        .unzip();

    assert_eq!(
        finalize_indices.len(),
        finalize,
        "unexpected finalize count"
    );
    info!(
        "Evaluator selected to finalize index {}",
        finalize_indices[0]
    );

    e2g_tx
        .send(E2GMsg::Challenge(senders))
        .expect("send finalize senders to garbler");

    let G2EMsg::OpenSeeds(open_result) = g2e_rx.recv().expect("recv open_result") else {
        panic!("unexpected message; expected open seeds")
    };

    info!("Output dir: {}", out_dir.display());

    eval.run_regarbling(
        open_result,
        &receivers,
        &FileCiphertextHandlerProvider::new(out_dir.clone(), None).unwrap(),
    )
    .expect("regarbling checks");

    let Ok(G2EMsg::OpenLabels(cases)) = g2e_rx.recv() else {
        panic!("unexpected message; expected finalized inputs")
    };

    eval.evaluate_from(&out_dir, cases).unwrap()
}
