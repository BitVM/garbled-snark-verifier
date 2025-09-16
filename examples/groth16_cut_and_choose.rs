use std::{path::PathBuf, thread};

use crossbeam::channel;
use garbled_snark_verifier::{self as gsv, OpenForInstance};
use gsv::{
    CiphertextHashAcc, S,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    garbled_groth16, groth16_cut_and_choose as ccn,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tracing::{error, info};

// Configuration constants - modify these as needed
const TOTAL_INSTANCES: usize = 181;
const FINALIZE_INSTANCES: usize = 7;
const OUT_DIR: &str = "target/cut_and_choose";
const K_CONSTRAINTS: u32 = 6; // 2^k constraints

// Lightweight control-plane messages between parties.
enum G2EMsg {
    // Garbler -> Evaluator: commitments for all instances
    Commits(Vec<gsv::GarbledInstanceCommit>),
    // Garbler -> Evaluator: indices and seeds for instances to open
    OpenSeeds(Vec<(usize, ccn::Seed)>),
    // Garbler -> Evaluator: constants and input labels for finalized instances
    FinalizedData(Vec<(usize, u128, u128, Vec<gsv::GarbledWire>)>),
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
    if !gsv::hardware_aes_available() {
        eprintln!(
            "Warning: AES hardware acceleration not detected; using software AES (not constant-time)."
        );
    }

    gsv::init_tracing();

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

    // Garbler thread
    let g_input_g = g_input.clone();
    let garbler = thread::spawn(move || {
        let mut seed_rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());
        let cfg = ccn::Config::new(total, finalize, g_input_g);
        info!(
            "Garbler: Creating {} instances ({} to finalize)",
            total, finalize
        );
        // Create garbler (uses optimized thread pool internally)
        let g = ccn::Garbler::create(&mut seed_rng, cfg);

        // Send commits to evaluator
        let commits = g.commit();
        g2e_tx.send(G2EMsg::Commits(commits)).expect("send commits");

        // Receive which indices to finalize + ciphertext senders
        let E2GMsg::FinalizeSenders(finalize_senders) =
            e2g_rx.recv().expect("recv finalize senders");

        // Start streaming ciphertexts for finalized instances; return open/closed set
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

        // Inform evaluator which instances were opened and with which seeds
        g2e_tx
            .send(G2EMsg::OpenSeeds(seeds))
            .expect("send open_result");

        threads.into_iter().for_each(|th| {
            if let Err(err) = th.join() {
                error!("while regarbling: {err:?}")
            }
        });

        // After regarbling, send constants + input labels for finalized instance(s)
        let fin_data: Vec<(usize, u128, u128, Vec<gsv::GarbledWire>)> = finalized_indices
            .into_iter()
            .map(|idx| {
                let (t, f) = g.constants_for(idx);
                let inputs = g.input_labels_for(idx);
                (idx, t, f, inputs)
            })
            .collect();
        g2e_tx
            .send(G2EMsg::FinalizedData(fin_data))
            .expect("send finalized labels/constants");
    });

    // Evaluator thread
    let vk_e = vk.clone();
    let e_input = g_input.clone();
    let evaluator = thread::spawn(move || {
        // Receive commits from garbler
        let commits = match g2e_rx.recv().expect("recv commits") {
            G2EMsg::Commits(c) => c,
            _ => panic!("unexpected message; expected commits"),
        };
        let commits_for_check = commits.clone();

        // Prepare ciphertext channels for finalized instances (receivers to Evaluator, senders to Garbler)
        let mut receivers = Vec::with_capacity(finalize);
        let mut senders = Vec::with_capacity(finalize);
        // Use unbounded channels since we're writing to disk
        for _ in 0..finalize {
            let (tx, rx) = channel::unbounded::<(usize, S)>();
            senders.push(tx);
            receivers.push(rx);
        }

        // Build evaluator-side state and choose which instance(s) to finalize
        let cfg = ccn::Config::new(total, finalize, e_input);
        let eval = ccn::Evaluator::create(&mut rng, cfg, commits, receivers);
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

        // Zip chosen indices with corresponding senders and send to garbler
        let finalize_senders: Vec<(usize, channel::Sender<(usize, S)>)> =
            finalize_indices.iter().copied().zip(senders).collect();

        e2g_tx
            .send(E2GMsg::FinalizeSenders(finalize_senders))
            .expect("send finalize senders to garbler");

        // Receive and verify open/closed instances; write ciphertexts for closed to disk
        let open_result = match g2e_rx.recv().expect("recv open_result") {
            G2EMsg::OpenSeeds(s) => s,
            _ => panic!("unexpected message; expected open seeds"),
        };
        info!("Output dir: {}", out_dir.display());

        // Run regarbling checks (uses optimized thread pool internally)
        eval.run_regarbling(open_result, &out_dir)
            .expect("regarbling checks");

        // Receive constants and input labels for finalized instance(s)
        let fin = match g2e_rx.recv() {
            Ok(G2EMsg::FinalizedData(v)) => v,
            _ => panic!("unexpected message; expected finalized data"),
        };

        // Build a single Groth16 proof once and reuse for all finalized instances
        let eval_proof = garbled_groth16::Proof::new(
            ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove"),
            vec![c_val],
        );

        // Persist finalized instance inputs for later "eval-only" runs
        // and build cases: (index, EvaluatorInput, (true,false) constants)
        let cases: Vec<(
            usize,
            garbled_groth16::EvaluatorCompressedInput,
            (u128, u128),
        )> = fin
            .into_iter()
            .map(|(idx, t, f, labels)| {
                // Save constants as two 16-byte big-endian words
                {
                    use std::io::Write;
                    let const_path = out_dir.join(format!("gc_{}.consts.bin", idx));
                    let mut w = std::io::BufWriter::new(
                        std::fs::File::create(&const_path).expect("create consts file"),
                    );
                    w.write_all(&gsv::S::from_u128(t).to_bytes()).unwrap();
                    w.write_all(&gsv::S::from_u128(f).to_bytes()).unwrap();
                    w.flush().ok();
                }

                // Save labels as: u64 count (LE), then pairs of 16-byte big-endian (label0,label1)
                {
                    use std::io::Write;
                    let labels_path = out_dir.join(format!("gc_{}.labels.bin", idx));
                    let mut w = std::io::BufWriter::new(
                        std::fs::File::create(&labels_path).expect("create labels file"),
                    );
                    let count = labels.len() as u64;
                    w.write_all(&count.to_le_bytes()).unwrap();
                    for gw in &labels {
                        w.write_all(&gw.label0.to_bytes()).unwrap();
                        w.write_all(&gw.label1.to_bytes()).unwrap();
                    }
                    w.flush().ok();
                }

                let input = garbled_groth16::EvaluatorCompressedInput::new(
                    eval_proof.clone(),
                    vk_e.clone(),
                    labels,
                );
                (idx, input, (t, f))
            })
            .collect();

        // Evaluate all saved ciphertexts (uses optimized thread pool internally)
        let results = ccn::Evaluator::evaluate_from_saved_all(cases, 160_000, &out_dir);

        for (idx, out) in results {
            info!(
                "Finalized instance {}: is_proof_correct = {}",
                idx, out.value
            );
            assert!(out.value, "Groth16 verification should succeed");

            // Compute commit of resulting output label and compare with the appropriate one
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
    });

    garbler.join().unwrap();
    evaluator.join().unwrap();
}
