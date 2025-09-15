// Cut-and-choose demo over Groth16 verification circuit.
// Two-party (garbler/evaluator) protocol executed in two threads.
// Defaults: 181 total instances, 1 finalized.
// Run: `RUST_LOG=info cargo run --example groth16_cut_and_choose --release`

use std::{fs::File, io::Read, path::PathBuf, thread};

use crossbeam::channel;
use garbled_snark_verifier as gsv;
use gsv::{
    CiphertextHashAcc, S,
    ark::{self, CircuitSpecificSetupSNARK, SNARK, UniformRand},
    circuit::CircuitBuilder,
    garbled_groth16, groth16_cut_and_choose as ccn,
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

fn spawn_file_stream(path: PathBuf) -> channel::Receiver<(usize, S)> {
    let (tx, rx) = channel::unbounded::<(usize, S)>();
    thread::spawn(move || {
        let mut f = File::open(path).expect("open ciphertext file");
        let mut rec = [0u8; 8 + 16];
        loop {
            let mut read = 0usize;
            while read < rec.len() {
                match f.read(&mut rec[read..]) {
                    Ok(0) => {
                        // EOF; if mid-record, it's an error, but this file is trusted output
                        if read == 0 {
                            // normal end
                            drop(tx);
                            return;
                        } else {
                            panic!("unexpected EOF while reading ciphertexts");
                        }
                    }
                    Ok(n) => read += n,
                    Err(e) => panic!("io error reading ciphertexts: {e}"),
                }
            }

            let mut gid_bytes = [0u8; 8];
            gid_bytes.copy_from_slice(&rec[..8]);
            let gate_id = u64::from_le_bytes(gid_bytes) as usize;

            let mut s_bytes = [0u8; 16];
            s_bytes.copy_from_slice(&rec[8..]);
            let s = S::from_bytes(s_bytes);

            if tx.send((gate_id, s)).is_err() {
                return; // receiver dropped
            }
        }
    });
    rx
}

fn main() {
    if !gsv::hardware_aes_available() {
        eprintln!(
            "Warning: AES hardware acceleration not detected; using software AES (not constant-time)."
        );
    }

    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

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
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = ark::Groth16::<ark::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");

    // Package inputs for garbling/evaluation gadgets
    let g_input = garbled_groth16::GarblerInput {
        public_params_len: 1,
        vk: vk.clone(),
    }
    .compress();
    let eval_proof = garbled_groth16::Proof::new(proof, vec![c_val]);

    let total = 3usize;
    let to_finalize = 1usize;

    // Channels for the two-party protocol
    let (commits_tx, commits_rx) = channel::bounded(1);
    let (finalize_senders_tx, finalize_senders_rx) = channel::bounded(1);
    let (open_result_tx, open_result_rx) = channel::bounded(1);
    let (labels_req_tx, labels_req_rx) = channel::bounded::<usize>(1);
    let (labels_resp_tx, labels_resp_rx) =
        channel::bounded::<(u128, u128, Vec<gsv::GarbledWire>)>(1);

    // Garbler thread
    let vk_g = vk.clone();
    let g_input_g = g_input.clone();
    let garbler = thread::spawn(move || {
        let mut seed_rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());
        let cfg = ccn::Config::new(total, to_finalize, g_input_g);
        let g = ccn::Garbler::create(&mut seed_rng, cfg);

        // Send commits to evaluator
        let commits = g.commit();
        commits_tx.send(commits).expect("send commits");

        // Receive which indices to finalize + ciphertext senders
        let finalize_senders = finalize_senders_rx.recv().expect("recv finalize senders");

        // Start streaming ciphertexts for finalized instances; return open/closed set
        let open_result = g.open_commit(finalize_senders);
        open_result_tx.send(open_result).expect("send open_result");

        // Provide constants and input labels for the (single) finalized instance on request
        if let Ok(idx) = labels_req_rx.recv() {
            let (t, f) = g.constants_for(idx);
            let labels = g.input_labels_for(idx);
            labels_resp_tx
                .send((t, f, labels))
                .expect("send labels + constants");
        }

        drop(vk_g);
    });

    // Evaluator thread
    let vk_e = vk.clone();
    let e_input = g_input.clone();
    let evaluator = thread::spawn(move || {
        // Receive commits from garbler
        let commits = commits_rx.recv().expect("recv commits");
        let commits_for_check = commits.clone();

        // Build evaluator-side state and choose which instance to finalize
        let cfg = ccn::Config::new(total, to_finalize, e_input);
        let mut eval = ccn::Evaluator::create(&mut rng, cfg, commits);
        let finalize: Vec<usize> = eval.get_indexes_to_finalize().to_vec();
        assert_eq!(finalize.len(), 1, "expected exactly one finalized instance");
        info!("Evaluator selected to finalize index {}", finalize[0]);

        // Prepare senders for finalized instances (ciphertext streaming) and send to garbler
        let senders = eval.make_finalize_senders();
        finalize_senders_tx
            .send(senders)
            .expect("send finalize senders to garbler");

        // Receive and verify open/closed instances; write ciphertexts for closed to disk
        let open_result = open_result_rx.recv().expect("recv open_result");
        let out_dir: PathBuf = ["target", "cut_and_choose"].iter().collect();
        eval.regarbling(open_result, &out_dir)
            .expect("regarbling checks");

        // Ask for constants and input labels for the single finalized instance
        let idx = finalize[0];
        labels_req_tx
            .send(idx)
            .expect("request labels for finalized idx");
        let (true_const, false_const, input_labels) =
            labels_resp_rx.recv().expect("receive labels + constants");

        // Build evaluator input from labels + proof
        let eval_input =
            garbled_groth16::EvaluatorCompressedInput::new(eval_proof, vk_e.clone(), input_labels);

        // Stream ciphertexts for this instance from file to the evaluator
        let file_path = out_dir.join(format!("gc_{}.bin", idx));
        let rx = spawn_file_stream(file_path);

        // Evaluate
        let result: gsv::circuit::StreamingResult<
            gsv::circuit::modes::EvaluateMode<gsv::AesNiHasher>,
            _,
            gsv::EvaluatedWire,
        > = CircuitBuilder::streaming_evaluation(
            eval_input,
            160_000,
            true_const,
            false_const,
            rx,
            garbled_groth16::verify_compressed,
        );

        let out = result.output_value;
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
    });

    garbler.join().unwrap();
    evaluator.join().unwrap();
}
