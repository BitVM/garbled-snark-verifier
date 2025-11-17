//! High-level driver showcasing the cut-and-choose Setup/Evaluate flow from
//! `docs/gsv_spec.md` using the Groth16 verifier gadget.
use std::{path::PathBuf, thread};

use ark_ff::AdditiveGroup;
use crossbeam::channel::{self};
use garbled_snark_verifier::{
    EvaluatedWire,
    ark::{
        self, Bn254, CircuitSpecificSetupSNARK, Groth16 as ArkGroth16, ProvingKey as ArkProvingKey,
        SNARK, UniformRand,
    },
    cac::vsss::lagrange_interpolate_whole_polynomial,
    circuit::CiphertextSender,
    cut_and_choose::{
        Evaluator, EvaluatorCaseInput, FileCiphertextHandlerProvider, VsssGarbler,
        vsss::{
            Challenge, EvaluatorAdaptorSigs, FinalizeChallenge, SetupBroadcast, SetupResponse,
            VsssStreamReceivers, encode_input, transpose,
        },
    },
    garbled_groth16::{self, EvaluatorCompressedInput},
    groth16_cut_and_choose::{self as ccn, DEFAULT_CAPACITY},
    hashers::DefaultLabelCommitHasher,
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

// Calculate and display total gates to process
const GATES_PER_INSTANCE: u64 = 11_174_708_821;

// note: uncomment to use a dummy circuit for faster tetsing. Note that the evaluation will fail
// due to the input being incorrect.
// use dummy_circuit::verify_compressed as circuit_verify;
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
                    one_bits.push(wire.clone());
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

// Simple multiplicative circuit used to produce a valid Groth16 proof.
#[derive(Copy, Clone)]
#[allow(unused)]
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

    let (g2e_tx, g2e_rx) = channel::unbounded::<SetupBroadcast<DefaultLabelCommitHasher>>();
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
    g2e_tx: channel::Sender<SetupBroadcast<DefaultLabelCommitHasher>>,
    e2g_rx: channel::Receiver<SetupResponse<CiphertextSender>>,
) {
    let mut seed_rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());

    info!(
        "Garbler: {total}/{to_finalize}",
        total = cfg.total(),
        to_finalize = cfg.to_finalize(),
    );

    let mut g = ccn::VsssGarbler::from_inner(VsssGarbler::create(
        &mut seed_rng,
        cfg.clone(),
        DEFAULT_CAPACITY,
        circuit_verify,
    ));

    g2e_tx
        .send(SetupBroadcast::Commit(
            g.commit::<DefaultLabelCommitHasher>(),
        ))
        .expect("send commits");

    // Step 2 — Evaluator challenges the Garbler with the finalize set.
    let SetupResponse::FinalizeChallenge(challenge) = e2g_rx.recv().expect("recv finalize senders");

    let finalize_indices = challenge.to_finalize.iter().map(|x| x.index).collect_vec();

    let (opened_instance_data, finalized_instance_data) =
        g.inner().open_commit(challenge.to_finalize, circuit_verify);

    let finalized_instance_data_indices = finalized_instance_data
        .iter()
        .map(|x| x.index)
        .collect_vec();

    let opened_instance_data_indices = opened_instance_data.iter().map(|x| x.index).collect_vec();

    let (garbling_threads, wide_label_looksup): (Vec<_>, Vec<_>) = finalized_instance_data
        .into_iter()
        .map(|x| (x.garbling_thread, (x.index, x.wide_label_lookup)))
        .unzip();

    g2e_tx
        .send(SetupBroadcast::OpenInstances(
            opened_instance_data,
            wide_label_looksup,
        ))
        .expect("send open instances");

    garbling_threads.into_iter().for_each(|thread| {
        thread.join().unwrap();
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

    let inputs = g
        .prepare_input_labels(vec![public_input], challenge_proof, challenge.assert_index)
        .input;

    let encoded = encode_input(&inputs);

    // Step 4: translate input labels to wide labels
    let sigs = g
        .wide_labels_for(challenge.assert_index)
        .chunks(256)
        .into_iter()
        .zip(encoded.chunks(8))
        .map(|(wide_labels, bit_vals)| {
            let wide_label_idx = bit_vals.iter().fold(0, |acc, &val| acc * 2 + val as u8);
            wide_labels[wide_label_idx as usize]
        })
        .zip_eq(challenge.adaptor_sigs.iter())
        .map(|(wide_label, adaptor_sig)| adaptor_sig.garbler_signature(&wide_label))
        .collect::<Result<Vec<_>, _>>()
        .expect("adaptor sigs should be valid");

    g2e_tx
        .send(SetupBroadcast::Assert(sigs))
        .expect("send open instances");
}

#[allow(unused)]
fn run_evaluator(
    cfg: ccn::Config,
    out_dir: PathBuf,
    g2e_rx: channel::Receiver<SetupBroadcast<DefaultLabelCommitHasher>>,
    e2g_tx: channel::Sender<SetupResponse<CiphertextSender>>,
) -> Vec<(usize, EvaluatedWire)> {
    let mut rng = ChaCha20Rng::seed_from_u64(rand::thread_rng().r#gen());

    let finalize = cfg.to_finalize();

    // Step 1 — receive Commits.
    let SetupBroadcast::Commit(commits) = g2e_rx.recv().expect("recv commits") else {
        panic!("unexpected message; expected commits")
    };

    // Evaluator chooses which instances to finalize with first commits
    let mut eval: Evaluator<garbled_groth16::GarblerCompressedInput, DefaultLabelCommitHasher> =
        Evaluator::create_vsss(&mut rng, cfg.clone(), commits.clone());
    let finalize_indices: Vec<usize> = eval.finalized_indexes().to_vec();

    let (tx_data, receivers): (Vec<_>, Vec<_>) = finalize_indices
        .iter()
        .map(|&index| {
            let (label_tx, label_rx) = channel::bounded(1024);
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

    e2g_tx
        .send(SetupResponse::FinalizeChallenge(Challenge {
            to_finalize: tx_data,
            adaptor_sigs: adaptor_sigs.adaptor_sigs.clone(),
            assert_index: adaptor_sigs.assert_index,
        }))
        .expect("send finalize challenge");

    let SetupBroadcast::OpenInstances(open_instance_data, wide_label_lookups) =
        g2e_rx.recv().expect("recv commits")
    else {
        panic!("unexpected message; expected commits")
    };

    let out_dir = PathBuf::from("target/cut_and_choose_test_simple");
    let handler_provider =
        FileCiphertextHandlerProvider::new(out_dir.clone(), None).expect("create sink provider");

    eval.run_regarbling_vsss(
        &open_instance_data,
        &receivers,
        &handler_provider,
        DEFAULT_CAPACITY,
        circuit_verify,
        &wide_label_lookups,
    )
    .expect("regarbling ok");

    let SetupBroadcast::Assert(signatures) = g2e_rx.recv().expect("recv asserts") else {
        panic!("unexpected message; expected asserts")
    };

    let wide_labels = adaptor_sigs
        .adaptor_sigs
        .iter()
        .zip_eq(signatures)
        .map(|(adaptor_sig, signature)| {
            adaptor_sig
                .extract_secret(&signature)
                .expect("adaptor sigs should be valid")
        })
        .collect_vec();

    let value_indices = {
        let wide_label_lookup = &wide_label_lookups
            .iter()
            .find(|x| x.0 == adaptor_sigs.assert_index)
            .unwrap()
            .1;
        wide_labels
            .iter()
            .zip(wide_label_lookup.iter())
            .map(|(wide_label, wide_label_lookup)| wide_label_lookup.lookup_index(&wide_label))
            .collect_vec()
    };

    let known_labels = open_instance_data
        .into_iter()
        .map(|x| {
            (
                x.index, // instance index
                x.shares
                    .chunks(256)
                    .zip(value_indices.iter())
                    .map(|(share, index)| share[*index].0) // out of the 256 possible values, use the selected one
                    .collect_vec(),
            )
        })
        .chain(std::iter::once((
            adaptor_sigs.assert_index,
            wide_labels.clone(),
        )))
        .collect_vec();

    let missing_indices = (0..cfg.total())
        .filter(|&i| !known_labels.iter().any(|(j, _)| j == &i))
        .collect_vec();

    let num_labels = known_labels[0].1.len();
    let mut interpolated_labels = vec![];

    for i in 0..num_labels {
        let known = known_labels
            .iter()
            .map(|(j, shares)| (*j, shares[i]))
            .collect_vec();
        let missing = lagrange_interpolate_whole_polynomial(&known, &missing_indices);
        interpolated_labels.push(missing);
    }

    let interpolated_labels = transpose(&interpolated_labels);

    let all_finalized_labels = missing_indices
        .into_iter()
        .zip(interpolated_labels.into_iter())
        .chain(std::iter::once((
            adaptor_sigs.assert_index,
            wide_labels.clone(),
        )));

    let inputs = all_finalized_labels
        .map(|(index, labels)| {
            let wide_label_lookup = &wide_label_lookups.iter().find(|x| x.0 == index).unwrap().1;

            let evaluated_wires = labels
                .iter()
                .zip(wide_label_lookup.iter())
                .flat_map(|(wide_label, wide_label_lookup)| {
                    wide_label_lookup.lookup_evaluated_wires(&wide_label)
                })
                .collect_vec();

            let input = EvaluatorCompressedInput::from_evaluated_inputs(
                1,
                evaluated_wires,
                cfg.input().vk.clone(),
            );
            EvaluatorCaseInput { index, input }
        })
        .collect_vec();

    let results = eval
        .evaluate_from(&out_dir, inputs, DEFAULT_CAPACITY, circuit_verify)
        .expect("consistency checks should pass for true inputs");

    results
}
