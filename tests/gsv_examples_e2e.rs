use std::path::PathBuf;

use ark_ff::UniformRand;
use crossbeam::channel;
use garbled_snark_verifier::{
    AesCcrGateHasher, EvaluatedWire, GarbledWire, S, WireId,
    circuit::{
        CiphertextHandler, CircuitContext, CircuitInput, CircuitMode, EncodeInput, WiresObject,
        ciphertext_source,
        modes::{EvaluateMode, GarbleMode},
    },
    cut_and_choose::{
        Config, DefaultLabelCommitHasher, FileCiphertextHandlerProvider, commit_label,
        vanilla::{self, EvaluatorCaseInput, OpenForInstance},
    },
    gadgets::bn254::fq::Fq,
    hashers::GateHasher,
};
use itertools::Itertools;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

const TOTAL_INSTANCES: usize = 4;
const FINALIZE_INSTANCES: usize = 2;
const CAPACITY: usize = 5_000;

// Fq-based types (508 wires total: 2 × 254 bits)
#[derive(Clone)]
struct FqCutAndChooseInput {
    a_m: ark_bn254::Fq,
    b_m: ark_bn254::Fq,
    prod_m: ark_bn254::Fq,
    garbled_labels: Vec<GarbledWire>,
    evaluated_labels: Option<Vec<EvaluatedWire>>,
}

impl Serialize for FqCutAndChooseInput {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        unreachable!("serialization is not used in these example tests");
    }
}

impl<'de> Deserialize<'de> for FqCutAndChooseInput {
    fn deserialize<D>(_deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        unreachable!("deserialization is not used in these example tests");
    }
}

#[derive(Clone)]
struct FqWires {
    a: Fq,
    b: Fq,
    prod_m: ark_bn254::Fq,
}

impl FqCutAndChooseInput {
    fn new(a_m: ark_bn254::Fq, b_m: ark_bn254::Fq, prod_m: ark_bn254::Fq) -> Self {
        Self {
            a_m,
            b_m,
            prod_m,
            garbled_labels: Vec::new(),
            evaluated_labels: None,
        }
    }

    fn with_labels(&self, labels: Vec<GarbledWire>) -> Self {
        let mut next = self.clone();
        next.garbled_labels = labels;
        next.evaluated_labels = None;
        next
    }

    fn with_evaluated(&self, evaluated: Vec<EvaluatedWire>) -> Self {
        let mut next = self.clone();
        next.evaluated_labels = Some(evaluated);
        next.garbled_labels.clear();
        next
    }
}

impl CircuitInput for FqCutAndChooseInput {
    type WireRepr = FqWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        FqWires {
            a: Fq::new(&mut issue),
            b: Fq::new(issue),
            prod_m: self.prod_m,
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut v = repr.a.to_wires_vec();
        v.extend(repr.b.to_wires_vec());
        v
    }
}

impl<H: GateHasher, CTH> EncodeInput<GarbleMode<H, CTH>> for FqCutAndChooseInput
where
    CTH: CiphertextHandler,
{
    fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleMode<H, CTH>) {
        for &w in repr
            .a
            .to_wires_vec()
            .iter()
            .chain(repr.b.to_wires_vec().iter())
        {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(w, gw);
        }
    }
}

impl<H: GateHasher, SRC: ciphertext_source::CiphertextSource> EncodeInput<EvaluateMode<H, SRC>>
    for FqCutAndChooseInput
{
    fn encode(&self, repr: &Self::WireRepr, cache: &mut EvaluateMode<H, SRC>) {
        let wire_ids = repr
            .a
            .to_wires_vec()
            .into_iter()
            .chain(repr.b.to_wires_vec());

        if let Some(evaluated) = &self.evaluated_labels {
            assert_eq!(
                evaluated.len(),
                repr.a.to_wires_vec().len() + repr.b.to_wires_vec().len()
            );
            for (wire_id, ew) in wire_ids.zip(evaluated.iter()) {
                cache.feed_wire(wire_id, ew.clone());
            }
            return;
        }

        // Convert Fq values to bits (254 bits each, LSB first)
        let a_bits = Fq::to_bits(self.a_m);
        let b_bits = Fq::to_bits(self.b_m);
        let bits: Vec<bool> = a_bits.into_iter().chain(b_bits).collect();

        if !self.garbled_labels.is_empty() {
            assert_eq!(bits.len(), self.garbled_labels.len());

            for ((wire_id, bit), gw) in wire_ids
                .zip(bits.into_iter())
                .zip(self.garbled_labels.iter())
            {
                let ew = EvaluatedWire::new_from_garbled(gw, bit);
                cache.feed_wire(wire_id, ew);
            }
        } else {
            // Plain bit encoding used by VSSS helper encode_input; labels are irrelevant there.
            for (wire_id, bit) in wire_ids.zip(bits.into_iter()) {
                let ew = EvaluatedWire::new(S::ZERO, bit);
                cache.feed_wire(wire_id, ew);
            }
        }
    }
}

fn build_fq_mul_eq_const<C: CircuitContext>(ctx: &mut C, inputs: &FqWires) -> WireId {
    let prod = Fq::mul_montgomery(ctx, &inputs.a, &inputs.b);
    Fq::equal_constant(ctx, &prod, &inputs.prod_m)
}

fn scenario_inputs() -> (FqCutAndChooseInput, FqCutAndChooseInput) {
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    let a = ark_bn254::Fq::rand(&mut rng);
    let b = ark_bn254::Fq::rand(&mut rng);

    let a_m = Fq::as_montgomery(a);
    let b_m = Fq::as_montgomery(b);
    let prod_m = Fq::as_montgomery(a * b);

    let b_alt = ark_bn254::Fq::rand(&mut rng);
    let b_alt_m = Fq::as_montgomery(b_alt);

    (
        FqCutAndChooseInput::new(a_m, b_m, prod_m),
        FqCutAndChooseInput::new(a_m, b_alt_m, prod_m),
    )
}

#[allow(clippy::type_complexity)]
fn finalize_channels(
    indices: &[usize],
) -> (
    Vec<(usize, channel::Sender<S>)>,
    Vec<(usize, channel::Receiver<S>)>,
) {
    indices
        .iter()
        .map(|&index| {
            let (tx, rx) = channel::unbounded::<S>();
            ((index, tx), (index, rx))
        })
        .unzip()
}

mod vanilla_flow {
    use super::*;

    #[test]
    #[ignore = "Long-running cut-and-choose example flow"]
    fn gsv_vanilla_fq_e2e_small() {
        let (input_true, input_false) = scenario_inputs();
        let mut rng = ChaCha20Rng::seed_from_u64(2025);

        let cfg_g = Config::new(TOTAL_INSTANCES, FINALIZE_INSTANCES, input_true.clone());
        let mut garbler =
            vanilla::Garbler::create(&mut rng, cfg_g, CAPACITY, build_fq_mul_eq_const);

        let first_commits = garbler.commit_phase_one::<DefaultLabelCommitHasher>();

        let cfg_e = Config::new(TOTAL_INSTANCES, FINALIZE_INSTANCES, input_true.clone());
        let mut evaluator: vanilla::Evaluator<FqCutAndChooseInput> =
            vanilla::Evaluator::create(&mut rng, cfg_e, first_commits.clone());

        let nonce = evaluator.get_nonce();
        let second_commits = garbler.commit_phase_two::<DefaultLabelCommitHasher>(nonce);
        evaluator.fill_second_commit(second_commits);

        let finalized = evaluator.finalized_indexes().to_vec().into_boxed_slice();
        let (senders, receivers) = finalize_channels(&finalized);

        let open_info = garbler.open_commit(senders, build_fq_mul_eq_const);

        let mut seeds = Vec::new();
        let mut join_handles = Vec::new();
        for item in open_info {
            match item {
                OpenForInstance::Open(i, s) => seeds.push((i, s)),
                OpenForInstance::Closed {
                    garbling_thread, ..
                } => join_handles.push(garbling_thread),
            }
        }

        let out_dir = PathBuf::from("target/gsv_example_vanilla_fq");
        let handler_provider =
            FileCiphertextHandlerProvider::new(out_dir.clone(), None).expect("sink provider");

        evaluator
            .full_check_commit(
                seeds,
                &receivers,
                &handler_provider,
                CAPACITY,
                build_fq_mul_eq_const,
            )
            .expect("full check commit ok");

        for j in join_handles {
            j.join().unwrap();
        }

        let mut cases_true = Vec::new();
        let mut cases_false = Vec::new();
        for idx in finalized.iter().copied() {
            let labels = garbler.input_labels_for(idx);
            cases_true.push(EvaluatorCaseInput {
                index: idx,
                input: input_true.with_labels(labels.clone()),
            });
            cases_false.push(EvaluatorCaseInput {
                index: idx,
                input: input_false.with_labels(labels),
            });
        }

        let results_true = evaluator
            .evaluate_from(&out_dir, cases_true, CAPACITY, build_fq_mul_eq_const)
            .expect("evaluate true");
        for (idx, out) in results_true {
            assert!(out.value, "a*b == prod_m should be true");
            assert_eq!(
                commit_label(out.active_label),
                first_commits[idx].output_commit_true()
            );
        }

        let results_false = evaluator
            .evaluate_from(&out_dir, cases_false, CAPACITY, build_fq_mul_eq_const)
            .expect("evaluate false");
        for (idx, out) in results_false {
            assert!(!out.value, "a*b_alt == prod_m should be false");
            assert_eq!(
                commit_label(out.active_label),
                first_commits[idx].output_commit_false()
            );
        }
    }
}

#[cfg(feature = "sp1-soldering")]
mod soldering_flow {
    use garbled_snark_verifier::{
        commit_label_with,
        cut_and_choose::{soldering, soldering::SolderingGarblerExt},
        hashers::Sha256LabelCommitHasher,
        sp1_soldering::SolderInput,
    };

    use super::*;

    impl SolderInput for FqCutAndChooseInput {
        fn solder(&self, per_wire_deltas: &[(S, S)]) -> Self {
            assert_eq!(
                per_wire_deltas.len(),
                self.garbled_labels.len(),
                "delta length must match input labels"
            );

            let garbled_labels = self
                .garbled_labels
                .iter()
                .zip(per_wire_deltas.iter())
                .map(|(gw, (d0, d1))| GarbledWire {
                    label0: gw.label0 ^ d0,
                    label1: gw.label1 ^ d1,
                })
                .collect();

            FqCutAndChooseInput {
                a_m: self.a_m,
                b_m: self.b_m,
                prod_m: self.prod_m,
                garbled_labels,
                evaluated_labels: None,
            }
        }
    }

    #[test]
    #[ignore = "Long-running cut-and-choose soldering example flow"]
    fn gsv_soldering_fq_e2e_small() {
        let (input_true, input_false) = scenario_inputs();
        let mut rng = ChaCha20Rng::seed_from_u64(30303);

        let cfg_g = Config::new(TOTAL_INSTANCES, FINALIZE_INSTANCES, input_true.clone());
        let mut garbler: soldering::Garbler<FqCutAndChooseInput, AesCcrGateHasher> =
            soldering::Garbler::create(&mut rng, cfg_g, CAPACITY, build_fq_mul_eq_const);

        let first_commits = garbler.commit_phase_one::<Sha256LabelCommitHasher>();

        let cfg_e = Config::new(TOTAL_INSTANCES, FINALIZE_INSTANCES, input_true.clone());
        let mut evaluator: soldering::Evaluator<FqCutAndChooseInput, _, Sha256LabelCommitHasher> =
            soldering::Evaluator::create(&mut rng, cfg_e, first_commits.clone());

        let nonce = evaluator.get_nonce();
        let second_commits = garbler.commit_phase_two::<Sha256LabelCommitHasher>(nonce);
        evaluator.fill_second_commit(second_commits);

        let finalized = evaluator.finalized_indexes().to_vec().into_boxed_slice();
        let (senders, receivers) = finalize_channels(&finalized);

        let open_info = garbler.open_commit(senders, build_fq_mul_eq_const);

        let mut seeds = Vec::new();
        let mut join_handles = Vec::new();
        for item in open_info {
            match item {
                OpenForInstance::Open(i, s) => seeds.push((i, s)),
                OpenForInstance::Closed {
                    garbling_thread, ..
                } => join_handles.push(garbling_thread),
            }
        }

        let out_dir = PathBuf::from("target/gsv_example_soldering_fq");
        let handler_provider =
            FileCiphertextHandlerProvider::new(out_dir.clone(), None).expect("sink provider");

        evaluator
            .full_check_commit(
                seeds,
                &receivers,
                &handler_provider,
                CAPACITY,
                build_fq_mul_eq_const,
            )
            .expect("full check commit ok");

        for j in join_handles {
            j.join().unwrap();
        }

        let proof = garbler.do_soldering();
        evaluator
            .verify_soldering_against_commits(proof)
            .expect("soldering verify");

        let base_index = finalized[0];
        let base_labels = garbler.input_labels_for(base_index);

        let base_true = EvaluatorCaseInput {
            index: base_index,
            input: input_true.with_labels(base_labels.clone()),
        };
        let base_false = EvaluatorCaseInput {
            index: base_index,
            input: input_false.with_labels(base_labels),
        };

        let results_true = evaluator
            .evaluate_with_soldered_instances_from(
                &out_dir,
                base_true,
                CAPACITY,
                build_fq_mul_eq_const,
            )
            .expect("evaluate soldered true");

        for (idx, out) in results_true {
            assert!(out.value, "a*b == prod_m should be true");
            assert_eq!(
                commit_label_with::<Sha256LabelCommitHasher>(out.active_label),
                first_commits[idx].output_commit_true()
            );
        }

        let results_false = evaluator
            .evaluate_with_soldered_instances_from(
                &out_dir,
                base_false,
                CAPACITY,
                build_fq_mul_eq_const,
            )
            .expect("evaluate soldered false");

        for (idx, out) in results_false {
            assert!(!out.value, "a*b_alt == prod_m should be false");
            assert_eq!(
                commit_label_with::<Sha256LabelCommitHasher>(out.active_label),
                first_commits[idx].output_commit_false()
            );
        }
    }
}

#[cfg(feature = "vsss")]
mod vsss_flow {
    use garbled_snark_verifier::cut_and_choose::vsss::{
        self, FinalizeChallenge, encode_input as encode_vsss_input,
    };

    use super::*;

    #[test]
    #[ignore = "Long-running cut-and-choose VSSS example flow"]
    fn gsv_vsss_fq_e2e_small() {
        let (input_true, input_false) = scenario_inputs();
        let mut rng = ChaCha20Rng::seed_from_u64(40404);

        let cfg_g = Config::new(TOTAL_INSTANCES, FINALIZE_INSTANCES, input_true.clone());
        let mut garbler = vsss::Garbler::create(&mut rng, cfg_g, CAPACITY, build_fq_mul_eq_const);

        let commits = garbler.commit::<DefaultLabelCommitHasher>();
        let circuit_commits = commits.circuit_commits.clone();

        let cfg_e = Config::new(TOTAL_INSTANCES, FINALIZE_INSTANCES, input_true.clone());
        let mut evaluator: vsss::Evaluator<FqCutAndChooseInput> =
            vsss::Evaluator::create(&mut rng, cfg_e, commits);

        let finalize_indices = evaluator.finalized_indexes().to_vec();

        let (senders, receivers): (Vec<_>, Vec<_>) = finalize_indices
            .iter()
            .map(|&index| {
                let (tx, rx) = channel::unbounded::<S>();
                (
                    FinalizeChallenge {
                        index,
                        ciphertext_handler: tx,
                    },
                    (index, rx),
                )
            })
            .unzip();

        let (opened_instance_data, finalized_instance_data) =
            garbler.open_commit(senders, build_fq_mul_eq_const);

        let (wide_label_lookups, threads): (Vec<_>, Vec<_>) = finalized_instance_data
            .into_iter()
            .map(|x| ((x.index, x.wide_label_lookup), x.garbling_thread))
            .unzip();

        let out_dir = PathBuf::from("target/gsv_example_vsss_fq");
        let handler_provider =
            FileCiphertextHandlerProvider::new(out_dir.clone(), None).expect("sink provider");

        evaluator
            .run_regarbling(
                &opened_instance_data,
                &receivers,
                &handler_provider,
                CAPACITY,
                build_fq_mul_eq_const,
                &wide_label_lookups,
            )
            .expect("regarbling ok");

        for thread in threads {
            thread.join().unwrap();
        }

        let mut test_cases = Vec::new();
        for (idx, (_, wide_label_lookup)) in
            finalize_indices.into_iter().zip(wide_label_lookups.iter())
        {
            for (expected, input) in [(true, &input_true), (false, &input_false)] {
                let gate_hasher_seed = circuit_commits[idx].gate_hasher_seed();
                let encoded = encode_vsss_input::<AesCcrGateHasher, _>(input, *gate_hasher_seed);

                let wide_labels = garbler
                    .wide_labels_for(idx)
                    .chunks(256)
                    .zip(encoded.chunks(8))
                    .map(|(wide_labels, bit_vals)| {
                        let wide_label_idx = bit_vals
                            .iter()
                            .fold(0u8, |acc, &val| acc.wrapping_mul(2).wrapping_add(val as u8));
                        wide_labels[wide_label_idx as usize]
                    })
                    .collect_vec();

                let evaluated_wires = wide_labels
                    .iter()
                    .zip(wide_label_lookup.iter())
                    .flat_map(|(wide_label, lookup)| lookup.lookup_evaluated_wires(wide_label))
                    .collect_vec();

                let derived_input = input.with_evaluated(evaluated_wires);

                test_cases.push((
                    expected,
                    EvaluatorCaseInput {
                        index: idx,
                        input: derived_input,
                    },
                ));
            }
        }

        let (expected, eval_cases): (Vec<_>, Vec<_>) = test_cases.into_iter().unzip();

        let results = evaluator
            .evaluate_from(&out_dir, eval_cases, CAPACITY, build_fq_mul_eq_const)
            .expect("evaluate vsss");

        for (expected, (idx, out)) in expected.iter().zip(results.iter()) {
            assert_eq!(
                out.value, *expected,
                "output should equal expected for instance {idx}"
            );
            if *expected {
                assert_eq!(
                    commit_label(out.active_label),
                    circuit_commits[*idx].output_commit_true()
                );
            } else {
                assert_eq!(
                    commit_label(out.active_label),
                    circuit_commits[*idx].output_commit_false()
                );
            }
        }
    }
}
