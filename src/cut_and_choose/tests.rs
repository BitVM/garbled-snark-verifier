use std::path::PathBuf;

use crossbeam::channel;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::*;
use crate::{
    EvaluatedWire, GarbleMode, GarbledWire, Gate, S, WireId, ark,
    circuit::{
        CiphertextHandler, CircuitContext, EncodeInput, EvaluateMode, FALSE_WIRE, TRUE_WIRE,
        ciphertext_source, modes::CircuitMode,
    },
    gadgets::bn254::fq6::Fq6,
    hashers::GateHasher,
};

// Garbler-side input: single boolean wire, just allocate a fresh garbled label
#[derive(Clone)]
struct OneBitGarblerInput;

impl CircuitInput for OneBitGarblerInput {
    type WireRepr = crate::WireId;

    fn allocate(&self, mut issue: impl FnMut() -> crate::WireId) -> Self::WireRepr {
        (issue)()
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
        vec![*repr]
    }
}

impl<H: GateHasher, CTH> EncodeInput<GarbleMode<H, CTH>> for OneBitGarblerInput
where
    CTH: CiphertextHandler,
{
    fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleMode<H, CTH>) {
        let gw = cache.issue_garbled_wire();
        cache.feed_wire(*repr, gw);
    }
}

// Evaluator-side input: single boolean with its garbled label
#[derive(Clone)]
struct OneBitEvaluatorInput {
    bit: bool,
    label: GarbledWire,
}

impl CircuitInput for OneBitEvaluatorInput {
    type WireRepr = WireId;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (issue)()
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![*repr]
    }
}

impl<H: GateHasher, SRC: ciphertext_source::CiphertextSource> EncodeInput<EvaluateMode<H, SRC>>
    for OneBitEvaluatorInput
{
    fn encode(&self, repr: &Self::WireRepr, cache: &mut EvaluateMode<H, SRC>) {
        let ew = EvaluatedWire::new_from_garbled(&self.label, self.bit);
        cache.feed_wire(*repr, ew);
    }
}

// Very small circuit: out = (in AND true) OR false; this is logically identity
fn one_bit_circuit<C: CircuitContext>(ctx: &mut C, input: &WireId) -> WireId {
    let t = *input;
    let tmp = ctx.issue_wire();
    ctx.add_gate(Gate::and(t, TRUE_WIRE, tmp));
    let out = ctx.issue_wire();
    ctx.add_gate(Gate::or(tmp, FALSE_WIRE, out));
    out
}

/// End-to-end cut-and-choose over a 1-bit identity circuit.
///
/// Flow overview:
/// - Garbler: creates `total` independent instances by streaming-garbling the circuit,
///   derives commits for ciphertext hash, input labels, output labels (0/1), and constants.
/// - Evaluator: samples `finalize` indices, constructs per-index ciphertext channels
///   (receiver on Evaluator, sender provided to Garbler), and sends the selection to Garbler.
/// - Open/Close: Garbler returns seeds for opened instances and spawns regarble-to-evaluation
///   threads for closed (finalized) instances which stream ciphertexts to files.
/// - Regarbling check: Evaluator re-garbles each opened instance from its seed and checks that
///   the derived commit matches the Garbler’s commit (soundness against selective cheating).
/// - Evaluation: Using constants (true/false wire values) plus the Evaluator’s semantic inputs
///   encoded against the provided input labels, Evaluator runs streaming evaluation from the
///   saved ciphertext files and obtains the output bit and active label. We verify that the
///   active output label’s commit equals the appropriate committed output label (0 or 1).
#[test_log::test]
fn cut_and_choose_one_bit_e2e() {
    const CAPACITY: usize = 1000;
    // Deterministic RNG for reproducibility
    let mut rng = ChaCha20Rng::seed_from_u64(1234);

    let total = 5usize;
    let finalize = 2usize;

    // Garbler creates all instances
    let cfg_g = Config::new(total, finalize, OneBitGarblerInput);
    let mut garbler = Garbler::create(&mut rng, cfg_g, CAPACITY, one_bit_circuit);
    let commits = garbler.commit();

    // Evaluator chooses which instances to finalize
    let cfg_e = Config::new(total, finalize, OneBitGarblerInput);
    let evaluator: Evaluator<OneBitGarblerInput> =
        Evaluator::create(&mut rng, cfg_e, commits.clone());
    let finalize_indices: Vec<usize> = evaluator.finalized_indexes().to_vec();

    // Build channels for finalized instances using iterator + unzip
    let (senders, receivers): (Vec<_>, Vec<_>) = finalize_indices
        .iter()
        .map(|&index| {
            let (tx, rx) = channel::unbounded::<S>();
            ((index, tx), (index, rx))
        })
        .unzip();

    let open_info = garbler.open_commit(senders, one_bit_circuit);

    // Extract seeds for open instances
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

    // Run regarbling checks and persist ciphertexts
    let out_dir = PathBuf::from("target/cut_and_choose_test_simple");
    let handler_provider =
        FileCiphertextHandlerProvider::new(out_dir.clone(), None).expect("create sink provider");
    evaluator
        .run_regarbling(
            seeds,
            &receivers,
            &handler_provider,
            CAPACITY,
            one_bit_circuit,
        )
        .expect("regarbling ok");

    for j in join_handles {
        j.join().unwrap();
    }

    // Gather constants + input labels for finalized instances
    let mut cases_true = Vec::new();
    let mut cases_false = Vec::new();

    for idx in finalize_indices {
        let t = garbler.true_wire_constant_for(idx);
        let f = garbler.false_wire_constant_for(idx);

        let labels = garbler.input_labels_for(idx);

        assert_eq!(labels.len(), 1);

        // Build both true and false evaluator inputs
        let e_true = OneBitEvaluatorInput {
            bit: true,
            label: labels[0].clone(),
        };
        let e_false = OneBitEvaluatorInput {
            bit: false,
            label: labels[0].clone(),
        };

        cases_true.push(EvaluatorCaseInput {
            index: idx,
            input: e_true,
            true_constant_wire: t,
            false_constant_wire: f,
        });

        cases_false.push(EvaluatorCaseInput {
            index: idx,
            input: e_false,
            true_constant_wire: t,
            false_constant_wire: f,
        });
    }

    let results_true = evaluator
        .evaluate_from(&out_dir, cases_true, CAPACITY, one_bit_circuit)
        .expect("consistency checks should pass for true inputs");

    for (_idx, out) in results_true {
        assert!(out.value, "output should equal input (true)");
    }

    let results_false = evaluator
        .evaluate_from(&out_dir, cases_false, CAPACITY, one_bit_circuit)
        .expect("consistency checks should pass for false inputs");

    for (_idx, out) in results_false {
        assert!(!out.value, "output should equal input (false)");
        // Output label consistency is already checked in evaluate_from_saved_all_with_consistency
    }
}

// Fq12 multiplication-based cut-and-choose with equality-to-constant output.
// Uses two Fq12 inputs (a, b), multiplies them in-circuit, compares against
// precomputed constant a*b (Montgomery). Evaluates both true and false cases.
/// End-to-end cut-and-choose over Fq12 multiplication in Montgomery form.
///
/// Flow overview:
/// - Circuit: computes `prod = Fq12::mul_montgomery(a, b)` and then a boolean `ok` by
///   checking `prod == prod_m`, where `prod_m` is a precomputed constant of `as_montgomery(a*b)`.
/// - Garbling: the Garbler deterministically allocates labels for all input wires of `(a,b)`
///   and builds commits. It also prepares constants for true/false wires.
/// - Selection: the Evaluator chooses indices to finalize, builds channels for ciphertexts
///   of these instances, and sends them to the Garbler.
/// - Open/Close: Garbler returns seeds for opened instances; for finalized instances it spawns
///   a streaming garble->evaluation thread that writes ciphertexts to `gc_{idx}.bin`.
/// - Regarbling check: Evaluator re-garbles opened instances from seeds and verifies commits.
/// - Evaluation: For each finalized instance, Evaluator constructs its inputs by pairing the
///   Garbler’s input labels with semantic bits (flattened as `a.c0 || a.c1 || b.c0 || b.c1`)
///   to yield `EvaluatedWire`s, then runs streaming evaluation from the saved ciphertext file,
///   producing `ok` and the active output label. We assert both value and output-label commit:
///   - True case: `(a, b)` against `prod_m` → `ok = true` and commit equals committed label1.
///   - False case: `(a, b_alt)` vs `prod_m` → `ok = false` and commit equals committed label0.
///
/// The test keeps `total=1` and `to_finalize=1` to minimize runtime while exercising the full flow.
#[test_log::test]
fn cut_and_choose_fq12_mul_e2e() {
    const CAPACITY: usize = 16_000;
    use crate::{circuit::WiresObject, gadgets::bn254::fq12::Fq12 as Fq12Wire};

    // Evaluator-side input: bit values for (a, b) + corresponding garbled labels
    #[derive(Clone, Default)]
    struct Fq12MulInput {
        a_m: ark_bn254::Fq12,
        b_m: ark_bn254::Fq12,
        prod_m: ark_bn254::Fq12,
        labels: Vec<GarbledWire>,
    }

    #[derive(Clone)]
    struct Fq12MulWires {
        a: Fq12Wire,
        b: Fq12Wire,
        prod_m: ark_bn254::Fq12,
    }

    impl CircuitInput for Fq12MulInput {
        type WireRepr = Fq12MulWires;

        fn allocate(&self, mut issue: impl FnMut() -> crate::WireId) -> Self::WireRepr {
            Fq12MulWires {
                a: Fq12Wire::new(&mut issue),
                b: Fq12Wire::new(issue),
                prod_m: self.prod_m,
            }
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
            let mut v = repr.a.to_wires_vec();
            v.extend(repr.b.to_wires_vec());
            v
        }
    }

    impl<H: GateHasher, CTH> EncodeInput<GarbleMode<H, CTH>> for Fq12MulInput
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
        for Fq12MulInput
    {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut EvaluateMode<H, SRC>) {
            // Flatten Fq12 bits in allocation order: a.c0 || a.c1 || b.c0 || b.c1
            let mut bits: Vec<bool> = Vec::with_capacity(Fq12Wire::N_BITS * 2);
            let (a_c0_bits, a_c1_bits) = Fq12Wire::to_bits(self.a_m);
            for (v0, v1) in a_c0_bits.into_iter() {
                bits.extend(v0);
                bits.extend(v1);
            }
            for (v0, v1) in a_c1_bits.into_iter() {
                bits.extend(v0);
                bits.extend(v1);
            }
            let (b_c0_bits, b_c1_bits) = Fq12Wire::to_bits(self.b_m);
            for (v0, v1) in b_c0_bits.into_iter() {
                bits.extend(v0);
                bits.extend(v1);
            }
            for (v0, v1) in b_c1_bits.into_iter() {
                bits.extend(v0);
                bits.extend(v1);
            }

            assert_eq!(bits.len(), self.labels.len());

            for ((wire_id, bit), gw) in repr
                .a
                .to_wires_vec()
                .into_iter()
                .chain(repr.b.to_wires_vec().into_iter())
                .zip(bits.into_iter())
                .zip(self.labels.iter())
            {
                let ew = EvaluatedWire::new_from_garbled(gw, bit);
                cache.feed_wire(wire_id, ew);
            }
        }
    }

    // Circuit builder: multiply (a, b) then check equality to prod_m.
    // Provide three typed closures for the different modes we use.
    fn build_fq12_mul_eq_const<C: CircuitContext>(ctx: &mut C, inputs: &Fq12MulWires) -> WireId {
        let prod = Fq12Wire::mul_montgomery(ctx, &inputs.a, &inputs.b);
        Fq12Wire::equal_constant(ctx, &prod, &inputs.prod_m)
    }

    // Deterministic inputs
    let mut rng = ChaCha20Rng::seed_from_u64(42);

    let a12_std = ark::Fq12::new(Fq6::random(&mut rng), Fq6::random(&mut rng));
    let b12_std = ark::Fq12::new(Fq6::random(&mut rng), Fq6::random(&mut rng));

    let a_m = Fq12Wire::as_montgomery(a12_std);
    let b_m = Fq12Wire::as_montgomery(b12_std);

    let input = Fq12MulInput {
        a_m,
        b_m,
        prod_m: Fq12Wire::as_montgomery(a12_std * b12_std),
        labels: vec![],
    };

    let total = 5usize;
    let finalize = 2usize;

    // Garbler flow
    let cfg_g = Config::new(total, finalize, input.clone());
    let mut garbler = Garbler::create(&mut rng, cfg_g, CAPACITY, build_fq12_mul_eq_const);
    let commits = garbler.commit();

    // Evaluator chooses to finalize instances
    let cfg_e = Config::new(total, finalize, input.clone());
    let evaluator: Evaluator<Fq12MulInput> = Evaluator::create(&mut rng, cfg_e, commits.clone());
    let to_finalize = evaluator.finalized_indexes().to_vec().into_boxed_slice();

    // Prepare channels for finalized instances using iterator + unzip
    let (senders, receivers): (Vec<_>, Vec<_>) = to_finalize
        .iter()
        .map(|&index| {
            let (tx, rx) = channel::unbounded::<S>();
            ((index, tx), (index, rx))
        })
        .unzip();

    let open_info = garbler.open_commit(senders, build_fq12_mul_eq_const);

    // Seeds + join handles
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

    let out_dir = PathBuf::from("target/cut_and_choose_test_fq12_mul");

    // TODO Change to in-memory HandlerProvider
    let sink_provider =
        FileCiphertextHandlerProvider::new(out_dir.clone(), None).expect("create sink provider");

    evaluator
        .run_regarbling(
            seeds,
            &receivers,
            &sink_provider,
            CAPACITY,
            build_fq12_mul_eq_const,
        )
        .expect("regarbling ok");

    for j in join_handles {
        j.join().unwrap();
    }

    // Build true cases (a,b)
    let mut cases_true = Vec::new();

    for idx in to_finalize.iter().copied() {
        let t = garbler.true_wire_constant_for(idx);
        let f = garbler.false_wire_constant_for(idx);

        let labels = garbler.input_labels_for(idx);

        cases_true.push(EvaluatorCaseInput {
            index: idx,
            input: Fq12MulInput {
                labels: labels.clone(),
                ..input
            },
            true_constant_wire: t,
            false_constant_wire: f,
        });
    }

    // Evaluate true cases
    let results_true = evaluator
        .evaluate_from(&out_dir, cases_true, CAPACITY, build_fq12_mul_eq_const)
        .unwrap();

    for (idx, out) in results_true {
        assert!(out.value, "a*b == prod_m should be true");
        assert_eq!(
            super::commit_label(out.active_label),
            commits[idx].output_label1_commit()
        );
    }

    let b_alt_m = Fq12Wire::as_montgomery(ark_bn254::Fq12::new(
        Fq6::random(&mut rng),
        Fq6::random(&mut rng),
    ));

    let mut cases_false = Vec::new();

    for idx in to_finalize.iter().copied() {
        cases_false.push(EvaluatorCaseInput {
            index: idx,
            input: Fq12MulInput {
                a_m: input.a_m,
                b_m: b_alt_m,
                prod_m: input.prod_m,
                labels: garbler.input_labels_for(idx),
            },
            true_constant_wire: garbler.true_wire_constant_for(idx),
            false_constant_wire: garbler.false_wire_constant_for(idx),
        });
    }

    let results_false = evaluator
        .evaluate_from(&out_dir, cases_false, CAPACITY, build_fq12_mul_eq_const)
        .unwrap();

    for (idx, out) in results_false {
        assert!(!out.value, "a*b_alt == prod_m should be false");
        assert_eq!(
            super::commit_label(out.active_label),
            commits[idx].output_label0_commit()
        );
    }
}
