use crate_lib::{
    CircuitContext, Delta, EvaluatedWire, FqWire, GarbledWire, Gate, GateType, S, WireId,
    circuit::streaming::{
        CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, StreamingResult, WiresObject,
        modes::{EvaluateModeBlake3 as EvaluateMode, GarbleModeBlake3 as GarbleMode},
    },
};
use crossbeam::channel;
use garbled_snark_verifier as crate_lib;
use itertools::Itertools;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use test_log::test;

// =====================
// Moved evaluator tests
// =====================

#[derive(Debug)]
struct TestEvalInputs {
    a: EvaluatedWire,
    b: EvaluatedWire,
}

#[derive(Clone, Debug)]
struct TestGarbleInputs {
    a: GarbledWire,
    b: GarbledWire,
}

#[derive(Debug, Clone)]
struct TestInputsWire {
    a: WireId,
    b: WireId,
}

impl CircuitInput for TestEvalInputs {
    type WireRepr = TestInputsWire;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        TestInputsWire {
            a: issue(),
            b: issue(),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![repr.a, repr.b]
    }
}

impl CircuitInput for TestGarbleInputs {
    type WireRepr = TestInputsWire;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        TestInputsWire {
            a: issue(),
            b: issue(),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![repr.a, repr.b]
    }
}

impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for TestEvalInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        cache.feed_wire(repr.a, self.a.clone());
        cache.feed_wire(repr.b, self.b.clone());
    }
}

impl<M: CircuitMode<WireValue = GarbledWire>> EncodeInput<M> for TestGarbleInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        cache.feed_wire(repr.a, self.a.clone());
        cache.feed_wire(repr.b, self.b.clone());
    }
}

// E2E integration tests begin here

#[test]
fn test_garble_evaluate_and_consistency() {
    fn circuit_fn(ctx: &mut impl CircuitContext, inputs_wire: &TestInputsWire) -> Vec<WireId> {
        let and_result = ctx.issue_wire();
        ctx.add_gate(Gate::and(inputs_wire.a, inputs_wire.b, and_result));
        vec![and_result]
    }

    let seed: u64 = 0;
    for (a, b) in [true, false].iter().cartesian_product([true, false].iter()) {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        let delta = Delta::generate(&mut rng);
        let garble_inputs = TestGarbleInputs {
            a: GarbledWire::random(&mut rng, &delta),
            b: GarbledWire::random(&mut rng, &delta),
        };
        let eval_inputs = TestEvalInputs {
            a: EvaluatedWire::new_from_garbled(&garble_inputs.a, *a),
            b: EvaluatedWire::new_from_garbled(&garble_inputs.b, *b),
        };
        let (sender, receiver) = channel::unbounded();

        let garble_result: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(garble_inputs, 10, seed, sender, circuit_fn);

        let evaluate_result: StreamingResult<_, _, Vec<EvaluatedWire>> =
            CircuitBuilder::<EvaluateMode>::streaming_evaluation(
                eval_inputs,
                10,
                garble_result.true_constant.select(true).to_u128(),
                garble_result.false_constant.select(false).to_u128(),
                receiver,
                circuit_fn,
            );

        let [eval_and_output, ..] = evaluate_result.output_wires.as_slice() else {
            unreachable!()
        };
        let [garble_and_output, ..] = garble_result.output_wires.as_slice() else {
            unreachable!()
        };

        assert_eq!(
            eval_and_output.active_label,
            garble_and_output.select(a & b),
            "Expected: {:?} or {:?}, Got: {:?}",
            garble_and_output.label0,
            garble_and_output.label1,
            eval_and_output.active_label
        );
    }
}

macro_rules! test_gate_consistency {
    ($gate_type:expr, $test_name:ident) => {
        #[test]
        fn $test_name() {
            fn circuit_fn(
                ctx: &mut impl CircuitContext,
                inputs_wire: &TestInputsWire,
            ) -> Vec<WireId> {
                let gate_result = ctx.issue_wire();
                ctx.add_gate(Gate::new(
                    $gate_type,
                    inputs_wire.a,
                    inputs_wire.b,
                    gate_result,
                ));
                vec![gate_result]
            }

            let seed: u64 = 0;
            for (a, b) in [true, false].iter().cartesian_product([true, false].iter()) {
                let mut rng = ChaChaRng::seed_from_u64(seed);
                let delta = Delta::generate(&mut rng);
                let garble_inputs = TestGarbleInputs {
                    a: GarbledWire::random(&mut rng, &delta),
                    b: GarbledWire::random(&mut rng, &delta),
                };
                let eval_inputs = TestEvalInputs {
                    a: EvaluatedWire::new_from_garbled(&garble_inputs.a, *a),
                    b: EvaluatedWire::new_from_garbled(&garble_inputs.b, *b),
                };

                let (sender, receiver) = channel::unbounded();
                let garble_result: StreamingResult<_, _, Vec<GarbledWire>> =
                    CircuitBuilder::streaming_garbling_blake3(
                        garble_inputs,
                        10,
                        seed,
                        sender,
                        circuit_fn,
                    );

                let evaluate_result: StreamingResult<_, _, Vec<EvaluatedWire>> =
                    CircuitBuilder::<EvaluateMode>::streaming_evaluation(
                        eval_inputs,
                        10,
                        garble_result.true_constant.select(true).to_u128(),
                        garble_result.false_constant.select(false).to_u128(),
                        receiver,
                        circuit_fn,
                    );

                let [eval_gate_output, ..] = evaluate_result.output_wires.as_slice() else {
                    unreachable!()
                };
                let [garble_gate_output, ..] = garble_result.output_wires.as_slice() else {
                    unreachable!()
                };

                assert_eq!(
                    eval_gate_output.active_label,
                    garble_gate_output.select($gate_type.f()(*a, *b)),
                    "Gate type: {:?}, Expected: {:?} or {:?}, Got: {:?}",
                    $gate_type,
                    garble_gate_output.label0,
                    garble_gate_output.label1,
                    eval_gate_output.active_label
                );
            }
        }
    };
}

test_gate_consistency!(GateType::And, test_and_garble_evaluate_consistency);
test_gate_consistency!(GateType::Nand, test_nand_garble_evaluate_consistency);
test_gate_consistency!(GateType::Nimp, test_nimp_garble_evaluate_consistency);
test_gate_consistency!(GateType::Imp, test_imp_garble_evaluate_consistency);
test_gate_consistency!(GateType::Ncimp, test_ncimp_garble_evaluate_consistency);
test_gate_consistency!(GateType::Cimp, test_cimp_garble_evaluate_consistency);
test_gate_consistency!(GateType::Nor, test_nor_garble_evaluate_consistency);
test_gate_consistency!(GateType::Or, test_or_garble_evaluate_consistency);
test_gate_consistency!(GateType::Xor, test_xor_garble_evaluate_consistency);
test_gate_consistency!(GateType::Xnor, test_xnor_garble_evaluate_consistency);

#[derive(Debug)]
struct TestNotEvalInputs {
    a: EvaluatedWire,
}

#[derive(Clone, Debug)]
struct TestNotGarbleInputs {
    a: GarbledWire,
}

#[derive(Debug, Clone)]
struct TestNotInputsWire {
    a: WireId,
}

impl CircuitInput for TestNotEvalInputs {
    type WireRepr = TestNotInputsWire;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        TestNotInputsWire { a: issue() }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![repr.a]
    }
}

impl CircuitInput for TestNotGarbleInputs {
    type WireRepr = TestNotInputsWire;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        TestNotInputsWire { a: issue() }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![repr.a]
    }
}

impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for TestNotEvalInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        cache.feed_wire(repr.a, self.a.clone());
    }
}

impl<M: CircuitMode<WireValue = GarbledWire>> EncodeInput<M> for TestNotGarbleInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        cache.feed_wire(repr.a, self.a.clone());
    }
}

#[test]
fn test_not_garble_evaluate_consistency() {
    fn circuit_fn(ctx: &mut impl CircuitContext, inputs_wire: &TestNotInputsWire) -> Vec<WireId> {
        ctx.add_gate(Gate::new(
            GateType::Not,
            inputs_wire.a,
            inputs_wire.a,
            inputs_wire.a,
        ));
        vec![inputs_wire.a]
    }

    let seed: u64 = 0;
    for a in [true, false] {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        let delta = Delta::generate(&mut rng);
        let garble_inputs = TestNotGarbleInputs {
            a: GarbledWire::random(&mut rng, &delta),
        };
        let eval_inputs = TestNotEvalInputs {
            a: EvaluatedWire::new_from_garbled(&garble_inputs.a, a),
        };

        let (sender, receiver) = channel::unbounded();
        let garble_result: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(garble_inputs, 10, seed, sender, circuit_fn);

        let evaluate_result: StreamingResult<_, _, Vec<EvaluatedWire>> =
            CircuitBuilder::<EvaluateMode>::streaming_evaluation(
                eval_inputs,
                10,
                garble_result.true_constant.select(true).to_u128(),
                garble_result.false_constant.select(false).to_u128(),
                receiver,
                circuit_fn,
            );

        let [eval_not_output, ..] = evaluate_result.output_wires.as_slice() else {
            unreachable!()
        };
        let [garble_not_output, ..] = garble_result.output_wires.as_slice() else {
            unreachable!()
        };

        assert_eq!(
            eval_not_output.active_label,
            garble_not_output.select(GateType::Not.f()(a, false)),
            "Gate type: NOT, Expected: {:?} or {:?}, Got: {:?}",
            garble_not_output.label0,
            garble_not_output.label1,
            eval_not_output.active_label
        );
    }
}

// ======================================================
// Additional complex circuit test using BN254 Fq gadget
// ======================================================

#[derive(Debug, Clone)]
struct FqPairInputs {
    a: ark_bn254::Fq,
    b: ark_bn254::Fq,
}

#[derive(Debug, Clone)]
struct FqPairWires {
    a: FqWire,
    b: FqWire,
}

impl FqPairInputs {
    fn new(a: ark_bn254::Fq, b: ark_bn254::Fq) -> Self {
        Self { a, b }
    }
}

impl CircuitInput for FqPairInputs {
    type WireRepr = FqPairWires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        FqPairWires {
            a: FqWire::new(&mut issue),
            b: FqWire::new(issue),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = repr.a.to_wires_vec();
        ids.extend(repr.b.to_wires_vec());
        ids
    }
}

impl EncodeInput<GarbleMode> for FqPairInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleMode) {
        let mut rng = ChaChaRng::seed_from_u64(777);
        let delta = Delta::generate(&mut rng);
        for w in repr.a.0.iter().chain(repr.b.0.iter()) {
            cache.feed_wire(*w, GarbledWire::random(&mut rng, &delta));
        }
    }
}

impl EncodeInput<EvaluateMode> for FqPairInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut EvaluateMode) {
        let mut rng = ChaChaRng::seed_from_u64(777);
        let delta = Delta::generate(&mut rng);

        let a_bits = FqWire::to_bits(FqWire::as_montgomery(self.a));
        let b_bits = FqWire::to_bits(FqWire::as_montgomery(self.b));

        for (w, bit) in repr.a.0.iter().zip(a_bits.iter().copied()) {
            cache.feed_wire(
                *w,
                EvaluatedWire::new_from_garbled(&GarbledWire::random(&mut rng, &delta), bit),
            );
        }
        for (w, bit) in repr.b.0.iter().zip(b_bits.iter().copied()) {
            cache.feed_wire(
                *w,
                EvaluatedWire::new_from_garbled(&GarbledWire::random(&mut rng, &delta), bit),
            );
        }
    }
}

fn fq_complex_circuit<C: CircuitContext>(ctx: &mut C, inputs: &FqPairWires) -> Vec<WireId> {
    // Compute ((a^2) * b) + a in Montgomery form
    let a2 = FqWire::square_montgomery(ctx, &inputs.a);
    let a2b = FqWire::mul_montgomery(ctx, &a2, &inputs.b);
    let res = FqWire::add(ctx, &a2b, &inputs.a);
    res.to_wires_vec()
}

#[test]
fn test_bn254_fq_complex_chain_garble_eval() {
    // a = 13, b = 7
    let a = ark_bn254::Fq::from(13u32);
    let b = ark_bn254::Fq::from(7u32);
    let expected = (a * a) * b + a;

    let inputs = FqPairInputs::new(a, b);

    // Garble to produce ciphertexts and obtain constants
    let (g_sender, g_receiver) = channel::unbounded();
    let garble_res: StreamingResult<GarbleMode, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling_blake3(
            inputs.clone(),
            100_000,
            99,
            g_sender,
            fq_complex_circuit,
        );
    let tables: Vec<(usize, S)> = g_receiver.try_iter().collect();

    // Forward ciphertexts to evaluator
    let (e_sender, e_receiver) = channel::unbounded();
    for (i, ct) in tables {
        let _ = e_sender.send((i, ct));
    }
    drop(e_sender);

    // Evaluate using constants from garbler
    let true_s = garble_res.true_constant.select(true);
    let false_s = garble_res.false_constant.select(false);

    let eval: StreamingResult<EvaluateMode, _, Vec<EvaluatedWire>> =
        CircuitBuilder::<EvaluateMode>::streaming_evaluation(
            inputs,
            100_000,
            true_s.to_u128(),
            false_s.to_u128(),
            e_receiver,
            fq_complex_circuit,
        );

    let bits_len = FqWire::to_bits(ark_bn254::Fq::from(0u32)).len();
    assert_eq!(eval.output_wires.len(), bits_len);
    let bits: Vec<bool> = eval.output_wires.iter().map(|w| w.value).collect();
    let actual = FqWire::from_montgomery(FqWire::from_bits(bits));
    assert_eq!(actual, expected);
}
