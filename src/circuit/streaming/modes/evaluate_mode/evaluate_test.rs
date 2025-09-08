use std::{iter, thread};

use crossbeam::channel;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

use crate::{
    Delta, EvaluatedWire, GarbledWire, Gate, GateType, S, WireId,
    circuit::streaming::{
        CircuitBuilder, CircuitContext, CircuitInput, CircuitMode, EncodeInput, EvaluateMode,
        TRUE_WIRE,
    },
    core::gate::garbling::Blake3Hasher,
};

#[derive(Debug)]
struct TestEvalInputs {
    a: EvaluatedWire,
    b: EvaluatedWire,
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

impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for TestEvalInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        cache.feed_wire(repr.a, self.a.clone());
        cache.feed_wire(repr.b, self.b.clone());
    }
}

fn prepare() -> (S, S, TestEvalInputs) {
    let mut rng = ChaChaRng::seed_from_u64(0);
    let delta = Delta::generate(&mut rng);

    let true_wire = GarbledWire::random(&mut rng, &delta);
    let false_wire = GarbledWire::random(&mut rng, &delta);

    let a = GarbledWire::random(&mut rng, &delta);
    let b = GarbledWire::random(&mut rng, &delta);

    let true_evaluated = EvaluatedWire::new_from_garbled(&true_wire, true);
    let false_evaluated = EvaluatedWire::new_from_garbled(&false_wire, false);

    let a_evaluated = EvaluatedWire::new_from_garbled(&a, rng.r#gen());
    let b_evaluated = EvaluatedWire::new_from_garbled(&b, rng.r#gen());

    let inputs = TestEvalInputs {
        a: a_evaluated,
        b: b_evaluated,
    };

    (
        true_evaluated.active_label,
        false_evaluated.active_label,
        inputs,
    )
}

#[test]
fn test_xor_evaluate_mode_basic() {
    let (_sender, receiver) = channel::unbounded();
    let (true_wire, false_wire, inputs) = prepare();

    let result: crate::circuit::streaming::StreamingResult<
        EvaluateMode<Blake3Hasher>,
        TestEvalInputs,
        Vec<EvaluatedWire>,
    > = CircuitBuilder::<EvaluateMode<Blake3Hasher>>::streaming_evaluation(
        inputs,
        5,
        true_wire.to_u128(),
        false_wire.to_u128(),
        receiver,
        |ctx, input_wires| {
            let output = ctx.issue_wire();
            ctx.add_gate(Gate::xor(input_wires.a, input_wires.b, output));
            vec![output]
        },
    );

    assert_eq!(result.output_wires.len(), 1);
    assert!(result.output_wires[0].value);
}

#[test]
fn test_xor_evaluate_mode_with_constants() {
    let (_sender, receiver) = channel::unbounded();
    let (true_wire, false_wire, inputs) = prepare();
    let a = inputs.a.value;
    let b = inputs.b.value;

    let result: crate::circuit::streaming::StreamingResult<
        EvaluateMode<Blake3Hasher>,
        TestEvalInputs,
        Vec<EvaluatedWire>,
    > = CircuitBuilder::<EvaluateMode<Blake3Hasher>>::streaming_evaluation(
        inputs,
        5,
        true_wire.to_u128(),
        false_wire.to_u128(),
        receiver,
        |ctx, input_wires| {
            let output1 = ctx.issue_wire();
            let output2 = ctx.issue_wire();
            ctx.add_gate(Gate::xor(input_wires.a, TRUE_WIRE, output1));
            ctx.add_gate(Gate::xor(output1, input_wires.b, output2));
            vec![output2]
        },
    );

    assert_eq!(result.output_wires[0].value, (a ^ true) ^ b);
}

#[test]
fn test_evaluate_mode() {
    const NON_FREE_GATE_COUNT: usize = 5;
    let (sender, receiver) = channel::unbounded();

    thread::spawn(move || {
        let mut rng = ChaChaRng::seed_from_u64(1);
        iter::repeat_with(move || S::random(&mut rng))
            .take(NON_FREE_GATE_COUNT)
            .enumerate()
            .for_each(|(i, ct)| sender.send((i, ct)).unwrap());
    });

    let (true_wire, false_wire, inputs) = prepare();
    let a = inputs.a.value;
    let b = inputs.b.value;

    let result: crate::circuit::streaming::StreamingResult<
        EvaluateMode<Blake3Hasher>,
        TestEvalInputs,
        Vec<EvaluatedWire>,
    > = CircuitBuilder::<EvaluateMode<Blake3Hasher>>::streaming_evaluation(
        inputs,
        10,
        true_wire.to_u128(),
        false_wire.to_u128(),
        receiver,
        |ctx, input_wires| {
            let val1 = ctx.issue_wire();
            ctx.add_gate(Gate::and(input_wires.a, input_wires.b, val1));

            let val2 = ctx.issue_wire();
            ctx.add_gate(Gate::nimp(val1, input_wires.a, val2));

            let val3 = ctx.issue_wire();
            ctx.add_gate(Gate::nor(val1, val2, val3));

            let val4 = ctx.issue_wire();
            ctx.add_gate(Gate::imp(val2, val3, val4));

            let val5 = ctx.issue_wire();
            ctx.add_gate(Gate::imp(input_wires.a, val3, val5));

            let val6 = ctx.issue_wire();
            ctx.add_gate(Gate::xor(val5, val4, val6));

            vec![val6]
        },
    );

    let val1 = GateType::And.f()(a, b);
    let val2 = GateType::Nimp.f()(val1, a);
    let val3 = GateType::Nor.f()(val1, val2);
    let val4 = GateType::Imp.f()(val2, val3);
    let val5 = GateType::Imp.f()(a, val3);
    let val6 = GateType::Xor.f()(val5, val4);

    assert_eq!(result.output_wires[0].value, val6);
}
