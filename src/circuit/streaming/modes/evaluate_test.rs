use crossbeam::channel;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use test_log::test;

use super::EvaluateMode;
use crate::{
    CircuitContext, Delta, EvaluatedWire, GarbledWire, Gate, WireId,
    circuit::streaming::{CircuitBuilder, CircuitInput, EncodeInput, TRUE_WIRE},
    core::gate::garbling::Blake3Hasher,
};

// Simple input structure for testing
#[derive(Debug)]
struct TestInputs {
    a: bool,
    b: bool,
}

#[derive(Debug, Clone)]
struct TestInputsWire {
    a: WireId,
    b: WireId,
}

impl CircuitInput for TestInputs {
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

impl EncodeInput<EvaluatedWire> for TestInputs {
    fn encode<M: crate::circuit::streaming::CircuitMode<WireValue = EvaluatedWire>>(
        &self,
        repr: &Self::WireRepr,
        cache: &mut M,
    ) {
        // For testing, we'll create dummy EvaluatedWire with random labels
        let mut rng = ChaChaRng::seed_from_u64(42);
        let delta = Delta::generate(&mut rng);

        let wire_a = GarbledWire::random(&mut rng, &delta);
        let wire_b = GarbledWire::random(&mut rng, &delta);

        cache.feed_wire(repr.a, EvaluatedWire::new_from_garbled(&wire_a, self.a));
        cache.feed_wire(repr.b, EvaluatedWire::new_from_garbled(&wire_b, self.b));
    }
}

#[test]
fn test_evaluate_mode_basic() {
    let mut rng = ChaChaRng::seed_from_u64(0);
    let delta = Delta::generate(&mut rng);

    // Create constant wires
    let true_wire = GarbledWire::random(&mut rng, &delta);
    let false_wire = GarbledWire::random(&mut rng, &delta);

    let true_evaluated = EvaluatedWire::new_from_garbled(&true_wire, true);
    let false_evaluated = EvaluatedWire::new_from_garbled(&false_wire, false);

    // Create a channel for ciphertexts (empty for this test since we use only free gates)
    let (_sender, receiver) = channel::unbounded();

    let inputs = TestInputs { a: true, b: false };

    let result: crate::circuit::streaming::StreamingResult<
        EvaluateMode<Blake3Hasher>,
        TestInputs,
        Vec<EvaluatedWire>,
    > = CircuitBuilder::<EvaluateMode<Blake3Hasher>>::streaming_evaluation(
        inputs,
        10_000,
        true_evaluated,
        false_evaluated,
        receiver,
        |ctx, input_wires| {
            // Simple XOR gate test - should be free
            let output = ctx.issue_wire();
            ctx.add_gate(Gate::xor(input_wires.a, input_wires.b, output));

            vec![output]
        },
    );

    // XOR of true and false should be true
    assert_eq!(result.output_wires.len(), 1);
    assert!(result.output_wires[0].value);

    println!("Test passed: XOR gate evaluation works correctly");
}

#[test]
fn test_evaluate_mode_with_constants() {
    let mut rng = ChaChaRng::seed_from_u64(1);
    let delta = Delta::generate(&mut rng);

    // Create constant wires
    let true_wire = GarbledWire::random(&mut rng, &delta);
    let false_wire = GarbledWire::random(&mut rng, &delta);

    let true_evaluated = EvaluatedWire::new_from_garbled(&true_wire, true);
    let false_evaluated = EvaluatedWire::new_from_garbled(&false_wire, false);

    // Create a channel for ciphertexts (empty for this test)
    let (_sender, receiver) = channel::unbounded();

    let inputs = TestInputs { a: true, b: true };

    let result: crate::circuit::streaming::StreamingResult<
        EvaluateMode<Blake3Hasher>,
        TestInputs,
        Vec<EvaluatedWire>,
    > = CircuitBuilder::<EvaluateMode<Blake3Hasher>>::streaming_evaluation(
        inputs,
        10_000,
        true_evaluated,
        false_evaluated,
        receiver,
        |ctx, input_wires| {
            // Test using constant wires
            let output1 = ctx.issue_wire();
            let output2 = ctx.issue_wire();

            ctx.add_gate(Gate::xor(input_wires.a, TRUE_WIRE, output1));
            ctx.add_gate(Gate::xor(output1, input_wires.b, output2));

            vec![output2]
        },
    );

    // (true XOR true) XOR true = false XOR true = true
    assert!(result.output_wires[0].value);

    println!("Test passed: Constant wire evaluation works correctly");
}
