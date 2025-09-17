//! Integration test demonstrating the connection between Garbling and Evaluation modes
//!
//! This test shows the complete workflow:
//! 1. Create a circuit using Garbling mode with specific inputs
//! 2. Collect the garbled tables and wire labels
//! 3. Use the same inputs to create EvaluatedWires for Evaluation mode
//! 4. Run the same circuit in Evaluation mode
//! 5. Verify the outputs match
//!
//! Includes both simple boolean circuits and complex BN254 field arithmetic

use ark_ff::PrimeField;
use crossbeam::channel;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use test_log::test;

use crate::{
    circuit::streaming::{
        modes::EvaluateModeBlake3, CircuitBuilder, CircuitContext, CircuitInput, CircuitMode,
        EncodeInput, StreamingResult, WiresObject,
    },
    gadgets::{
        bigint::{bits_from_biguint_with_len, BigUint as BigUintOutput},
        bn254::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2},
    },
    Delta, EvaluatedWire, GarbledWire, Gate, WireId, S,
};

// Define the types locally since they're not exported
type GarbledTableEntry = S;
type CiphertextEntry = S;

/// Test inputs that work for both garbling and evaluation
#[derive(Debug)]
struct TestCircuitInputs {
    a: bool,
    b: bool,
    c: bool,
    seed: Option<u64>, // Optional seed for wire generation consistency
}

impl TestCircuitInputs {
    fn new(a: bool, b: bool, c: bool) -> Self {
        Self {
            a,
            b,
            c,
            seed: None,
        }
    }

    fn with_seed(a: bool, b: bool, c: bool, seed: u64) -> Self {
        Self {
            a,
            b,
            c,
            seed: Some(seed),
        }
    }
}

#[derive(Debug, Clone)]
struct TestWireRepr {
    a: WireId,
    b: WireId,
    c: WireId,
}

impl CircuitInput for TestCircuitInputs {
    type WireRepr = TestWireRepr;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        TestWireRepr {
            a: issue(),
            b: issue(),
            c: issue(),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![repr.a, repr.b, repr.c]
    }
}

// Implementation for garbling mode
impl<M: CircuitMode<WireValue = GarbledWire>> EncodeInput<M> for TestCircuitInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        let wire_seed = self.seed.unwrap_or(42);

        // Generate garbled wires with correct semantics for the boolean values
        let mut rng = ChaChaRng::seed_from_u64(wire_seed);
        let delta = Delta::generate(&mut rng);

        let wire_a = GarbledWire::random(&mut rng, &delta);
        let wire_b = GarbledWire::random(&mut rng, &delta);
        let wire_c = GarbledWire::random(&mut rng, &delta);

        cache.feed_wire(repr.a, wire_a.clone());
        cache.feed_wire(repr.b, wire_b.clone());
        cache.feed_wire(repr.c, wire_c.clone());
    }
}

// Implementation for evaluation mode - CRITICAL: Uses same seed and wire generation as garbler
impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for TestCircuitInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        let wire_seed = self.seed.unwrap_or(42);
        println!("🔧 EVALUATOR INPUT ENCODING:");
        println!("  Input values: a={}, b={}, c={}", self.a, self.b, self.c);
        println!("  Using wire generation seed: {}", wire_seed);

        // Generate garbled wires with correct semantics for the boolean values
        let mut rng = ChaChaRng::seed_from_u64(wire_seed);
        let delta = Delta::generate(&mut rng);
        println!("  Delta: {:?}", delta);

        let wire_a = GarbledWire::random(&mut rng, &delta);
        let wire_b = GarbledWire::random(&mut rng, &delta);
        let wire_c = GarbledWire::random(&mut rng, &delta);

        println!(
            "  Generated wire_a: label0={:?}, label1={:?}",
            wire_a.label0, wire_a.label1
        );
        println!(
            "  Generated wire_b: label0={:?}, label1={:?}",
            wire_b.label0, wire_b.label1
        );
        println!(
            "  Generated wire_c: label0={:?}, label1={:?}",
            wire_c.label0, wire_c.label1
        );

        let eval_wire_a = EvaluatedWire::new_from_garbled(&wire_a, self.a);
        let eval_wire_b = EvaluatedWire::new_from_garbled(&wire_b, self.b);
        let eval_wire_c = EvaluatedWire::new_from_garbled(&wire_c, self.c);

        println!(
            "  EvaluatedWire a: active_label={:?}, value={}",
            eval_wire_a.active_label, eval_wire_a.value
        );
        println!(
            "  EvaluatedWire b: active_label={:?}, value={}",
            eval_wire_b.active_label, eval_wire_b.value
        );
        println!(
            "  EvaluatedWire c: active_label={:?}, value={}",
            eval_wire_c.active_label, eval_wire_c.value
        );

        cache.feed_wire(repr.a, eval_wire_a);
        cache.feed_wire(repr.b, eval_wire_b);
        cache.feed_wire(repr.c, eval_wire_c);
    }
}

/// Defines our test circuit: ((a AND b) XOR c)
fn test_circuit<C: crate::circuit::streaming::CircuitContext>(
    ctx: &mut C,
    inputs: &TestWireRepr,
) -> Vec<WireId> {
    // (a AND b)
    let and_result = ctx.issue_wire();
    ctx.add_gate(Gate::and(inputs.a, inputs.b, and_result));

    // (a AND b) XOR c
    let final_result = ctx.issue_wire();
    ctx.add_gate(Gate::xor(and_result, inputs.c, final_result));

    vec![final_result]
}

/// Expected result for our test circuit: ((a AND b) XOR c)
fn expected_result(a: bool, b: bool, c: bool) -> bool {
    (a && b) ^ c
}

#[test]
fn test_garble_evaluate_connection() {
    // Test case: a=true, b=false, c=true
    // Expected result: ((true AND false) XOR true) = (false XOR true) = true
    let test_inputs = TestCircuitInputs::new(true, false, true);
    let expected = expected_result(test_inputs.a, test_inputs.b, test_inputs.c);

    println!(
        "Testing circuit with inputs: a={}, b={}, c={}",
        test_inputs.a, test_inputs.b, test_inputs.c
    );
    println!("Expected result: {}", expected);

    // Step 1: Run circuit in Garbling mode
    println!("\n--- Step 1: Garbling ---");

    let (garbled_sender, garbled_receiver) = channel::unbounded();

    let garble_result: StreamingResult<_, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling_blake3(
            test_inputs,
            10_000,
            42, // seed
            garbled_sender,
            test_circuit,
        );

    // Collect all garbled table entries
    let garbled_tables: Vec<GarbledTableEntry> = garbled_receiver.try_iter().collect();

    println!("Garbling produced {} table entries", garbled_tables.len());
    println!("Output wire count: {}", garble_result.output_wires.len());

    // Step 2: Convert garbled tables to ciphertext entries for evaluation
    println!("\n--- Step 2: Preparing Evaluation ---");

    let (eval_sender, eval_receiver) = channel::unbounded();

    // Convert garbled tables to ciphertext entries
    // In a real scenario, these would come from the garbler
    for ciphertext in &garbled_tables {
        let ciphertext_entry: CiphertextEntry = *ciphertext;
        if eval_sender.send(ciphertext_entry).is_err() {
            break;
        }
    }
    drop(eval_sender); // Close the channel

    // Step 3: Run circuit in Evaluation mode
    println!("\n--- Step 3: Evaluation ---");

    // Use the same test inputs but for evaluation mode
    let test_inputs_eval = TestCircuitInputs::new(true, false, true);

    // Create constant wires for evaluation (these would come from the garbler)
    let mut rng = ChaChaRng::seed_from_u64(42);
    let delta = Delta::generate(&mut rng);

    let true_wire = GarbledWire::random(&mut rng, &delta);
    let false_wire = GarbledWire::random(&mut rng, &delta);

    let true_evaluated = EvaluatedWire::new_from_garbled(&true_wire, true);
    let false_evaluated = EvaluatedWire::new_from_garbled(&false_wire, false);

    let eval_result: StreamingResult<EvaluateModeBlake3, _, Vec<EvaluatedWire>> =
        CircuitBuilder::<EvaluateModeBlake3>::streaming_evaluation(
            test_inputs_eval,
            10_000,
            true_evaluated,
            false_evaluated,
            eval_receiver,
            test_circuit,
        );

    println!(
        "Evaluation output wire count: {}",
        eval_result.output_wires.len()
    );

    // Step 4: Verify results match
    println!("\n--- Step 4: Verification ---");

    assert_eq!(
        garble_result.output_wires.len(),
        eval_result.output_wires.len(),
        "Output wire counts should match"
    );

    // Check that evaluation result matches expected boolean result
    assert_eq!(
        eval_result.output_wires.len(),
        1,
        "Should have exactly one output"
    );
    let actual_result = eval_result.output_wires[0].value;

    // CRITICAL CONSISTENCY CHECK: Verify wire label consistency between garbler and evaluator
    let garbler_output = &garble_result.output_wires[0];
    let evaluator_output = &eval_result.output_wires[0];

    let labels_match = evaluator_output.active_label == garbler_output.label0
        || evaluator_output.active_label == garbler_output.label1;

    assert!(
        labels_match,
        "Wire label consistency failure: \
            Garbler labels: label0={:?}, label1={:?}, \
            Evaluator active: {:?} (value={}). \
            The evaluator's active label doesn't match either garbler label.",
        garbler_output.label0,
        garbler_output.label1,
        evaluator_output.active_label,
        evaluator_output.value
    );

    println!("Wire label consistency verified for garbler and evaluator");

    println!("Actual result from evaluation: {}", actual_result);
    assert_eq!(
        actual_result, expected,
        "Evaluation result should match expected boolean computation"
    );

    println!("\n✅ SUCCESS: Garbling and Evaluation connection works correctly!");
    println!(
        "   - Garbling mode produced {} ciphertext entries",
        garbled_tables.len()
    );
    println!(
        "   - Evaluation mode consumed those entries and computed correct result: {}",
        actual_result
    );
}

#[test]
fn test_multiple_input_combinations() {
    // Test all possible input combinations for our 3-input circuit
    let test_cases = [
        (false, false, false),
        (false, false, true),
        (false, true, false),
        (false, true, true),
        (true, false, false),
        (true, false, true),
        (true, true, false),
        (true, true, true),
    ];

    println!("Testing all {} input combinations...\n", test_cases.len());

    for (i, (a, b, c)) in test_cases.iter().enumerate() {
        println!(
            "\n==================== Test case {}: a={}, b={}, c={} ====================",
            i + 1,
            a,
            b,
            c
        );

        let expected = expected_result(*a, *b, *c);
        println!("Expected circuit result: {}", expected);

        // CRITICAL: Use the SAME seed for both garbler and evaluator input wire generation
        let wire_seed = 42u64; // Fixed seed for input wires
        let test_inputs = TestCircuitInputs::with_seed(*a, *b, *c, wire_seed);

        // Garbling
        println!("\n--- GARBLING PHASE ---");
        println!("Using garbling seed: {}", i as u64);

        let (garbled_sender, garbled_receiver) = channel::unbounded();
        let garble_result: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(
                test_inputs,
                10_000,
                i as u64, // Different seed for each test
                garbled_sender,
                test_circuit,
            );

        let garbled_tables: Vec<GarbledTableEntry> = garbled_receiver.try_iter().collect();
        println!("Garbling produced {} table entries", garbled_tables.len());
        println!(
            "Garbled output wire: label0={:?}, label1={:?}",
            garble_result.output_wires[0].label0, garble_result.output_wires[0].label1
        );

        // Evaluation setup
        println!("\n--- EVALUATION SETUP ---");
        let (eval_sender, eval_receiver) = channel::unbounded();
        for ciphertext in garbled_tables {
            let ciphertext_entry: CiphertextEntry = ciphertext;
            if eval_sender.send(ciphertext_entry).is_err() {
                break;
            }
        }
        drop(eval_sender);

        // Evaluation
        println!("\n--- EVALUATION PHASE ---");

        // CRITICAL: Use the actual constant wires from the garbler's StreamingResult
        let garbler_true_wire = garble_result.one_constant.clone();
        let garbler_false_wire = garble_result.zero_constant.clone();

        println!("Actual constant wires from garbler StreamingResult:");
        println!(
            "  true_wire (one_constant): label0={:?}, label1={:?}",
            garbler_true_wire.label0, garbler_true_wire.label1
        );
        println!(
            "  false_wire (zero_constant): label0={:?}, label1={:?}",
            garbler_false_wire.label0, garbler_false_wire.label1
        );

        let test_inputs_eval = TestCircuitInputs::with_seed(*a, *b, *c, wire_seed);

        let eval_result: StreamingResult<EvaluateModeBlake3, _, Vec<EvaluatedWire>> =
            CircuitBuilder::<EvaluateModeBlake3>::streaming_evaluation(
                test_inputs_eval,
                10_000,
                EvaluatedWire::new_from_garbled(&garbler_true_wire, true),
                EvaluatedWire::new_from_garbled(&garbler_false_wire, false),
                eval_receiver,
                test_circuit,
            );

        let actual_result = eval_result.output_wires[0].value;

        println!("\n--- RESULTS & CONSISTENCY CHECK ---");
        println!("Actual evaluation result: {}", actual_result);
        println!("Expected boolean result: {}", expected);

        // CRITICAL: Verify wire label consistency between garbler and evaluator
        let garbler_output = &garble_result.output_wires[0];
        let evaluator_output = &eval_result.output_wires[0];

        println!("Wire label comparison:");
        println!(
            "  Garbler output: label0={:?}, label1={:?}",
            garbler_output.label0, garbler_output.label1
        );
        println!(
            "  Evaluator output: active_label={:?}, value={}",
            evaluator_output.active_label, evaluator_output.value
        );

        let match_label0 = evaluator_output.active_label == garbler_output.label0;
        let match_label1 = evaluator_output.active_label == garbler_output.label1;
        println!("  Active matches label0: {}", match_label0);
        println!("  Active matches label1: {}", match_label1);

        let labels_match = match_label0 || match_label1;

        assert!(
            labels_match,
            "Wire label consistency failure in test case {}: \
                Inputs: a={}, b={}, c={} -> expected={}. \
                Garbler labels: label0={:?}, label1={:?}. \
                Evaluator active: {:?} (value={}). \
                Evaluator's active label doesn't match either garbler label.",
            i + 1,
            a,
            b,
            c,
            expected,
            garbler_output.label0,
            garbler_output.label1,
            evaluator_output.active_label,
            evaluator_output.value
        );

        println!(
            "   Expected: {}, Actual: {} [Wire labels consistent]",
            expected, actual_result
        );
        assert_eq!(
            actual_result,
            expected,
            "Test case {} failed: inputs=({}, {}, {})",
            i + 1,
            a,
            b,
            c
        );
    }

    println!("\nAll test combinations passed with wire label consistency verified");
}

#[test]
fn test_direct_garble_degarble_comparison() {
    // This test directly compares garble and degarble for the same gate with the same inputs
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use crate::{
        circuit::streaming::modes::garble_mode::halfgates_garbling,
        hashers::Blake3Hasher,
    };

    println!("=== DIRECT GARBLE/DEGARBLE COMPARISON ===");

    // Generate deterministic wires for AND gate
    let mut rng = ChaChaRng::seed_from_u64(12345);
    let delta = Delta::generate(&mut rng);

    let a_garbled = GarbledWire::random(&mut rng, &delta);
    let b_garbled = GarbledWire::random(&mut rng, &delta);

    println!("Input wires:");
    println!(
        "  a_garbled: label0={:?}, label1={:?}",
        a_garbled.label0, a_garbled.label1
    );
    println!(
        "  b_garbled: label0={:?}, label1={:?}",
        b_garbled.label0, b_garbled.label1
    );
    println!("  delta: {:?}", delta);

    // Test case: a=false, b=false -> expected = false
    let a_val = false;
    let b_val = false;
    let expected_result = a_val & b_val; // false

    // Create evaluated wires
    let a_eval = EvaluatedWire::new_from_garbled(&a_garbled, a_val);
    let b_eval = EvaluatedWire::new_from_garbled(&b_garbled, b_val);

    println!("Evaluated wires:");
    println!(
        "  a_eval: active_label={:?}, value={}",
        a_eval.active_label, a_eval.value
    );
    println!(
        "  b_eval: active_label={:?}, value={}",
        b_eval.active_label, b_eval.value
    );

    // Garble the AND gate
    let gate_id = 0;
    let gate_type = crate::GateType::And;
    let a0 = a_garbled.select(false);
    let b0 = b_garbled.select(false);
    let (ciphertext, c_garbled_label0) = {
        let (c0, ct) =
            halfgates_garbling::garble_gate::<Blake3Hasher>(gate_type, a0, b0, &delta, gate_id);
        (ct.expect("AND produces ciphertext"), c0)
    };
    let c_garbled = GarbledWire::new(c_garbled_label0, c_garbled_label0 ^ &delta);

    println!("Garbled gate result:");
    println!("  ciphertext: {:?}", ciphertext);
    println!(
        "  c_garbled: label0={:?}, label1={:?}",
        c_garbled.label0, c_garbled.label1
    );

    // Get expected output wire
    let expected_c_eval = EvaluatedWire::new_from_garbled(&c_garbled, expected_result);
    println!(
        "  expected active label: {:?}",
        expected_c_eval.active_label
    );

    // Degarble the same gate
    let degarbled_label = halfgates_garbling::degarble_gate::<Blake3Hasher>(
        gate_type,
        &ciphertext,
        a_eval.active_label,
        a_eval.value,
        b_eval.active_label,
        gate_id,
    );

    println!("Degarbled result:");
    println!("  degarbled_label: {:?}", degarbled_label);

    // Compare results
    let labels_match = degarbled_label == expected_c_eval.active_label;
    println!("Wire labels match: {}", labels_match);

    assert!(
        labels_match,
        "Direct garble/degarble test failed!\n\
            Expected: {:?}\n\
            Degarbled: {:?}",
        expected_c_eval.active_label, degarbled_label
    );
}

#[test]
fn test_free_xor_optimization() {
    // Test circuit with only XOR gates (should produce no garbled tables)
    let test_inputs = TestCircuitInputs::new(true, false, true);

    let (garbled_sender, garbled_receiver) = channel::unbounded();

    let _garble_result: StreamingResult<_, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling_blake3(
            test_inputs,
            10_000,
            42,
            garbled_sender,
            |ctx, inputs: &TestWireRepr| {
                // Only XOR gates - should all be free
                let xor1 = ctx.issue_wire();
                ctx.add_gate(Gate::xor(inputs.a, inputs.b, xor1));

                let xor2 = ctx.issue_wire();
                ctx.add_gate(Gate::xor(xor1, inputs.c, xor2));

                vec![xor2]
            },
        );

    let garbled_tables: Vec<GarbledTableEntry> = garbled_receiver.try_iter().collect();

    // XOR gates should use Free-XOR optimization (no tables needed)
    assert_eq!(
        garbled_tables.len(),
        0,
        "XOR-only circuit should produce no garbled tables (Free-XOR optimization)"
    );

    println!("✅ Free-XOR optimization verified: XOR gates produced no ciphertext entries");
}

//
// Complex BN254 Fq2 Field Arithmetic Tests
//

/// Test inputs for BN254 Fq2 field arithmetic
#[derive(Debug, Clone)]
struct Fq2TestInputs {
    a: ark_bn254::Fq2,
    b: ark_bn254::Fq2,
}

impl Fq2TestInputs {
    fn new(a: ark_bn254::Fq2, b: ark_bn254::Fq2) -> Self {
        Self { a, b }
    }
}

#[derive(Debug, Clone)]
struct Fq2WireRepr {
    a: Fq2,
    b: Fq2,
}

impl CircuitInput for Fq2TestInputs {
    type WireRepr = Fq2WireRepr;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Fq2WireRepr {
            a: Fq2::new(&mut issue),
            b: Fq2::new(issue),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = repr.a.to_wires_vec();
        ids.extend(repr.b.to_wires_vec());
        ids
    }
}

// Implementation for garbling mode - creates random garbled wires
impl EncodeInput<GarbledWire> for Fq2TestInputs {
    fn encode<M: CircuitMode<WireValue = GarbledWire>>(
        &self,
        repr: &Self::WireRepr,
        cache: &mut M,
    ) {
        let mut rng = ChaChaRng::seed_from_u64(12345);
        let delta = Delta::generate(&mut rng);

        // Convert to montgomery form for circuit computation
        let a_m = Fq2::as_montgomery(self.a);
        let b_m = Fq2::as_montgomery(self.b);

        // Encode a (Fq2)
        let a_c0_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(a_m.c0.into_bigint()), Fq::N_BITS)
                .unwrap();
        let a_c1_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(a_m.c1.into_bigint()), Fq::N_BITS)
                .unwrap();

        for (wire, _bit) in repr.a.0[0].0.iter().zip(a_c0_bits.iter()) {
            let garbled_wire = GarbledWire::random(&mut rng, &delta);
            cache.feed_wire(*wire, garbled_wire);
        }
        for (wire, _bit) in repr.a.0[1].0.iter().zip(a_c1_bits.iter()) {
            let garbled_wire = GarbledWire::random(&mut rng, &delta);
            cache.feed_wire(*wire, garbled_wire);
        }

        // Encode b (Fq2)
        let b_c0_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(b_m.c0.into_bigint()), Fq::N_BITS)
                .unwrap();
        let b_c1_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(b_m.c1.into_bigint()), Fq::N_BITS)
                .unwrap();

        for (wire, _bit) in repr.b.0[0].0.iter().zip(b_c0_bits.iter()) {
            let garbled_wire = GarbledWire::random(&mut rng, &delta);
            cache.feed_wire(*wire, garbled_wire);
        }
        for (wire, _bit) in repr.b.0[1].0.iter().zip(b_c1_bits.iter()) {
            let garbled_wire = GarbledWire::random(&mut rng, &delta);
            cache.feed_wire(*wire, garbled_wire);
        }
    }
}

// Implementation for evaluation mode
impl EncodeInput<EvaluatedWire> for Fq2TestInputs {
    fn encode<M: CircuitMode<WireValue = EvaluatedWire>>(
        &self,
        repr: &Self::WireRepr,
        cache: &mut M,
    ) {
        let mut rng = ChaChaRng::seed_from_u64(12345);
        let delta = Delta::generate(&mut rng);

        // Convert to montgomery form for circuit computation
        let a_m = Fq2::as_montgomery(self.a);
        let b_m = Fq2::as_montgomery(self.b);

        // Encode a (Fq2)
        let a_c0_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(a_m.c0.into_bigint()), Fq::N_BITS)
                .unwrap();
        let a_c1_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(a_m.c1.into_bigint()), Fq::N_BITS)
                .unwrap();

        for (wire, bit) in repr.a.0[0].0.iter().zip(a_c0_bits.iter()) {
            let garbled_wire = GarbledWire::random(&mut rng, &delta);
            cache.feed_wire(*wire, EvaluatedWire::new_from_garbled(&garbled_wire, *bit));
        }
        for (wire, bit) in repr.a.0[1].0.iter().zip(a_c1_bits.iter()) {
            let garbled_wire = GarbledWire::random(&mut rng, &delta);
            cache.feed_wire(*wire, EvaluatedWire::new_from_garbled(&garbled_wire, *bit));
        }

        // Encode b (Fq2)
        let b_c0_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(b_m.c0.into_bigint()), Fq::N_BITS)
                .unwrap();
        let b_c1_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(b_m.c1.into_bigint()), Fq::N_BITS)
                .unwrap();

        for (wire, bit) in repr.b.0[0].0.iter().zip(b_c0_bits.iter()) {
            let garbled_wire = GarbledWire::random(&mut rng, &delta);
            cache.feed_wire(*wire, EvaluatedWire::new_from_garbled(&garbled_wire, *bit));
        }
        for (wire, bit) in repr.b.0[1].0.iter().zip(b_c1_bits.iter()) {
            let garbled_wire = GarbledWire::random(&mut rng, &delta);
            cache.feed_wire(*wire, EvaluatedWire::new_from_garbled(&garbled_wire, *bit));
        }
    }
}

/// Complex BN254 Fq2 multiplication circuit: (a * b) + (a^2)
fn fq2_complex_circuit<C: CircuitContext>(ctx: &mut C, inputs: &Fq2WireRepr) -> Vec<WireId> {
    println!("Building complex Fq2 circuit: (a * b) + (a^2)");

    // Compute a * b
    let a_mul_b = Fq2::mul_montgomery(ctx, &inputs.a, &inputs.b);
    println!("Computed a * b");

    // Compute a^2
    let a_squared = Fq2::square_montgomery(ctx, &inputs.a);
    println!("Computed a^2");

    // Compute final result: (a * b) + (a^2)
    let result = Fq2::add(ctx, &a_mul_b, &a_squared);
    println!("Computed final result: (a * b) + (a^2)");

    // Return all wires from the result
    result.to_wires_vec()
}

#[test]
fn test_complex_fq2_garble_evaluate_integration() {
    // Test with specific BN254 Fq2 values
    let a = ark_bn254::Fq2::from(13u32); // Simple test values
    let b = ark_bn254::Fq2::from(7u32);

    // Expected result: (a * b) + (a^2) = (13 * 7) + (13^2) = 91 + 169 = 260
    let expected = (a * b) + (a * a);

    println!("Testing complex Fq2 circuit with:");
    println!("  a = {}", a);
    println!("  b = {}", b);
    println!("  expected = (a * b) + (a^2) = {}", expected);

    let test_inputs = Fq2TestInputs::new(a, b);

    // Step 1: Run circuit in Garbling mode
    println!("\n--- Step 1: Garbling Complex Fq2 Circuit ---");

    let (garbled_sender, garbled_receiver) = channel::unbounded();

    let garble_result: StreamingResult<_, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling_blake3(
            test_inputs.clone(),
            100_000, // Increased capacity for complex operations
            42,
            garbled_sender,
            fq2_complex_circuit,
        );

    let garbled_tables: Vec<GarbledTableEntry> = garbled_receiver.try_iter().collect();

    println!("Garbling produced {} table entries", garbled_tables.len());
    println!("Output wire count: {}", garble_result.output_wires.len());

    // Step 2: Convert garbled tables to ciphertext entries for evaluation
    println!("\n--- Step 2: Preparing Evaluation ---");

    let (eval_sender, eval_receiver) = channel::unbounded();

    for (gate_id, ciphertext) in &garbled_tables {
        let ciphertext_entry: CiphertextEntry = (*gate_id, *ciphertext);
        if eval_sender.send(ciphertext_entry).is_err() {
            break;
        }
    }
    drop(eval_sender);

    // Step 3: Run circuit in Evaluation mode
    println!("\n--- Step 3: Evaluation ---");

    let mut rng = ChaChaRng::seed_from_u64(42);
    let delta = Delta::generate(&mut rng);
    let true_wire = GarbledWire::random(&mut rng, &delta);
    let false_wire = GarbledWire::random(&mut rng, &delta);

    let eval_result: StreamingResult<EvaluateModeBlake3, _, Vec<EvaluatedWire>> =
        CircuitBuilder::<EvaluateModeBlake3>::streaming_evaluation(
            test_inputs,
            100_000,
            EvaluatedWire::new_from_garbled(&true_wire, true),
            EvaluatedWire::new_from_garbled(&false_wire, false),
            eval_receiver,
            fq2_complex_circuit,
        );

    println!(
        "Evaluation output wire count: {}",
        eval_result.output_wires.len()
    );

    // Step 4: Verify results by extracting the field element
    println!("\n--- Step 4: Verification ---");

    // Extract the boolean values from the evaluated wires and reconstruct the Fq2 element
    assert_eq!(eval_result.output_wires.len(), 508); // 2 * 254 bits for Fq2

    let mut c0_bits = Vec::new();
    let mut c1_bits = Vec::new();

    // First 254 bits are c0, next 254 bits are c1
    for i in 0..254 {
        c0_bits.push(eval_result.output_wires[i].value);
    }
    for i in 254..508 {
        c1_bits.push(eval_result.output_wires[i].value);
    }

    // Convert bits back to field elements
    let c0_biguint = bits_to_biguint(&c0_bits);
    let c1_biguint = bits_to_biguint(&c1_bits);

    let actual_result = ark_bn254::Fq2::new(
        ark_bn254::Fq::from(c0_biguint),
        ark_bn254::Fq::from(c1_biguint),
    );

    // Convert from Montgomery form back to regular form
    let actual_result = Fq2::from_montgomery(actual_result);

    println!("Actual result from evaluation: {}", actual_result);
    println!("Expected result: {}", expected);

    assert_eq!(
        actual_result, expected,
        "Complex Fq2 circuit evaluation should match expected result"
    );

    println!("\n✅ SUCCESS: Complex Fq2 Garbling and Evaluation works correctly!");
    println!("   - Garbled {} non-free gates", garbled_tables.len());
    println!("   - Evaluated complex field arithmetic correctly");
    println!("   - Result: (13 * 7) + (13^2) = {} ✓", actual_result);
}

/// Helper function to convert bit array back to BigUint
fn bits_to_biguint(bits: &[bool]) -> num_bigint::BigUint {
    let mut result = num_bigint::BigUint::from(0u32);
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            result += num_bigint::BigUint::from(1u32) << i;
        }
    }
    result
}

#[test]
fn test_fq2_square_and_multiply_operations() {
    // Test a more complex sequence: ((a^2) * b) - a
    let a = ark_bn254::Fq2::from(5u32);
    let b = ark_bn254::Fq2::from(3u32);
    let expected = ((a * a) * b) - a; // (5^2 * 3) - 5 = (75) - 5 = 70

    println!("Testing Fq2 operations: ((a^2) * b) - a");
    println!("  a = {}, b = {}", a, b);
    println!("  expected = ((5^2) * 3) - 5 = {}", expected);

    let test_inputs = Fq2TestInputs::new(a, b);

    fn circuit_fn<C: CircuitContext>(ctx: &mut C, inputs: &Fq2WireRepr) -> Vec<WireId> {
        // a^2
        let a_squared = Fq2::square_montgomery(ctx, &inputs.a);
        // (a^2) * b
        let a2_mul_b = Fq2::mul_montgomery(ctx, &a_squared, &inputs.b);
        // ((a^2) * b) - a
        let result = Fq2::sub(ctx, &a2_mul_b, &inputs.a);
        result.to_wires_vec()
    }

    // Garbling
    let (garbled_sender, garbled_receiver) = channel::unbounded();
    let _garble_result: StreamingResult<_, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling_blake3(
            test_inputs.clone(),
            100_000,
            99,
            garbled_sender,
            circuit_fn,
        );

    let garbled_tables: Vec<GarbledTableEntry> = garbled_receiver.try_iter().collect();

    // Evaluation setup
    let (eval_sender, eval_receiver) = channel::unbounded();
    for (gate_id, ciphertext) in &garbled_tables {
        let ciphertext_entry: CiphertextEntry = (*gate_id, *ciphertext);
        if eval_sender.send(ciphertext_entry).is_err() {
            break;
        }
    }
    drop(eval_sender);

    // Evaluation
    let mut rng = ChaChaRng::seed_from_u64(99);
    let delta = Delta::generate(&mut rng);
    let true_wire = GarbledWire::random(&mut rng, &delta);
    let false_wire = GarbledWire::random(&mut rng, &delta);

    let eval_result: StreamingResult<EvaluateModeBlake3, _, Vec<EvaluatedWire>> =
        CircuitBuilder::<EvaluateModeBlake3>::streaming_evaluation(
            test_inputs,
            100_000,
            EvaluatedWire::new_from_garbled(&true_wire, true),
            EvaluatedWire::new_from_garbled(&false_wire, false),
            eval_receiver,
            circuit_fn,
        );

    // Extract and verify result
    assert_eq!(eval_result.output_wires.len(), 508);

    let mut c0_bits = Vec::new();
    let mut c1_bits = Vec::new();
    for i in 0..254 {
        c0_bits.push(eval_result.output_wires[i].value);
    }
    for i in 254..508 {
        c1_bits.push(eval_result.output_wires[i].value);
    }

    let c0_biguint = bits_to_biguint(&c0_bits);
    let c1_biguint = bits_to_biguint(&c1_bits);

    let actual_result = Fq2::from_montgomery(ark_bn254::Fq2::new(
        ark_bn254::Fq::from(c0_biguint),
        ark_bn254::Fq::from(c1_biguint),
    ));

    assert_eq!(actual_result, expected);
}
