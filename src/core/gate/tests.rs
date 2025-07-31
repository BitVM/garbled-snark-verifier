use std::collections::HashMap;

use super::*;
use crate::test_utils::trng;

const GATE_ID: GateId = 0;

const TEST_CASES: [(bool, bool); 4] =
    [(false, false), (false, true), (true, false), (true, true)];

fn create_test_delta() -> Delta {
    use rand::rng;
    Delta::generate(&mut rng())
}

fn issue_test_wire() -> GarbledWires {
    GarbledWires::new(1000)
}

fn create_test_wire_ids() -> (WireId, WireId, WireId) {
    (WireId(0), WireId(1), WireId(2))
}

fn test_gate_e2e(gate: Gate, expected_fn: fn(bool, bool) -> bool, gate_name: &str) {
    let delta = create_test_delta();
    let mut wires = issue_test_wire();

    let table = gate
        .garble::<Blake3Hasher>(GATE_ID, &mut wires, &delta, &mut trng())
        .expect("Garbling should succeed")
        .map(|row| vec![row])
        .unwrap_or_default();

    let wire_a_garbled = wires.get(gate.wire_a).expect("Wire A should exist");
    let wire_b_garbled = wires.get(gate.wire_b).expect("Wire B should exist");
    let wire_c_garbled = wires.get(gate.wire_c).expect("Wire C should exist");

    for (input_a, input_b) in TEST_CASES {
        let eval_a = EvaluatedWire {
            active_label: wire_a_garbled.select(input_a),
            value: input_a,
        };
        let eval_b = EvaluatedWire {
            active_label: wire_b_garbled.select(input_b),
            value: input_b,
        };

        let eval_c = gate.evaluate(&eval_a, &eval_b, wire_c_garbled);

        let expected_output = expected_fn(input_a, input_b);
        assert_eq!(
            eval_c.value, expected_output,
            "Evaluation should be correct for {gate_name}({input_a}, {input_b})"
        );

        let mut evaluations = HashMap::new();
        evaluations.insert(gate.wire_a, eval_a);
        evaluations.insert(gate.wire_b, eval_b);
        evaluations.insert(gate.wire_c, eval_c);

        let mut table_index = 0;

        let correctness_result = gate.check_correctness(
            GATE_ID,
            &|wire_id: WireId| evaluations.get(&wire_id),
            &table,
            &mut table_index,
        );

        assert_eq!(
            correctness_result,
            Ok(()),
            "Correctness check should pass for {gate_name}({input_a}, {input_b})"
        );
    }
}

fn test_not_gate_e2e(gate: Gate) {
    let delta = create_test_delta();
    let mut wires = issue_test_wire();

    let table = gate
        .garble::<Blake3Hasher>(GATE_ID, &mut wires, &delta, &mut trng())
        .expect("Garbling should succeed")
        .map(|row| vec![row])
        .unwrap_or_default();

    let wire_garbled = wires.get(gate.wire_a).expect("Wire should exist");

    for input in [false, true] {
        let eval_wire = EvaluatedWire {
            active_label: wire_garbled.select(input),
            value: input,
        };

        let eval_c = gate.evaluate(&eval_wire, &eval_wire, wire_garbled);

        let expected_output = !input;
        assert_eq!(
            eval_c.value, expected_output,
            "Evaluation should be correct for NOT({input})"
        );

        let mut evaluations = HashMap::new();
        evaluations.insert(gate.wire_a, eval_wire.clone());
        evaluations.insert(gate.wire_b, eval_wire.clone());
        evaluations.insert(gate.wire_c, eval_wire);

        let mut table_index = 0;

        let correctness_result = gate.check_correctness(
            GATE_ID,
            &|wire_id: WireId| evaluations.get(&wire_id),
            &table,
            &mut table_index,
        );

        assert_eq!(
            correctness_result,
            Ok(()),
            "Correctness check should pass for NOT({input})"
        );
    }
}

#[test]
fn test_and_gate() {
    let (wire_a, wire_b, wire_c) = create_test_wire_ids();
    let gate = Gate::and(wire_a, wire_b, wire_c);
    test_gate_e2e(gate, |a, b| a && b, "AND");
}

#[test]
fn test_nand_gate() {
    let (wire_a, wire_b, wire_c) = create_test_wire_ids();
    let gate = Gate::nand(wire_a, wire_b, wire_c);
    test_gate_e2e(gate, |a, b| !(a && b), "NAND");
}

#[test]
fn test_nimp_gate() {
    let (wire_a, wire_b, wire_c) = create_test_wire_ids();
    let gate = Gate::nimp(wire_a, wire_b, wire_c);
    test_gate_e2e(gate, |a, b| a && !b, "NIMP");
}

#[test]
fn test_imp_gate() {
    let (wire_a, wire_b, wire_c) = create_test_wire_ids();
    let gate = Gate::imp(wire_a, wire_b, wire_c);
    test_gate_e2e(gate, |a, b| !a || b, "IMP");
}

#[test]
fn test_ncimp_gate() {
    let (wire_a, wire_b, wire_c) = create_test_wire_ids();
    let gate = Gate::ncimp(wire_a, wire_b, wire_c);
    test_gate_e2e(gate, |a, b| !a && b, "NCIMP");
}

#[test]
fn test_cimp_gate() {
    let (wire_a, wire_b, wire_c) = create_test_wire_ids();
    let gate = Gate::cimp(wire_a, wire_b, wire_c);
    test_gate_e2e(gate, |a, b| !b || a, "CIMP");
}

#[test]
fn test_nor_gate() {
    let (wire_a, wire_b, wire_c) = create_test_wire_ids();
    let gate = Gate::nor(wire_a, wire_b, wire_c);
    test_gate_e2e(gate, |a, b| !(a || b), "NOR");
}

#[test]
fn test_or_gate() {
    let (wire_a, wire_b, wire_c) = create_test_wire_ids();
    let gate = Gate::or(wire_a, wire_b, wire_c);
    test_gate_e2e(gate, |a, b| a || b, "OR");
}

#[test]
fn test_xor_gate() {
    let (wire_a, wire_b, wire_c) = create_test_wire_ids();
    let gate = Gate::xor(wire_a, wire_b, wire_c);
    test_gate_e2e(gate, |a, b| a ^ b, "XOR");
}

#[test]
fn test_xnor_gate() {
    let (wire_a, wire_b, wire_c) = create_test_wire_ids();
    let gate = Gate::xnor(wire_a, wire_b, wire_c);
    test_gate_e2e(gate, |a, b| !(a ^ b), "XNOR");
}

#[test]
fn test_not_gate() {
    let mut wire_a = WireId(0);
    let gate = Gate::not(&mut wire_a);
    test_not_gate_e2e(gate);
}