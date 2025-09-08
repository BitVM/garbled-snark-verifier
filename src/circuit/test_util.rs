#[cfg(test)]
use rand::Rng;

use crate::Circuit;

impl Circuit {
    #[cfg(test)]
    pub fn full_cycle_test(
        &self,
        get_input: impl Fn(crate::WireId) -> Option<bool>,
        get_expected_output: impl Fn(crate::WireId) -> Option<bool>,
        rng: &mut impl Rng,
    ) {
        self.garble(rng)
            .unwrap_or_else(|err| panic!("Can't garble with {err:#?}"))
            .evaluate(get_input)
            .unwrap_or_else(|err| panic!("Can't eval with {err:#?}"))
            .check_correctness()
            .unwrap_or_else(|err| panic!("Circuit not correct with {err:#?}"))
            .iter_output()
            .for_each(|(wire_id, res)| {
                assert_eq!(
                    get_expected_output(wire_id),
                    Some(res),
                    "{wire_id} not found or not equal"
                )
            });
    }
}

#[cfg(test)]
mod failure_tests {
    use std::collections::HashMap;

    use rand::{Rng, SeedableRng};

    use super::{super::evaluation::Error, Circuit};
    use crate::{
        CircuitContext, CircuitError, Gate, GateError, GateType, WireId,
        core::gate::CorrectnessError, test_utils::trng,
    };

    #[test]
    fn test_missing_input_failure() {
        let mut circuit = Circuit::default();

        let a_wire = circuit.issue_input_wire();
        let b_wire = circuit.issue_input_wire();
        let out_wire = circuit.issue_wire();

        circuit.add_gate(Gate::new(GateType::And, a_wire, b_wire, out_wire));
        circuit.make_wire_output(out_wire);

        let garbled = circuit
            .garble(&mut trng())
            .expect("Garbling should succeed");

        let result = garbled.evaluate(|wire_id| if wire_id == a_wire { Some(true) } else { None });

        match result {
            Err(Error::LostInput(wire)) => assert_eq!(wire, b_wire),
            Ok(_) => panic!("Expected LostInput error, got success"),
            Err(other) => panic!("Expected LostInput error, got: {other:?}"),
        }
    }

    #[test]
    fn test_wrong_gate_order_failure() {
        let mut circuit = Circuit::default();

        let input_a = circuit.issue_input_wire();
        let input_b = circuit.issue_input_wire();
        let intermediate_wire = circuit.issue_wire();
        let output_wire = circuit.issue_wire();

        circuit.add_gate(Gate::new(
            GateType::And,
            intermediate_wire,
            input_a,
            output_wire,
        ));
        circuit.add_gate(Gate::new(
            GateType::Xor,
            input_a,
            input_b,
            intermediate_wire,
        ));
        circuit.make_wire_output(output_wire);

        assert_eq!(
            circuit.garble(&mut trng()).err(),
            Some(CircuitError::Gate(GateError::Init {
                wire: "c",
                err: crate::WireError::InvalidWireIndex(intermediate_wire)
            }))
        );
    }

    #[test]
    fn test_garbling_with_invalid_wire_reference() {
        let mut circuit = Circuit::default();

        let a_wire = circuit.issue_input_wire();
        let invalid_wire = crate::WireId(999);
        let out_wire = circuit.issue_wire();

        circuit.add_gate(Gate::new(GateType::And, a_wire, invalid_wire, out_wire));
        circuit.make_wire_output(out_wire);

        let result = circuit.garble(&mut trng());

        assert!(
            result.is_err(),
            "Garbling should fail with invalid wire reference"
        );
    }

    #[test]
    fn test_correctness_check_failure() {
        let mut circuit = Circuit::default();

        let a_wire = circuit.issue_input_wire();
        let b_wire = circuit.issue_input_wire();
        let out_wire = circuit.issue_wire();

        circuit.add_gate(Gate::new(GateType::And, a_wire, b_wire, out_wire));
        circuit.make_wire_output(out_wire);

        let input_map = [(a_wire, true), (b_wire, false)]
            .into_iter()
            .collect::<HashMap<_, _>>();

        let mut garbled = circuit
            .garble(&mut trng())
            .expect("Garbling should succeed");

        for entry in &mut garbled.garbled_table {
            *entry = crate::S::random(&mut rand::rngs::StdRng::from_seed([50u8; 32]));
        }

        let evaluated = garbled
            .evaluate(|id| input_map.get(&id).copied())
            .expect("Evaluation should succeed");

        let result = evaluated.check_correctness();

        assert!(
            matches!(result, Err(ref errors) if errors.iter().any(|(_, error)| matches!(error, CorrectnessError::TableMismatch { .. }))),
            "Expected TableMismatch error from corrupted table"
        );
    }

    #[test]
    fn test_evaluation_all_inputs_missing() {
        let mut circuit = Circuit::default();

        let a_wire = circuit.issue_input_wire();
        let b_wire = circuit.issue_input_wire();
        let out_wire = circuit.issue_wire();

        circuit.add_gate(Gate::new(GateType::And, a_wire, b_wire, out_wire));
        circuit.make_wire_output(out_wire);

        let garbled = circuit
            .garble(&mut trng())
            .expect("Garbling should succeed");

        let result = garbled.evaluate(|_| None);

        match result {
            Err(Error::LostInput(wire)) => {
                assert!(
                    wire == a_wire || wire == b_wire,
                    "Should fail on first missing input"
                );
            }
            Ok(_) => panic!("Expected LostInput error, got success"),
            Err(other) => panic!("Expected LostInput error, got: {other:?}"),
        }
    }

    #[test]
    fn test_garbled_vs_direct_evaluation_consistency() {
        pub fn consistency_test(
            circuit: &mut Circuit,
            get_input: impl Fn(WireId) -> Option<bool> + Clone,
            rng: &mut impl Rng,
        ) {
            let garbled_result = circuit
                .garble(rng)
                .unwrap_or_else(|err| panic!("Can't garble with {err:#?}"))
                .evaluate(get_input.clone())
                .unwrap_or_else(|err| panic!("Can't eval garbled with {err:#?}"))
                .check_correctness()
                .unwrap_or_else(|err| panic!("Circuit not correct with {err:#?}"));

            let direct_result: std::collections::HashMap<_, _> = circuit
                .simple_evaluate(get_input)
                .unwrap_or_else(|err| panic!("Can't eval directly with {err:#?}"))
                .collect();

            assert_eq!(
                garbled_result.structure.output_wires.len(),
                direct_result.len(),
                "Output lengths don't match"
            );

            for (wire_id, garbled_value) in garbled_result.iter_output() {
                let direct_value = direct_result[&wire_id];
                assert_eq!(
                    garbled_value, direct_value,
                    "Output mismatch at wire {wire_id}: garbled={garbled_value}, direct={direct_value}"
                );
            }
        }

        let mut circuit = Circuit::default();

        let a_wire = circuit.issue_input_wire();
        let b_wire = circuit.issue_input_wire();
        let c_wire = circuit.issue_input_wire();

        let and_out = circuit.issue_wire();
        let final_out = circuit.issue_wire();

        circuit.add_gate(Gate::new(GateType::And, a_wire, b_wire, and_out));
        circuit.add_gate(Gate::new(GateType::Xor, and_out, c_wire, final_out));
        circuit.make_wire_output(final_out);

        for a in [false, true] {
            for b in [false, true] {
                for c in [false, true] {
                    let input_map = [(a_wire, a), (b_wire, b), (c_wire, c)]
                        .into_iter()
                        .collect::<HashMap<_, _>>();

                    consistency_test(
                        &mut circuit,
                        |wire_id| input_map.get(&wire_id).copied(),
                        &mut trng(),
                    );
                }
            }
        }
    }

    #[test]
    fn test_direct_evaluation_simple() {
        let mut circuit = Circuit::default();

        let a_wire = circuit.issue_input_wire();
        let b_wire = circuit.issue_input_wire();
        let out_wire = circuit.issue_wire();

        circuit.add_gate(Gate::new(GateType::And, a_wire, b_wire, out_wire));
        circuit.make_wire_output(out_wire);

        let test_cases = [
            (false, false, false),
            (false, true, false),
            (true, false, false),
            (true, true, true),
        ];

        for (a, b, expected) in test_cases {
            let input_map = [(a_wire, a), (b_wire, b)]
                .into_iter()
                .collect::<HashMap<_, _>>();

            let result: Vec<_> = circuit
                .simple_evaluate(|wire_id| input_map.get(&wire_id).copied())
                .expect("Direct evaluation should succeed")
                .collect();

            assert_eq!(result.len(), 1, "Should have one output");
            assert_eq!(
                result[0].1, expected,
                "AND gate output incorrect for inputs ({a}, {b})"
            );
        }
    }
}
