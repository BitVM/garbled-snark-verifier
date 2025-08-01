use super::{
    Circuit,
    commitment::{Commit, commit},
    structure::{GateSource, VecGate},
};
use crate::{EvaluatedWire, S, WireId};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(
        "Input wire restoration failed: wire {wire_id} index {index} exceeds circuit capacity {max_wires}"
    )]
    InputWireIndexOutOfBounds {
        wire_id: WireId,
        index: usize,
        max_wires: usize,
    },
    #[error(
        "Gate evaluation failed: gate {gate_id} input wire A ({wire_a}) has no evaluated value during circuit restoration"
    )]
    GateInputWireAMissing { gate_id: usize, wire_a: WireId },
    #[error(
        "Gate evaluation failed: gate {gate_id} input wire B ({wire_b}) has no evaluated value during circuit restoration"
    )]
    GateInputWireBMissing { gate_id: usize, wire_b: WireId },
    #[error(
        "Gate evaluation failed: gate {gate_id} output wire ({wire_c}) index {index} exceeds circuit capacity {max_wires}"
    )]
    GateOutputWireIndexOutOfBounds {
        gate_id: usize,
        wire_c: WireId,
        index: usize,
        max_wires: usize,
    },
    #[error(
        "Output verification failed: output wire {wire_id} has no evaluated value after circuit restoration"
    )]
    OutputWireMissing { wire_id: WireId },
    #[error(
        "Output verification failed: output wire {wire_id} exceeds circuit capacity {max_wires}"
    )]
    OutputWireIndexOutOfBounds { wire_id: WireId, max_wires: usize },
    #[error(
        "Output commit verification failed: restored commit does not match expected output commitment"
    )]
    CommitMismatch,
}

#[derive(Debug)]
pub struct FinalizedCircuit<G: GateSource = VecGate> {
    pub structure: Circuit<G>,
    pub input_wires: Vec<(WireId, EvaluatedWire)>,
    pub output_wires_commit: Commit,
    pub garbled_table: Vec<S>,
}

impl<G: GateSource> FinalizedCircuit<G> {
    pub fn new(
        structure: Circuit<G>,
        input_wires: Vec<(WireId, EvaluatedWire)>,
        output_wires: impl Iterator<Item = EvaluatedWire>,
        garbled_table: Vec<S>,
    ) -> Self {
        let output_wires_commit = commit(output_wires);

        Self {
            structure,
            input_wires,
            output_wires_commit,
            garbled_table,
        }
    }

    pub fn check(&self) -> Result<(), Error> {
        // Restore intermediate values by re-evaluating the circuit
        // Migrate to MaybeUnunit
        let mut wires = vec![None; self.structure.num_wire];

        // Set input wire values
        for (wire_id, input_wire) in &self.input_wires {
            if wire_id.0 >= wires.len() {
                return Err(Error::InputWireIndexOutOfBounds {
                    wire_id: *wire_id,
                    index: wire_id.0,
                    max_wires: wires.len(),
                });
            }
            wires[wire_id.0] = Some(input_wire.clone());
        }

        // Evaluate gates to restore intermediate values
        let mut table_gate_index = 0;
        for (gate_id, gate) in self.structure.gates.iter().enumerate() {
            let wire_a = wires.get(gate.wire_a.0).and_then(|v| v.as_ref()).ok_or(
                Error::GateInputWireAMissing {
                    gate_id,
                    wire_a: gate.wire_a,
                },
            )?;
            let wire_b = wires.get(gate.wire_b.0).and_then(|v| v.as_ref()).ok_or(
                Error::GateInputWireBMissing {
                    gate_id,
                    wire_b: gate.wire_b,
                },
            )?;

            if gate.wire_c.0 >= wires.len() {
                return Err(Error::GateOutputWireIndexOutOfBounds {
                    gate_id,
                    wire_c: gate.wire_c,
                    index: gate.wire_c.0,
                    max_wires: wires.len(),
                });
            }

            let result = gate.calculate_output(
                gate_id,
                wire_a,
                wire_b,
                &self.garbled_table,
                &mut table_gate_index,
            );

            wires[gate.wire_c.0] = Some(result);
        }

        // Verify output commit matches restored values
        let mut output_values = Vec::new();
        for wire_id in &self.structure.output_wires {
            if wire_id.0 >= wires.len() {
                return Err(Error::OutputWireIndexOutOfBounds {
                    wire_id: *wire_id,
                    max_wires: wires.len(),
                });
            }

            let wire_value = wires
                .get(wire_id.0)
                .and_then(|v| v.as_ref())
                .ok_or(Error::OutputWireMissing { wire_id: *wire_id })?;
            output_values.push(wire_value.clone());
        }

        let restored_output_commit = commit(output_values.into_iter());

        if restored_output_commit != self.output_wires_commit {
            return Err(Error::CommitMismatch);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use rand::SeedableRng;

    use super::*;
    use crate::{Circuit, CircuitContext, EvaluatedWire, Gate, GateType, S, WireId};

    fn test_rng() -> rand::rngs::StdRng {
        rand::rngs::StdRng::from_seed([42u8; 32])
    }

    fn create_simple_and_circuit() -> Circuit {
        let mut circuit = Circuit::default();
        let input_a = circuit.issue_input_wire();
        let input_b = circuit.issue_input_wire();
        let output = circuit.issue_wire();
        circuit.add_gate(Gate::new(GateType::And, input_a, input_b, output));
        circuit.make_wire_output(output);
        circuit
    }

    fn create_multi_gate_circuit() -> Circuit {
        let mut circuit = Circuit::default();
        let input_a = circuit.issue_input_wire();
        let input_b = circuit.issue_input_wire();
        let input_c = circuit.issue_input_wire();

        let and_out = circuit.issue_wire();
        let final_out = circuit.issue_wire();

        circuit.add_gate(Gate::new(GateType::And, input_a, input_b, and_out));
        circuit.add_gate(Gate::new(GateType::Xor, and_out, input_c, final_out));
        circuit.make_wire_output(final_out);
        circuit
    }

    fn create_test_finalized_circuit(
        circuit: Circuit,
        inputs: &[(WireId, bool)],
    ) -> FinalizedCircuit {
        let input_map: HashMap<WireId, bool> = inputs.iter().cloned().collect();

        let garbled = circuit
            .garble(&mut test_rng())
            .expect("Garbling should succeed");
        let evaluated = garbled
            .evaluate(|wire_id| input_map.get(&wire_id).copied())
            .expect("Evaluation should succeed");
        let checked = evaluated
            .check_correctness()
            .expect("Correctness check should succeed");

        checked.finalize()
    }

    #[test]
    fn test_check_success_simple_and_gate() {
        let circuit = create_simple_and_circuit();
        let input_wires = vec![
            (WireId(2), true),  // input_a
            (WireId(3), false), // input_b
        ];

        let finalized = create_test_finalized_circuit(circuit, &input_wires);

        assert!(
            finalized.check().is_ok(),
            "Simple AND gate check should succeed"
        );
    }

    #[test]
    fn test_check_success_multi_gate_circuit() {
        let circuit = create_multi_gate_circuit();
        let input_wires = vec![
            (WireId(2), true),  // input_a
            (WireId(3), true),  // input_b
            (WireId(4), false), // input_c
        ];

        let finalized = create_test_finalized_circuit(circuit, &input_wires);

        assert!(
            finalized.check().is_ok(),
            "Multi-gate circuit check should succeed"
        );
    }

    #[test]
    fn test_check_success_all_input_combinations() {
        let circuit = create_simple_and_circuit();

        for a in [false, true] {
            for b in [false, true] {
                let input_wires = vec![(WireId(2), a), (WireId(3), b)];

                let finalized = create_test_finalized_circuit(circuit.clone(), &input_wires);
                assert!(
                    finalized.check().is_ok(),
                    "AND gate check should succeed for inputs ({a}, {b})"
                );
            }
        }
    }

    #[test]
    fn test_input_wire_index_out_of_bounds() {
        let circuit = create_simple_and_circuit();

        // Create a finalized circuit with valid structure
        let input_wires = vec![(WireId(2), true), (WireId(3), false)];
        let mut finalized = create_test_finalized_circuit(circuit, &input_wires);

        // Corrupt the input wires to reference an invalid index
        finalized.input_wires.push((
            WireId(999),
            EvaluatedWire {
                active_label: S::random(&mut test_rng()),
                value: false,
            },
        ));

        match finalized.check() {
            Err(Error::InputWireIndexOutOfBounds {
                wire_id,
                index,
                max_wires,
            }) => {
                assert_eq!(wire_id, WireId(999));
                assert_eq!(index, 999);
                assert!(max_wires < 999);
            }
            other => panic!("Expected InputWireIndexOutOfBounds error, got: {other:?}"),
        }
    }

    #[test]
    fn test_gate_input_wire_a_missing() {
        let circuit = create_simple_and_circuit();
        let input_wires = vec![(WireId(2), true), (WireId(3), false)];
        let mut finalized = create_test_finalized_circuit(circuit, &input_wires);

        // Remove the first input wire to simulate missing wire_a
        finalized.input_wires.retain(|(wire_id, _)| wire_id.0 != 2);

        match finalized.check() {
            Err(Error::GateInputWireAMissing { gate_id, wire_a }) => {
                assert_eq!(gate_id, 0);
                assert_eq!(wire_a, WireId(2)); // input_a wire
            }
            other => panic!("Expected GateInputWireAMissing error, got: {other:?}"),
        }
    }

    #[test]
    fn test_gate_input_wire_b_missing() {
        let circuit = create_simple_and_circuit();
        let input_wires = vec![(WireId(2), true), (WireId(3), false)];
        let mut finalized = create_test_finalized_circuit(circuit, &input_wires);

        // Remove the second input wire to simulate missing wire_b
        finalized.input_wires.retain(|(wire_id, _)| wire_id.0 != 3);

        match finalized.check() {
            Err(Error::GateInputWireBMissing { gate_id, wire_b }) => {
                assert_eq!(gate_id, 0);
                assert_eq!(wire_b, WireId(3)); // input_b wire
            }
            other => panic!("Expected GateInputWireBMissing error, got: {other:?}"),
        }
    }

    #[test]
    fn test_gate_output_wire_index_out_of_bounds() {
        let circuit = create_simple_and_circuit();
        let input_wires = vec![(WireId(2), true), (WireId(3), false)];
        let mut finalized = create_test_finalized_circuit(circuit, &input_wires);

        // Corrupt a gate to reference an invalid output wire
        finalized
            .structure
            .gates
            .update(0, |g| g.wire_c = WireId(999));

        match finalized.check() {
            Err(Error::GateOutputWireIndexOutOfBounds {
                gate_id,
                wire_c,
                index,
                max_wires,
            }) => {
                assert_eq!(gate_id, 0);
                assert_eq!(wire_c, WireId(999));
                assert_eq!(index, 999);
                assert!(max_wires < 999);
            }
            other => panic!("Expected GateOutputWireIndexOutOfBounds error, got: {other:?}"),
        }
    }

    #[test]
    fn test_output_wire_index_out_of_bounds() {
        let circuit = create_simple_and_circuit();
        let input_wires = vec![(WireId(2), true), (WireId(3), false)];
        let mut finalized = create_test_finalized_circuit(circuit, &input_wires);

        // Corrupt the output wires to reference an invalid index
        finalized.structure.output_wires.push(WireId(999));

        match finalized.check() {
            Err(Error::OutputWireIndexOutOfBounds { wire_id, max_wires }) => {
                assert_eq!(wire_id, WireId(999));
                assert!(max_wires < 999);
            }
            other => panic!("Expected OutputWireIndexOutOfBounds error, got: {other:?}"),
        }
    }

    #[test]
    fn test_output_wire_missing() {
        let circuit = create_simple_and_circuit();
        let input_wires = vec![(WireId(2), true), (WireId(3), false)];
        let mut finalized = create_test_finalized_circuit(circuit, &input_wires);

        // Add a new wire to the structure and reference it as output
        // but don't add it to the computed wires
        let new_wire_id = WireId(finalized.structure.num_wire);
        finalized.structure.num_wire += 1;
        finalized.structure.output_wires.push(new_wire_id);

        match finalized.check() {
            Err(Error::OutputWireMissing { wire_id }) => {
                assert_eq!(wire_id, new_wire_id);
            }
            other => panic!("Expected OutputWireMissing error, got: {other:?}"),
        }
    }

    #[test]
    fn test_commit_mismatch() {
        let circuit = create_simple_and_circuit();
        let input_wires = vec![(WireId(2), true), (WireId(3), false)];
        let mut finalized = create_test_finalized_circuit(circuit, &input_wires);

        // Corrupt the output commit to cause a mismatch
        finalized.output_wires_commit = vec![0xDE, 0xAD, 0xBE, 0xEF];

        match finalized.check() {
            Err(Error::CommitMismatch) => {
                // Expected
            }
            other => panic!("Expected CommitMismatch error, got: {other:?}"),
        }
    }

    #[test]
    fn test_empty_circuit() {
        let circuit = Circuit::default();
        let finalized = FinalizedCircuit {
            structure: circuit,
            input_wires: Vec::new(),
            output_wires_commit: commit(std::iter::empty()),
            garbled_table: Vec::new(),
        };

        assert!(finalized.check().is_ok(), "Empty circuit should pass check");
    }

    #[test]
    fn test_circuit_with_single_input() {
        let mut circuit = Circuit::default();
        let input_a = circuit.issue_input_wire();
        let output = circuit.issue_wire();

        // Create a simple buffer gate (AND with same input twice)
        circuit.add_gate(Gate::new(GateType::And, input_a, input_a, output));
        circuit.make_wire_output(output);

        let finalized = create_test_finalized_circuit(circuit, &[(WireId(2), true)]);
        assert!(
            finalized.check().is_ok(),
            "Single input circuit should pass check"
        );
    }
}
