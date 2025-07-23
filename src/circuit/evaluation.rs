#[cfg(test)]
use std::iter;

use super::{finalized::FinalizedCircuit, structure::Circuit};
#[cfg(test)]
use crate::core::gate::CorrectnessError;
use crate::{EvaluatedWire, Gate, S, WireId};

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Wire access failed: {0}")]
    WhileGetWire(#[from] crate::WireError),
    #[error("Circuit input missing: wire {0} value not provided")]
    LostInput(WireId),
    #[error("Gate evaluation failed: {gate:?} requires unevaluated wire {wire_id}")]
    WrongGateOrder { gate: Gate, wire_id: WireId },
}

#[derive(Debug)]
pub struct EvaluatedCircuit {
    pub structure: Circuit,
    pub(crate) wires: Vec<EvaluatedWire>,
    pub garbled_table: Vec<S>,
}

impl EvaluatedCircuit {
    pub fn iter_output<'s>(&'s self) -> impl 's + Iterator<Item = (WireId, bool)> {
        self.structure
            .output_wires
            .iter()
            .map(move |wire_id| (*wire_id, self.wires.get(wire_id.0).unwrap().value))
    }

    fn get_evaluated_wire(&self, wire_id: WireId) -> Option<&EvaluatedWire> {
        self.wires.get(wire_id.0)
    }

    pub fn finalize(self) -> FinalizedCircuit {
        let input_wires = [
            self.structure.get_false_wire_constant(),
            self.structure.get_true_wire_constant(),
        ]
        .iter()
        .chain(self.structure.input_wires.iter())
        .map(|wire_id| (*wire_id, self.get_evaluated_wire(*wire_id).unwrap().clone()))
        .collect::<Vec<(WireId, EvaluatedWire)>>();

        let output_wires = self
            .structure
            .output_wires
            .iter()
            .map(|wire_id| self.get_evaluated_wire(*wire_id).unwrap().clone());

        let garbled_table = self.garbled_table.clone();

        FinalizedCircuit::new(
            self.structure.clone(),
            input_wires,
            output_wires,
            garbled_table,
        )
    }

    #[cfg(test)]
    pub fn check_correctness(self) -> Result<Self, Vec<(Gate, CorrectnessError)>> {
        let mut table_gate_index = 0;
        let errors = self
            .structure
            .gates
            .iter()
            .enumerate()
            .flat_map(|(gate_id, gate)| {
                match gate.check_correctness(
                    gate_id,
                    &|wire_id| self.get_evaluated_wire(wire_id),
                    &self.garbled_table,
                    &mut table_gate_index,
                ) {
                    Err(errors) if errors.is_empty() => {
                        unreachable!("This function should not return an empty error set")
                    }
                    Err(errors) => Some(iter::repeat(gate.clone()).zip(errors).collect::<Vec<_>>()),
                    Ok(()) => None,
                }
            })
            .flatten()
            .collect::<Vec<_>>();

        if errors.is_empty() {
            Ok(self)
        } else {
            Err(errors)
        }
    }
}
