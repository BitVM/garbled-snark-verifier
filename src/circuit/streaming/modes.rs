use std::{collections::HashMap, fmt};

use crate::{EvaluatedWire, Gate, WireId};

mod execute;
pub use execute::Execute;

mod execute_mode;
pub use execute_mode::{ExecuteMode, OptionalBoolean};

mod garble;
pub use garble::Garble;

mod garble_mode;
pub use garble_mode::{GarbleMode, OptionalGarbledWire};

pub trait CircuitMode: Sized + std::fmt::Debug {
    /// The wire value type used during circuit evaluation (bool for Execute, GarbledWire for Garble, etc)
    type WireValue: Clone;

    /// The storage representation type (OptionalBoolean for Execute, etc)
    type StorageValue: Clone + Default + fmt::Debug;

    /// Get the false constant value
    fn false_value(&self) -> Self::WireValue;

    /// Get the true constant value
    fn true_value(&self) -> Self::WireValue;

    /// Get default storage value for uninitialized wires
    fn default_storage_value() -> Self::StorageValue;

    /// Convert storage representation to wire value
    fn storage_to_wire(&self, stored: &Self::StorageValue) -> Option<Self::WireValue>;

    /// Convert wire value to storage representation
    fn wire_to_storage(&self, value: Self::WireValue) -> Self::StorageValue;

    /// Evaluate a gate with given input values
    fn evaluate_gate(
        &mut self,
        gate: &Gate,
        a: Self::WireValue,
        b: Self::WireValue,
    ) -> Self::WireValue;

    // Default methods for compatibility with existing code
    fn lookup_wire(&mut self, _wire: WireId) -> Option<Self::WireValue> {
        panic!("lookup_wire not implemented for this mode")
    }

    fn feed_wire(&mut self, _wire: WireId, _value: Self::WireValue) {
        panic!("feed_wire not implemented for this mode")
    }
}

// Old Garble struct replaced by new streaming implementation in garble.rs and garble_mode.rs

pub struct Evaluate {
    wires: Vec<HashMap<WireId, EvaluatedWire>>,
}

impl Evaluate {
    fn lookup_wire(&self, wire: WireId) -> Option<&EvaluatedWire> {
        self.wires.last().and_then(|last| last.get(&wire))
    }

    fn feed_wire(&mut self, wire: WireId, value: EvaluatedWire) {
        self.wires.last_mut().unwrap().insert(wire, value);
    }

    fn size(&self) -> usize {
        self.wires.iter().map(|w| w.len()).sum()
    }

    fn push_frame(&mut self, inputs: Vec<(WireId, EvaluatedWire)>) {
        self.wires.push(inputs.into_iter().collect())
    }

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, EvaluatedWire)> {
        self.wires
            .pop()
            .unwrap()
            .into_iter()
            .filter(|(wire_id, _value)| outputs.contains(wire_id))
            .collect()
    }

    fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, EvaluatedWire)> {
        input_wires
            .iter()
            .filter_map(|&wire_id| {
                self.lookup_wire(wire_id)
                    .map(|value| (wire_id, value.clone()))
            })
            .collect()
    }

    fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, EvaluatedWire)> {
        self.pop_frame(output_wires)
    }
}

// TODO: Implement CircuitMode for Evaluate when needed
