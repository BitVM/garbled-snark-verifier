use std::{array, collections::HashMap};

use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::{
    Delta, EvaluatedWire, GarbledWire, GarbledWires, Gate, S, WireId,
    circuit::streaming::{FALSE_WIRE, TRUE_WIRE},
};

mod execute;
pub use execute::Execute;

mod execute_mode;
pub use execute_mode::{ExecuteMode, OptionalBoolean};

pub trait CircuitMode: Sized + std::fmt::Debug {
    /// The wire value type used during circuit evaluation (bool for Execute, GarbledWire for Garble, etc)
    type WireValue: Clone;

    /// The storage representation type (OptionalBoolean for Execute, etc)
    type StorageValue: Clone + Default + std::fmt::Debug;

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

pub struct Garble {
    rng: ChaChaRng,
    delta: Delta,
    wires: Vec<GarbledWires>,
    garble_table: Vec<S>,
    gate_index: usize,
    component_max_live_wires: usize,
}

impl Garble {
    pub fn new(seeds: u64, component_max_live_wires: usize) -> Self {
        let mut rng = ChaChaRng::seed_from_u64(seeds);
        let delta = Delta::generate(&mut rng);

        let mut self_ = Garble {
            rng,
            delta,
            component_max_live_wires,
            wires: vec![GarbledWires::new(component_max_live_wires)],
            garble_table: Default::default(),
            gate_index: 0,
        };

        let [false_, true_] = array::from_fn(|_| GarbledWire::random(&mut self_.rng, &self_.delta));

        self_.feed_wire(FALSE_WIRE, false_);
        self_.feed_wire(TRUE_WIRE, true_);

        self_
    }
    pub fn next_gate_index(&mut self) -> usize {
        let index = self.gate_index;
        self.gate_index += 1;
        index
    }
}

impl Garble {
    fn lookup_wire(&self, wire: WireId) -> Option<&GarbledWire> {
        self.wires.last().and_then(|last| last.get(wire).ok())
    }

    fn feed_wire(&mut self, wire: WireId, value: GarbledWire) {
        self.wires.last_mut().unwrap().init(wire, value).unwrap();
    }

    fn size(&self) -> usize {
        self.wires.iter().map(|l| l.size()).sum()
    }

    fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, GarbledWire)> {
        input_wires
            .iter()
            .filter_map(|&wire_id| {
                self.lookup_wire(wire_id)
                    .map(|value| (wire_id, value.clone()))
            })
            .collect()
    }
}

// TODO: Implement CircuitMode for Garble when needed

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
