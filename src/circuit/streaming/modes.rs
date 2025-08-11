use std::collections::HashMap;

use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::{
    Delta, EvaluatedWire, GarbledWire, GarbledWires, Gate, S, WireId,
    circuit::streaming::WireStack, core::gate::garbling::Blake3Hasher,
};

pub trait CircuitMode {
    type WireValue: Clone;

    fn lookup_wire(&self, wire: WireId) -> Option<&Self::WireValue>;

    fn feed_wire(&mut self, wire: WireId, value: Self::WireValue);

    fn size(&self) -> usize;

    fn push_frame(&mut self, inputs: Vec<(WireId, Self::WireValue)>);

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, Self::WireValue)>;

    fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, Self::WireValue)>;

    fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, Self::WireValue)>;

    fn evaluate_gate(&mut self, gate: &Gate) -> Option<()>;
}

#[derive(Default)]
pub struct Execute(WireStack<bool>);

impl CircuitMode for Execute {
    type WireValue = bool;

    fn lookup_wire(&self, wire: WireId) -> Option<&bool> {
        self.0.lookup_wire(wire)
    }

    fn feed_wire(&mut self, wire: WireId, value: bool) {
        self.0.feed_wire(wire, value);
    }

    fn size(&self) -> usize {
        self.0.size()
    }

    fn push_frame(&mut self, inputs: Vec<(WireId, bool)>) {
        self.0.push_frame(inputs);
    }

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, bool)> {
        self.0.pop_frame(outputs)
    }

    fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, bool)> {
        self.0.prepare_frame_inputs(input_wires)
    }

    fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, bool)> {
        self.0.extract_frame_outputs(output_wires)
    }

    fn evaluate_gate(&mut self, gate: &Gate) -> Option<()> {
        let wire_a_val = self.lookup_wire(gate.wire_a)?;
        let wire_b_val = self.lookup_wire(gate.wire_b)?;
        let result = (gate.gate_type.f())(*wire_a_val, *wire_b_val);
        self.feed_wire(gate.wire_c, result);
        Some(())
    }
}

// Example modes to demonstrate the generic design

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
        Garble {
            rng,
            delta,
            component_max_live_wires,
            wires: vec![GarbledWires::new(component_max_live_wires)],
            garble_table: Default::default(),
            gate_index: 0,
        }
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

    fn push_frame(&mut self, inputs: Vec<(WireId, GarbledWire)>) {
        let mut new_cache = GarbledWires::new(self.component_max_live_wires);
        inputs.into_iter().for_each(|(wire_id, value)| {
            new_cache.init(wire_id, value).unwrap();
        });

        self.wires.push(new_cache);
    }

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, GarbledWire)> {
        let last = self.wires.pop().unwrap();

        outputs
            .iter()
            .copied()
            .map(|wire_id| (wire_id, last.get(wire_id).unwrap().clone()))
            .collect()
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

    fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, GarbledWire)> {
        self.pop_frame(output_wires)
    }
}

impl CircuitMode for Garble {
    type WireValue = GarbledWire;

    fn lookup_wire(&self, wire: WireId) -> Option<&GarbledWire> {
        self.lookup_wire(wire)
    }

    fn feed_wire(&mut self, wire: WireId, value: GarbledWire) {
        self.feed_wire(wire, value);
    }

    fn size(&self) -> usize {
        self.size()
    }

    fn push_frame(&mut self, inputs: Vec<(WireId, GarbledWire)>) {
        self.push_frame(inputs);
    }

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, GarbledWire)> {
        self.pop_frame(outputs)
    }

    fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, GarbledWire)> {
        self.prepare_frame_inputs(input_wires)
    }

    fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, GarbledWire)> {
        self.extract_frame_outputs(output_wires)
    }

    fn evaluate_gate(&mut self, gate: &Gate) -> Option<()> {
        let gate_id = self.next_gate_index();

        if let Some(ciphertext) = gate
            .garble::<Blake3Hasher>(
                gate_id,
                self.wires.last_mut().unwrap(),
                &self.delta,
                &mut self.rng,
            )
            .unwrap()
        {
            self.garble_table.push(ciphertext);
        }

        Some(())
    }
}

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
        self.wires.len()
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

impl CircuitMode for Evaluate {
    type WireValue = EvaluatedWire;

    fn lookup_wire(&self, wire: WireId) -> Option<&EvaluatedWire> {
        self.lookup_wire(wire)
    }

    fn feed_wire(&mut self, wire: WireId, value: EvaluatedWire) {
        self.feed_wire(wire, value);
    }

    fn size(&self) -> usize {
        self.size()
    }

    fn push_frame(&mut self, inputs: Vec<(WireId, EvaluatedWire)>) {
        self.push_frame(inputs);
    }

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, EvaluatedWire)> {
        self.pop_frame(outputs)
    }

    fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, EvaluatedWire)> {
        self.prepare_frame_inputs(input_wires)
    }

    fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, EvaluatedWire)> {
        self.extract_frame_outputs(output_wires)
    }

    fn evaluate_gate(&mut self, _gate: &Gate) -> Option<()> {
        todo!()
    }
}
