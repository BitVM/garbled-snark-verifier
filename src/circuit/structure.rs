use bitvec::prelude::*;

use crate::{Gate, WireId, core::gate_type::GateCount};

#[derive(Clone, Debug)]
pub struct Circuit {
    pub num_wire: usize,
    pub input_wires: Vec<WireId>,
    pub output_wires: Vec<WireId>,
    pub gates: Vec<Gate>,
    pub gate_count: GateCount,
}

impl Default for Circuit {
    fn default() -> Self {
        Self {
            num_wire: 2,
            input_wires: Default::default(),
            output_wires: Default::default(),
            gates: Default::default(),
            gate_count: GateCount::default(),
        }
    }
}

impl Circuit {
    pub fn get_false_wire_constant(&self) -> WireId {
        WireId(0)
    }

    pub fn get_true_wire_constant(&self) -> WireId {
        WireId(1)
    }

    pub fn issue_wire(&mut self) -> WireId {
        let new = WireId(self.num_wire);
        self.num_wire += 1;
        new
    }

    pub fn issue_input_wire(&mut self) -> WireId {
        let wire_id = self.issue_wire();
        self.make_wire_input(wire_id);
        wire_id
    }

    pub fn issue_output_wire(&mut self) -> WireId {
        let wire_id = self.issue_wire();
        self.make_wire_output(wire_id);
        wire_id
    }

    pub fn make_wire_input(&mut self, w: WireId) {
        match self.input_wires.binary_search(&w) {
            Ok(_) => {}
            Err(pos) => self.input_wires.insert(pos, w),
        }
    }

    pub fn make_wire_output(&mut self, w: WireId) {
        match self.output_wires.binary_search(&w) {
            Ok(_) => {}
            Err(pos) => self.output_wires.insert(pos, w),
        }
    }

    pub fn add_gate(&mut self, gate: Gate) {
        self.gate_count.handle(gate.gate_type);
        self.gates.push(gate);
    }

    pub fn simple_evaluate(
        &self,
        get_input: impl Fn(WireId) -> Option<bool>,
    ) -> Result<impl Iterator<Item = (WireId, bool)>, super::Error> {
        let mut wire_values = bitvec![0; self.num_wire];
        let mut wire_initialized = bitvec![0; self.num_wire];

        wire_values.set(self.get_false_wire_constant().0, false);
        wire_initialized.set(self.get_false_wire_constant().0, true);
        
        wire_values.set(self.get_true_wire_constant().0, true);
        wire_initialized.set(self.get_true_wire_constant().0, true);

        for &wire_id in &self.input_wires {
            let value = get_input(wire_id).ok_or(super::Error::LostInput(wire_id))?;
            wire_values.set(wire_id.0, value);
            wire_initialized.set(wire_id.0, true);
        }

        for gate in &self.gates {
            if !wire_initialized[gate.wire_a.0] {
                return Err(super::Error::WrongGateOrder { gate: gate.clone(), wire_id: gate.wire_a });
            }
            if !wire_initialized[gate.wire_b.0] {
                return Err(super::Error::WrongGateOrder { gate: gate.clone(), wire_id: gate.wire_b });
            }
            
            let a = wire_values[gate.wire_a.0];
            let b = wire_values[gate.wire_b.0];
            let result = gate.gate_type.f()(a, b);
            wire_values.set(gate.wire_c.0, result);
            wire_initialized.set(gate.wire_c.0, true);
        }

        Ok(self
            .output_wires
            .iter()
            .map(move |&wire_id| (wire_id, wire_values[wire_id.0])))
    }
}
