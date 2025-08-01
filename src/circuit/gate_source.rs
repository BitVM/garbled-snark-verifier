use crate::{Gate, core::gate_type::GateCount};

pub trait GateSource: Clone {
    fn iter(&self) -> impl Iterator<Item = &Gate>;
    fn push(&mut self, gate: Gate);
    fn gate_count(&mut self) -> &GateCount;
}

#[derive(Clone, Default)]
pub struct VecGate {
    gates: Vec<Gate>,
    gate_count: GateCount,
}

#[cfg(test)]
impl VecGate {
    pub(crate) fn update(&mut self, index: usize, upd: impl FnOnce(&mut Gate)) {
        upd(&mut self.gates[index])
    }
}

impl GateSource for VecGate {
    fn iter(&self) -> impl Iterator<Item = &Gate> {
        self.gates.iter()
    }

    fn push(&mut self, gate: Gate) {
        self.gate_count.handle(gate.gate_type);
        self.gates.push(gate)
    }

    fn gate_count(&mut self) -> &GateCount {
        &self.gate_count
    }
}
