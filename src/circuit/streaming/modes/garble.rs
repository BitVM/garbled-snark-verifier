use std::iter;

use crossbeam::channel;

pub use super::garble_mode::{GarbleMode, GarbleModeBlake3, GarbledTableEntry};
use crate::{
    GarbledWire, WireId,
    circuit::streaming::{
        CircuitInput, CircuitMode, ComponentTemplatePool, EncodeInput,
        component_key::ComponentKey,
        streaming_mode::{StreamingContext, StreamingMode},
    },
    core::{gate::garbling::GateHasher, gate_type::GateCount},
    storage::Credits,
};

const ROOT_KEY: ComponentKey = [0u8; 8];

/// Storage type alias for GarbleMode
pub type GarbleContext = StreamingContext<GarbleModeBlake3>;

/// Type alias for backward compatibility - Garble is now StreamingMode<GarbleMode>
pub type Garble = StreamingMode<GarbleModeBlake3>;

// Extension methods for StreamingContext<GarbleMode>
impl<H: GateHasher> StreamingContext<GarbleMode<H>> {
    pub fn pop_credits(&mut self, len: usize) -> Vec<Credits> {
        let stack = self.stack.last_mut().unwrap();

        iter::repeat_with(|| stack.next_credit().unwrap())
            .take(len)
            .collect::<Vec<_>>()
    }
}

// Helper methods for Garble type alias
impl Garble {
    pub fn new(
        seed: u64,
        capacity: usize,
        output_sender: channel::Sender<GarbledTableEntry>,
    ) -> Self {
        Self::new_garble(seed, capacity, output_sender)
    }

    fn new_garble(
        seed: u64,
        capacity: usize,
        output_sender: channel::Sender<GarbledTableEntry>,
    ) -> Self {
        StreamingMode::ExecutionPass(StreamingContext {
            mode: GarbleModeBlake3::new(capacity, seed, output_sender),
            stack: vec![],
            templates: ComponentTemplatePool::new(),
            gate_count: GateCount::default(),
        })
    }
}

// Implement EncodeInput for garbled wire inputs
pub struct GarbledInputs {
    pub wires: Vec<GarbledWire>,
}

impl CircuitInput for GarbledInputs {
    type WireRepr = Vec<WireId>;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.wires.len()).map(|_| issue()).collect()
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.clone()
    }
}

impl<M: CircuitMode<WireValue = GarbledWire>> EncodeInput<M> for GarbledInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        self.wires
            .iter()
            .zip(repr.iter())
            .for_each(|(wire, wire_id)| {
                cache.feed_wire(*wire_id, wire.clone());
            });
    }
}

#[cfg(test)]
#[path = "garble_test.rs"]
mod garble_test;
