use std::{collections::HashMap, iter, sync::mpsc};

pub use super::garble_mode::{GarbleMode, GarbledTableEntry};
use crate::{
    GarbledWire, WireId,
    circuit::streaming::{
        CircuitContext, CircuitInput, CircuitMode, EncodeInput,
        component_key::ComponentKey,
        component_meta::ComponentMetaBuilder,
        streaming_mode::{StreamingContext, StreamingMode},
    },
    core::gate_type::GateCount,
    storage::{Credits, Storage},
};

const ROOT_KEY: ComponentKey = [0u8; 8];

/// Storage type alias for GarbleMode
pub type GarbleContext = StreamingContext<GarbleMode>;

/// Type alias for backward compatibility - Garble is now StreamingMode<GarbleMode>
pub type Garble = StreamingMode<GarbleMode>;

// Extension methods for StreamingContext<GarbleMode>
impl StreamingContext<GarbleMode> {
    pub fn pop_credits(&mut self, len: usize) -> Vec<Credits> {
        let stack = self.stack.last_mut().unwrap();

        iter::repeat_with(|| stack.next_credit().unwrap())
            .take(len)
            .collect::<Vec<_>>()
    }
}

// Helper methods for Garble type alias
impl Garble {
    pub fn new(seed: u64, capacity: usize, output_sender: mpsc::Sender<GarbledTableEntry>) -> Self {
        Self::new_garble(seed, capacity, output_sender)
    }

    fn new_garble(
        seed: u64,
        capacity: usize,
        output_sender: mpsc::Sender<GarbledTableEntry>,
    ) -> Self {
        StreamingMode::ExecutionPass(StreamingContext {
            mode: GarbleMode::new(seed, output_sender),
            storage: Storage::new(capacity),
            stack: vec![],
            templates: HashMap::default(),
            gate_count: GateCount::default(),
        })
    }

    fn new_meta(inputs: &[WireId]) -> Self {
        StreamingMode::MetadataPass(ComponentMetaBuilder::new(inputs.len()))
    }

    pub fn to_root_ctx<I: EncodeInput<GarbledWire>>(
        self,
        _seed: u64,
        _capacity: usize,
        _output_sender: mpsc::Sender<GarbledTableEntry>,
        _input: &I,
        _meta_input_wires_len: usize,
        _meta_output_wires: &[WireId],
    ) -> (Self, I::WireRepr) {
        todo!()
    }

    pub fn issue_wire_with_credit(&mut self) -> (WireId, Credits) {
        match self {
            StreamingMode::MetadataPass(meta) => (meta.issue_wire(), 0),
            StreamingMode::ExecutionPass(ctx) => ctx.issue_wire_with_credit(),
        }
    }

    pub fn non_free_gates_count(&self) -> usize {
        match self {
            StreamingMode::MetadataPass(_meta) => 0,
            StreamingMode::ExecutionPass(ctx) => ctx.gate_count.nonfree_gate_count() as usize,
        }
    }

    pub fn total_gates_count(&self) -> usize {
        match self {
            StreamingMode::MetadataPass(_meta) => 0,
            StreamingMode::ExecutionPass(ctx) => ctx.gate_count.total_gate_count() as usize,
        }
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

impl EncodeInput<GarbledWire> for GarbledInputs {
    fn encode<M: CircuitMode<WireValue = GarbledWire>>(
        &self,
        repr: &Self::WireRepr,
        cache: &mut M,
    ) {
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
