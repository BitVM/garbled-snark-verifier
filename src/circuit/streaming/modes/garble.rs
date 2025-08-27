use std::{collections::HashMap, iter, sync::mpsc};

use log::trace;

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
        StreamingMode::MetadataPass(ComponentMetaBuilder::new(inputs))
    }

    pub fn to_root_ctx<I: EncodeInput<GarbledWire>>(
        self,
        seed: u64,
        capacity: usize,
        output_sender: mpsc::Sender<GarbledTableEntry>,
        input: &I,
        meta_input_wires: &[WireId],
        meta_output_wires: &[WireId],
    ) -> (Self, I::WireRepr) {
        if let StreamingMode::MetadataPass(meta) = self {
            let meta = meta.build(meta_output_wires);

            let mut input_credits = vec![0; meta_input_wires.len()];

            let mut instance = meta.to_instance(
                meta_input_wires,
                &vec![1; meta_output_wires.len()],
                |wire_id, credits| {
                    let index = wire_id.0 - WireId::MIN.0;
                    let rev_index = meta_input_wires.len() - 1 - index;
                    input_credits[rev_index] += credits;
                },
            );

            instance.credits_stack.extend_from_slice(&input_credits);

            trace!("meta before input encode: {instance:?}");

            let mut ctx = StreamingMode::ExecutionPass(StreamingContext {
                mode: GarbleMode::new(seed, output_sender),
                storage: Storage::new(capacity),
                stack: vec![instance],
                templates: {
                    let mut map = HashMap::default();
                    map.insert(ROOT_KEY, meta);
                    map
                },
                gate_count: GateCount::default(),
            });

            let input_repr = input.allocate(|| ctx.issue_wire());
            input.encode(&input_repr, &mut ctx);

            if let StreamingMode::ExecutionPass(ctx) = &ctx {
                trace!("meta after input encode: {:?}", ctx.stack.last().unwrap());
            }

            (ctx, input_repr)
        } else {
            panic!()
        }
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
