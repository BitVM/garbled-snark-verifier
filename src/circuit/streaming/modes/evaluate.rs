use std::iter;

use crossbeam::channel;

pub use super::evaluate_mode::{CiphertextEntry, EvaluateMode, EvaluateModeBlake3};
use crate::{
    EvaluatedWire, S, WireId,
    circuit::streaming::{
        CircuitInput, CircuitMode, ComponentTemplatePool, EncodeInput,
        component_key::ComponentKey,
        streaming_mode::{StreamingContext, StreamingMode},
    },
    core::{gate::garbling::GateHasher, gate_type::GateCount},
    storage::Credits,
};

const ROOT_KEY: ComponentKey = [0u8; 8];

/// Storage type alias for EvaluateMode
pub type EvaluateContext = StreamingContext<EvaluateModeBlake3>;

/// Type alias for backward compatibility - Evaluate is now StreamingMode<EvaluateMode>
pub type Evaluate = StreamingMode<EvaluateModeBlake3>;

// Extension methods for StreamingContext<EvaluateMode>
impl<H: GateHasher> StreamingContext<EvaluateMode<H>> {
    pub fn pop_credits(&mut self, len: usize) -> Vec<Credits> {
        let stack = self.stack.last_mut().unwrap();

        iter::repeat_with(|| stack.next_credit().unwrap())
            .take(len)
            .collect::<Vec<_>>()
    }
}

// Helper methods for Evaluate type alias
impl Evaluate {
    pub fn new(
        capacity: usize,
        true_wire: S,
        false_wire: S,
        ciphertext_receiver: channel::Receiver<CiphertextEntry>,
    ) -> Self {
        Self::new_evaluate(capacity, true_wire, false_wire, ciphertext_receiver)
    }

    fn new_evaluate(
        capacity: usize,
        true_wire: S,
        false_wire: S,
        ciphertext_receiver: channel::Receiver<CiphertextEntry>,
    ) -> Self {
        StreamingMode::ExecutionPass(StreamingContext {
            mode: EvaluateModeBlake3::new(capacity, true_wire, false_wire, ciphertext_receiver),
            stack: vec![],
            templates: ComponentTemplatePool::new(),
            gate_count: GateCount::default(),
        })
    }
}

// Implement CircuitInput and EncodeInput for types containing EvaluatedWire
// This allows direct use of EvaluatedWire in input structures

/// Example input structure for evaluation mode
/// Users should create their own structures following this pattern
pub struct EvaluatedInputs {
    pub wires: Vec<EvaluatedWire>,
}

impl CircuitInput for EvaluatedInputs {
    type WireRepr = Vec<WireId>;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        (0..self.wires.len()).map(|_| issue()).collect()
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.clone()
    }
}

impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for EvaluatedInputs {
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
#[path = "evaluate_test.rs"]
mod evaluate_test;
