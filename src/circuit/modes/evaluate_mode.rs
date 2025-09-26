use std::num::NonZero;

use serde::{Deserialize, Serialize};

use super::garble_mode::{GarbledWire, halfgates_garbling};
use crate::{
    Gate, S, WireId,
    circuit::{CircuitMode, FALSE_WIRE, TRUE_WIRE, ciphertext_source::CiphertextSource},
    core::progress::maybe_log_progress,
    hashers::GateHasher,
    storage::{Credits, Storage},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatedWire {
    pub active_label: S,
    pub value: bool,
}

impl EvaluatedWire {
    pub fn empty() -> Self {
        EvaluatedWire {
            active_label: S::ZERO,
            value: false,
        }
    }

    pub fn new(active_label: S, value: bool) -> Self {
        EvaluatedWire {
            active_label,
            value,
        }
    }

    pub fn new_from_garbled(garbled_wire: &GarbledWire, value: bool) -> Self {
        EvaluatedWire {
            active_label: garbled_wire.select(value),
            value,
        }
    }
}

impl Default for EvaluatedWire {
    fn default() -> Self {
        EvaluatedWire {
            active_label: S::ZERO,
            value: false,
        }
    }
}

/// Storage representation for evaluated wires
#[derive(Clone, Debug, Default)]
pub struct OptionalEvaluatedWire {
    pub wire: Option<EvaluatedWire>,
}

/// Evaluate mode - consumes garbled circuits from a pluggable source.
pub struct EvaluateMode<H: GateHasher, SRC: CiphertextSource> {
    gate_index: usize,
    source: SRC,
    storage: Storage<WireId, Option<EvaluatedWire>>,
    // Store the constant wires (provided externally)
    false_wire: S,
    true_wire: S,
    _hasher: std::marker::PhantomData<H>,
}

impl<H: GateHasher, SRC: CiphertextSource> EvaluateMode<H, SRC> {
    pub fn new(capacity: usize, true_wire: S, false_wire: S, source: SRC) -> Self {
        Self {
            storage: Storage::new(capacity),
            gate_index: 0,
            source,
            false_wire,
            true_wire,
            _hasher: std::marker::PhantomData,
        }
    }

    fn next_gate_index(&mut self) -> usize {
        let index = self.gate_index;
        self.gate_index += 1;
        index
    }

    fn consume_ciphertext(&mut self) -> Option<S> {
        self.source.recv()
    }
}

impl<H: GateHasher, SRC: CiphertextSource> std::fmt::Debug for EvaluateMode<H, SRC> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvaluateMode")
            .field("gate_index", &self.gate_index)
            .finish()
    }
}

impl<H: GateHasher, SRC: CiphertextSource> CircuitMode for EvaluateMode<H, SRC> {
    type WireValue = EvaluatedWire;
    type CiphertextAcc = SRC::Result;

    fn false_value(&self) -> EvaluatedWire {
        EvaluatedWire {
            active_label: self.false_wire,
            value: false,
        }
    }

    /// Allocate a wire with its initial remaining-use counter (`credits`).
    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(None, credits)
    }

    fn true_value(&self) -> EvaluatedWire {
        EvaluatedWire {
            active_label: self.true_wire,
            value: true,
        }
    }

    fn evaluate_gate(&mut self, gate: &Gate) {
        // Always consume input credits by looking up A and B.
        let a = self.lookup_wire(gate.wire_a).unwrap();
        let b = self.lookup_wire(gate.wire_b).unwrap();

        let gate_id = self.next_gate_index();

        // If C is unreachable, skip evaluation and do not advance gate index.
        if gate.wire_c == WireId::UNREACHABLE {
            return;
        }

        maybe_log_progress("evaluated", gate_id);

        let expected_label = halfgates_garbling::degarble_gate::<H>(
            gate.gate_type,
            || {
                self.consume_ciphertext()
                    .unwrap_or_else(|| panic!("Ciphertext source exhausted at gate {}", gate_id))
            },
            a.active_label,
            a.value,
            b.active_label,
            gate_id,
        );

        // Re-implement evaluation bound to streaming mode and raw labels.
        let expected_value = (gate.gate_type.f())(a.value, b.value);

        let c = EvaluatedWire {
            active_label: expected_label,
            value: expected_value,
        };

        self.feed_wire(gate.wire_c, c);
    }

    fn feed_wire(&mut self, wire_id: crate::WireId, value: Self::WireValue) {
        if matches!(wire_id, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }

        self.storage
            .set(wire_id, |val| {
                *val = Some(value);
            })
            .unwrap();
    }

    fn lookup_wire(&mut self, wire_id: crate::WireId) -> Option<Self::WireValue> {
        match wire_id {
            TRUE_WIRE => Some(self.true_value()),
            FALSE_WIRE => Some(self.false_value()),
            wire_id => match self.storage.get(wire_id).map(|ew| ew.to_owned()) {
                Ok(Some(ew)) => Some(ew),
                Ok(None) => panic!(
                    "Called `lookup_wire` for a WireId {wire_id} that was created but not initialized"
                ),
                Err(_) => None,
            },
        }
    }

    /// Bump remaining-use counters for `wires` by `credits`.
    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        for wire_id in wires {
            self.storage.add_credits(*wire_id, credits.get()).unwrap();
        }
    }

    fn finalize_ciphertext_accumulator(self) -> Self::CiphertextAcc {
        self.source.finalize()
    }
}

#[cfg(test)]
mod evaluate_test;
