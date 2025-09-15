use std::num::NonZero;

use crate::{
    Gate, WireId,
    circuit::{CircuitMode, FALSE_WIRE, TRUE_WIRE},
    core::progress::maybe_log_progress,
    storage::{Credits, Error as StorageError, Storage},
};

/// Boolean value representation in storage
#[derive(Clone, Copy, Debug, Default)]
pub enum OptionalBoolean {
    #[default]
    None,
    True,
    False,
}

/// Execute mode - direct boolean evaluation
#[derive(Debug)]
pub struct ExecuteMode {
    storage: Storage<WireId, OptionalBoolean>,
    gate_index: usize,
}

impl ExecuteMode {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            storage: Storage::new(capacity),
            gate_index: 0,
        }
    }
}

impl CircuitMode for ExecuteMode {
    type WireValue = bool;

    fn false_value(&self) -> bool {
        false
    }

    fn true_value(&self) -> bool {
        true
    }

    /// Allocate a wire with its initial remaining-use counter (`credits`).
    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(OptionalBoolean::None, credits)
    }

    fn evaluate_gate(&mut self, gate: &Gate) {
        // Always consume input credits by looking up A and B.
        let a = self.lookup_wire(gate.wire_a).unwrap();
        let b = self.lookup_wire(gate.wire_b).unwrap();

        // If C is unreachable, skip evaluation and do not advance gate index.
        if gate.wire_c == WireId::UNREACHABLE {
            return;
        }

        maybe_log_progress("executed", self.gate_index);
        self.gate_index += 1;

        let c = gate.execute(a, b);
        self.feed_wire(gate.wire_c, c);
    }

    fn lookup_wire(&mut self, wire_id: WireId) -> Option<Self::WireValue> {
        match wire_id {
            TRUE_WIRE => return Some(self.true_value()),
            FALSE_WIRE => return Some(self.false_value()),
            WireId::UNREACHABLE => return None,
            _ => (),
        }

        match self.storage.get(wire_id).as_deref() {
            Ok(OptionalBoolean::True) => Some(true),
            Ok(OptionalBoolean::False) => Some(false),
            Ok(OptionalBoolean::None) => panic!(
                "Called `lookup_wire` for a WireId {wire_id} that was created but not initialized"
            ),
            Err(StorageError::NotFound { .. }) => None,
            Err(StorageError::OverflowCredits) => panic!("overflow of credits!"),
        }
    }

    fn feed_wire(&mut self, wire_id: WireId, value: Self::WireValue) {
        if matches!(wire_id, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }

        self.storage
            .set(wire_id, |entry| {
                if value {
                    *entry = OptionalBoolean::True;
                } else {
                    *entry = OptionalBoolean::False;
                }
            })
            .unwrap();
    }

    /// Bump remaining-use counters for `wires` by `credits`.
    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        for wire in wires {
            self.storage.add_credits(*wire, credits.get()).unwrap();
        }
    }
}
