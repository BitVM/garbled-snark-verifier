use std::num::NonZero;

use crate::{
    Gate, WireId,
    circuit::streaming::{CircuitMode, FALSE_WIRE, TRUE_WIRE},
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
}

impl ExecuteMode {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            storage: Storage::new(capacity),
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

    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(OptionalBoolean::None, credits)
    }

    fn evaluate_gate(&mut self, gate: &Gate, a: bool, b: bool) -> bool {
        gate.execute(a, b)
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

    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        for wire in wires {
            self.storage.add_credits(*wire, credits.get()).unwrap();
        }
    }
}
