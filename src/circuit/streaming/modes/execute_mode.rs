use crate::{Gate, circuit::streaming::CircuitMode};

/// Boolean value representation in storage
#[derive(Clone, Copy, Debug, Default)]
pub enum OptionalBoolean {
    #[default]
    None,
    True,
    False,
}

/// Execute mode - direct boolean evaluation
#[derive(Debug, Default)]
pub struct ExecuteMode;

impl CircuitMode for ExecuteMode {
    type WireValue = bool;
    type StorageValue = OptionalBoolean;

    fn false_value(&self) -> bool {
        false
    }

    fn true_value(&self) -> bool {
        true
    }

    fn default_storage_value() -> OptionalBoolean {
        OptionalBoolean::None
    }

    fn storage_to_wire(&self, stored: &OptionalBoolean) -> Option<bool> {
        match stored {
            OptionalBoolean::True => Some(true),
            OptionalBoolean::False => Some(false),
            OptionalBoolean::None => None,
        }
    }

    fn wire_to_storage(&self, value: bool) -> OptionalBoolean {
        if value {
            OptionalBoolean::True
        } else {
            OptionalBoolean::False
        }
    }

    fn evaluate_gate(&mut self, gate: &Gate, a: bool, b: bool) -> bool {
        gate.execute(a, b)
    }
}
