use std::{fmt, num::NonZero};

use crate::{Gate, WireId, storage::Credits};

mod execute_mode;
pub use execute_mode::{ExecuteMode, OptionalBoolean};
// Back-compat alias used widely in tests/gadgets
pub type Execute = crate::circuit::streaming::StreamingMode<ExecuteMode>;

// Collapse thin wrappers; tests live in mode files.

mod garble_mode;
pub use garble_mode::{GarbleMode, GarbleModeBlake3, OptionalGarbledWire};

// Collapse thin wrappers; tests live in mode files.

mod evaluate_mode;
pub use evaluate_mode::{EvaluateMode, EvaluateModeBlake3, OptionalEvaluatedWire};

/// Execution backends for the streaming circuit.
///
/// Credits vs fanout
/// - Fanout is computed during the metadata pass as the total number of downstream reads of a wire.
/// - At runtime, backends receive and manage "credits" — the remaining read budget — to allocate
///   storage and reclaim it precisely when the final read occurs.
pub trait CircuitMode: Sized + fmt::Debug {
    type WireValue: Clone;

    fn false_value(&self) -> Self::WireValue;

    fn true_value(&self) -> Self::WireValue;

    fn evaluate_gate(
        &mut self,
        gate: &Gate,
        a: Self::WireValue,
        b: Self::WireValue,
    ) -> Self::WireValue;

    fn allocate_wire(&mut self, credits: Credits) -> WireId;

    fn lookup_wire(&mut self, _wire: WireId) -> Option<Self::WireValue>;

    fn feed_wire(&mut self, _wire: WireId, _value: Self::WireValue);

    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>);
}

// Old Garble struct replaced by new streaming implementation in garble.rs and garble_mode.rs
// Old Evaluate struct replaced by new streaming implementation in evaluate.rs and evaluate_mode.rs
