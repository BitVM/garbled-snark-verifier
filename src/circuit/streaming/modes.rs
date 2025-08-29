use std::{fmt, num::NonZero};

use crate::{Gate, WireId, storage::Credits};

mod streaming_mode;
pub use streaming_mode::Execute;

mod execute_mode;
pub use execute_mode::{ExecuteMode, OptionalBoolean};

mod garble;
pub use garble::Garble;

mod garble_mode;
pub use garble_mode::{GarbleMode, GarbleModeBlake3, OptionalGarbledWire};

mod evaluate;
pub use evaluate::Evaluate;

mod evaluate_mode;
pub use evaluate_mode::{EvaluateMode, EvaluateModeBlake3, OptionalEvaluatedWire};

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
