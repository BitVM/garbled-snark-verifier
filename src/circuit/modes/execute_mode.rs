use std::num::NonZero;

use crate::{
    Gate, GateType, WireId,
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
    storage: Storage<WireId, Option<bool>>,
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
    type CiphertextAcc = ();

    #[inline]
    fn false_value(&self) -> bool {
        false
    }

    #[inline]
    fn true_value(&self) -> bool {
        true
    }

    /// Allocate a wire with its initial remaining-use counter (`credits`).
    #[inline]
    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(None, credits)
    }

    #[inline]
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

        // Inline gate evaluation to avoid indirect function pointer dispatch.
        #[inline(always)]
        fn eval(g: &GateType, a: bool, b: bool) -> bool {
            use GateType::*;
            match g {
                And => a & b,
                Nand => !(a & b),
                Nimp => a & !b,
                Imp => !a | b,
                Ncimp => !a & b,
                Cimp => !b | a,
                Nor => !(a | b),
                Or => a | b,
                Xor => a ^ b,
                Xnor => !(a ^ b),
                Not => !a,
            }
        }

        let c = eval(&gate.gate_type, a, b);
        self.feed_wire(gate.wire_c, c);
    }

    #[inline]
    fn lookup_wire(&mut self, wire_id: WireId) -> Option<Self::WireValue> {
        match wire_id {
            TRUE_WIRE => return Some(self.true_value()),
            FALSE_WIRE => return Some(self.false_value()),
            WireId::UNREACHABLE => return None,
            _ => (),
        }

        match self.storage.get(wire_id).as_deref() {
            Ok(Some(v)) => Some(*v),
            Ok(None) => uninit_wire_panic(wire_id),
            Err(StorageError::NotFound { .. }) => None,
            Err(StorageError::OverflowCredits) => panic!("overflow of credits!"),
        }
    }

    #[inline]
    fn feed_wire(&mut self, wire_id: WireId, value: Self::WireValue) {
        if matches!(wire_id, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }

        self.storage
            .set(wire_id, |entry| *entry = Some(value))
            .unwrap();
    }

    /// Bump remaining-use counters for `wires` by `credits`.
    #[inline]
    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        for wire in wires {
            self.storage.add_credits(*wire, credits.get()).unwrap();
        }
    }
}

#[cold]
#[inline(never)]
fn uninit_wire_panic(wire_id: WireId) -> ! {
    panic!("Called `lookup_wire` for a WireId {wire_id} that was created but not initialized")
}
