use std::fmt;

pub use crate::GateType;
use crate::{WireId, circuit::TRUE_WIRE};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gate {
    pub wire_a: WireId,
    pub wire_b: WireId,
    pub wire_c: WireId,
    pub gate_type: GateType,
}

impl fmt::Display for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} {} {} {}",
            &self.gate_type, self.wire_a, self.wire_b, self.wire_c
        )
    }
}

impl Gate {
    #[must_use]
    pub fn new(t: GateType, a: WireId, b: WireId, c: WireId) -> Self {
        Self {
            wire_a: a,
            wire_b: b,
            wire_c: c,
            gate_type: t,
        }
    }

    #[must_use]
    pub fn and(wire_a: WireId, wire_b: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type: GateType::And,
        }
    }

    #[must_use]
    pub fn nand(wire_a: WireId, wire_b: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type: GateType::Nand,
        }
    }

    #[must_use]
    pub fn nimp(wire_a: WireId, wire_b: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type: GateType::Nimp,
        }
    }

    #[must_use]
    pub fn imp(wire_a: WireId, wire_b: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type: GateType::Imp,
        }
    }

    #[must_use]
    pub fn ncimp(wire_a: WireId, wire_b: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type: GateType::Ncimp,
        }
    }

    #[must_use]
    pub fn cimp(wire_a: WireId, wire_b: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type: GateType::Cimp,
        }
    }

    #[must_use]
    pub fn nor(wire_a: WireId, wire_b: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type: GateType::Nor,
        }
    }

    #[must_use]
    pub fn or(wire_a: WireId, wire_b: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type: GateType::Or,
        }
    }

    #[must_use]
    pub fn xor(wire_a: WireId, wire_b: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type: GateType::Xor,
        }
    }

    #[must_use]
    pub fn xnor(wire_a: WireId, wire_b: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b,
            wire_c,
            gate_type: GateType::Xnor,
        }
    }

    #[must_use]
    pub fn not(wire_a: &mut WireId) -> Self {
        let wire_a = *wire_a;
        Self {
            wire_a,
            wire_b: wire_a,
            wire_c: wire_a,
            gate_type: GateType::Not,
        }
    }

    #[must_use]
    pub fn not_with_xor(wire_a: WireId, wire_c: WireId) -> Self {
        Self {
            wire_a,
            wire_b: TRUE_WIRE,
            wire_c,
            gate_type: GateType::Xor,
        }
    }

    /// Creates an AND-variant gate with configurable boolean function.                                                                                      │ │
    ///                                                                                                                                                      │ │
    /// This function implements the formula: `((a XOR f[0]) AND (b XOR f[1])) XOR f[2]`                                                                     │ │
    /// where the 3-bit encoding `f` determines which of the 8 AND-variant gate types to create.                                                             │ │
    ///                                                                                                                                                      │ │
    /// # Arguments                                                                                                                                          │ │
    ///                                                                                                                                                      │ │
    /// * `wire_a` - First input wire                                                                                                                        │ │
    /// * `wire_b` - Second input wire                                                                                                                       │ │
    /// * `wire_c` - Output wire                                                                                                                             │ │
    /// * `f` - 3-bit encoding array `[f0, f1, f2]` that determines the gate type:                                                                           │ │
    ///   - `[0,0,0]` → AND gate                                                                                                                             │ │
    ///   - `[0,0,1]` → NAND gate                                                                                                                            │ │
    ///   - `[0,1,0]` → NIMP gate (A AND NOT B)                                                                                                              │ │
    ///   - `[0,1,1]` → IMP gate (A implies B)                                                                                                               │ │
    ///   - `[1,0,0]` → NCIMP gate (NOT A AND B)                                                                                                             │ │
    ///   - `[1,0,1]` → CIMP gate (B implies A)                                                                                                              │ │
    ///   - `[1,1,0]` → NOR gate                                                                                                                             │ │
    ///   - `[1,1,1]` → OR gate                                                                                                                              │ │
    ///
    /// # Returns                                                                                                                                            │ │
    ///                                                                                                                                                      │ │
    /// A new `Gate` instance with the specified wires and gate type.                                                                                        │ │
    #[must_use]
    pub fn and_variant(a: WireId, b: WireId, c: WireId, f: [bool; 3]) -> Self {
        Self::new(
            match f {
                [false, false, false] => GateType::And,
                [false, false, true] => GateType::Nand,
                [false, true, false] => GateType::Nimp,
                [false, true, true] => GateType::Imp,
                [true, false, false] => GateType::Ncimp,
                [true, false, true] => GateType::Cimp,
                [true, true, false] => GateType::Nor,
                [true, true, true] => GateType::Or,
            },
            a,
            b,
            c,
        )
    }

    pub fn is_free(&self) -> bool {
        self.gate_type.is_free()
    }

    pub fn execute(&self, a: bool, b: bool) -> bool {
        self.gate_type.f()(a, b)
    }
}
