use std::fmt;

pub use crate::GateType;
use crate::{Delta, EvaluatedWire, GarbledWire, S, WireError, WireId};
pub mod garbling;
use garbling::{Blake3Hasher, GateHasher, degarble, garble};

pub type DefaultHasher = Blake3Hasher;

pub type GateId = usize;

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("Error while get wire {wire}: {err:?}")]
    GetWire { wire: &'static str, err: WireError },
    #[error("Error while init wire {wire}: {err:?}")]
    InitWire { wire: &'static str, err: WireError },
    #[error("Error while get_or_init wire {wire}: {err:?}")]
    GetOrInitWire { wire: &'static str, err: WireError },
}
pub type GateError = Error;

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

    /// Return ciphertext for garble table if presented
    pub fn garble<H: GateHasher>(
        &self,
        gate_id: GateId,
        a: &GarbledWire,
        b: &GarbledWire,
        delta: &Delta,
    ) -> Result<GarbleResult, Error> {
        match self.gate_type {
            GateType::Xor => {
                let a_label0 = a.select(false);
                let b_label0 = b.select(false);

                let c_label0 = a_label0 ^ &b_label0;
                let c_label1 = c_label0 ^ delta;

                Ok(GarbleResult {
                    result: GarbledWire::new(c_label0, c_label1),
                    ciphertext: None,
                })
            }
            GateType::Xnor => {
                let a_label0 = a.select(false);
                let b_label0 = b.select(false);

                let c_label0 = a_label0 ^ &b_label0 ^ delta;
                let c_label1 = c_label0 ^ delta;

                Ok(GarbleResult {
                    result: GarbledWire::new(c_label0, c_label1),
                    ciphertext: None,
                })
            }
            GateType::Not => {
                assert_eq!(self.wire_a, self.wire_b);
                assert_eq!(self.wire_b, self.wire_c);

                Ok(GarbleResult {
                    result: GarbledWire {
                        label0: a.label1,
                        label1: a.label0,
                    },
                    ciphertext: None,
                })
            }
            _ => {
                let (ciphertext, w0) = garble::<H>(gate_id, self.gate_type, a, b, delta);

                Ok(GarbleResult {
                    result: GarbledWire::new(w0, w0 ^ delta),
                    ciphertext: Some(ciphertext),
                })
            }
        }
    }

    pub fn evaluate_with_garbled_wire(
        &self,
        a: &EvaluatedWire,
        b: &EvaluatedWire,
        c: &GarbledWire,
    ) -> EvaluatedWire {
        let evaluated_value = (self.gate_type.f())(a.value, b.value);

        EvaluatedWire {
            active_label: c.select(evaluated_value),
            value: evaluated_value,
        }
    }

    pub fn execute(&self, a: bool, b: bool) -> bool {
        self.gate_type.f()(a, b)
    }
}

pub struct GarbleResult {
    pub result: GarbledWire,
    pub ciphertext: Option<S>,
}

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum CorrectnessError {
    #[error("Gate {0} is not calculated but already requested")]
    NotEvaluated(WireId),
    #[error("Gate verification failed: computed {calculated}, expected {actual}")]
    Value { calculated: bool, actual: bool },
    #[error("XOR gate label mismatch: computed {calculated:?}, expected {actual:?}")]
    XorLabel { calculated: S, actual: S },
    #[error("XNOR gate label mismatch: computed {calculated:?}, expected {actual:?}")]
    XnorLabel { calculated: S, actual: S },

    #[error("NOT gate label verification failed: wires A={a:?}, B={b:?}, C={c:?}")]
    NotLabel {
        a: EvaluatedWire,
        b: EvaluatedWire,
        c: EvaluatedWire,
    },

    #[error(
        "Garbled table mismatch at row {table_row:#?}: expected {evaluated_c_label:?}, got table entry {c:#?}"
    )]
    TableMismatch {
        table_row: S,
        a: EvaluatedWire,
        b: EvaluatedWire,
        c: EvaluatedWire,
        evaluated_c_label: S,
    },
}

impl Gate {
    /// Calculate the expected output value and label for this gate
    pub fn evaluate<H: GateHasher>(
        &self,
        gate_id: GateId,
        a: &EvaluatedWire,
        b: &EvaluatedWire,
        get_ciphertext: impl FnOnce() -> S,
    ) -> EvaluatedWire {
        let expected_value = (self.gate_type.f())(a.value, b.value);

        let expected_label = match self.gate_type {
            GateType::Xor => a.active_label ^ &b.active_label,
            GateType::Xnor => a.active_label ^ &b.active_label,
            GateType::Not => {
                // For NOT gates, all wires are the same, so return the input
                a.active_label
            }
            _ => degarble::<H>(gate_id, self.gate_type, &get_ciphertext(), a, b),
        };

        EvaluatedWire {
            active_label: expected_label,
            value: expected_value,
        }
    }

    pub fn check_correctness<'s, 'w, H: GateHasher>(
        &'s self,
        gate_id: GateId,
        get_evaluated: &impl Fn(WireId) -> Option<&'w EvaluatedWire>,
        garble_table: &[S],
        table_gate_index: &mut usize,
    ) -> Result<(), Vec<CorrectnessError>> {
        let a = get_evaluated(self.wire_a);
        let b = get_evaluated(self.wire_b);
        let c = get_evaluated(self.wire_c);

        let mut errors = vec![];

        let (a, b, c) = match (a, b, c) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            (a, b, c) => {
                if a.is_none() {
                    errors.push(CorrectnessError::NotEvaluated(self.wire_a));
                }

                if b.is_none() {
                    errors.push(CorrectnessError::NotEvaluated(self.wire_b));
                }

                if c.is_none() {
                    errors.push(CorrectnessError::NotEvaluated(self.wire_c));
                }

                return Err(errors);
            }
        };

        let expected_output = self.evaluate::<H>(gate_id, a, b, || {
            let index = *table_gate_index;
            *table_gate_index += 1;
            garble_table[index]
        });

        // Check value correctness (skip for NOT gates as they're self-referential)
        if GateType::Not != self.gate_type && expected_output.value != c.value {
            errors.push(CorrectnessError::Value {
                calculated: expected_output.value,
                actual: c.value,
            })
        }

        // Check label correctness based on gate type
        match self.gate_type {
            GateType::Xor => {
                if expected_output.active_label != c.active_label {
                    errors.push(CorrectnessError::XorLabel {
                        calculated: expected_output.active_label,
                        actual: c.active_label,
                    })
                }
            }
            GateType::Xnor => {
                if expected_output.active_label != c.active_label {
                    errors.push(CorrectnessError::XnorLabel {
                        calculated: expected_output.active_label,
                        actual: c.active_label,
                    })
                }
            }
            GateType::Not => {
                if a != b || b != c {
                    errors.push(CorrectnessError::NotLabel {
                        a: a.clone(),
                        b: b.clone(),
                        c: c.clone(),
                    })
                }
            }
            _ => {
                if expected_output.active_label != c.active_label {
                    errors.push(CorrectnessError::TableMismatch {
                        table_row: garble_table[*table_gate_index - 1],
                        a: a.clone(),
                        b: b.clone(),
                        c: c.clone(),
                        evaluated_c_label: expected_output.active_label,
                    })
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests;
