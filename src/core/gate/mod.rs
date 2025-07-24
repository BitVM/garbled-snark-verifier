use std::fmt;

use digest;
use log::debug;
use rand::Rng;

pub use crate::GateType;
use crate::{Delta, EvaluatedWire, GarbledWire, GarbledWires, WireError, WireId, S};

type DefaultHasher = blake3::Hasher;

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

    fn wire_a<'w>(
        &self,
        wires: &'w mut GarbledWires,
        issue_gwire_fn: &mut impl FnMut() -> GarbledWire,
    ) -> Result<&'w GarbledWire, Error> {
        wires
            .get_or_init(self.wire_a, issue_gwire_fn)
            .map_err(|err| Error::GetWire { wire: "a", err })
    }

    fn wire_b<'w>(
        &self,
        wires: &'w mut GarbledWires,
        issue_gwire_fn: &mut impl FnMut() -> GarbledWire,
    ) -> Result<&'w GarbledWire, Error> {
        wires
            .get_or_init(self.wire_b, issue_gwire_fn)
            .map_err(|err| Error::GetWire { wire: "b", err })
    }

    fn init_wire_c(&self, wires: &mut GarbledWires, label0: S, label1: S) -> Result<(), Error> {
        wires
            .init(self.wire_c, GarbledWire::new(label0, label1))
            .map_err(|err| Error::InitWire { wire: "c", err })
            .map(|_| ())
    }

    /// Return ciphertext for garble table if presented
    pub fn garble<H: digest::Digest + Default + Clone>(
        &self,
        gate_id: GateId,
        wires: &mut GarbledWires,
        delta: &Delta,
        rng: &mut impl Rng,
    ) -> Result<Option<S>, Error> {
        debug!(
            "gate_garble: {:?} {}+{}->{} gid={}",
            self.gate_type, self.wire_a, self.wire_b, self.wire_c, gate_id
        );

        let mut issue_fn = || GarbledWire::random(rng, delta);

        match self.gate_type {
            GateType::Xor => {
                let a_label0 = self.wire_a(wires, &mut issue_fn)?.select(false);
                let b_label0 = self.wire_b(wires, &mut issue_fn)?.select(false);

                let c_label0 = a_label0 ^ &b_label0;
                let c_label1 = c_label0 ^ delta;

                self.init_wire_c(wires, c_label0, c_label1)?;

                Ok(None)
            }
            GateType::Xnor => {
                let a_label0 = self.wire_a(wires, &mut issue_fn)?.select(false);
                let b_label0 = self.wire_b(wires, &mut issue_fn)?.select(false);

                let c_label0 = a_label0 ^ &b_label0 ^ delta;
                let c_label1 = c_label0 ^ delta;

                self.init_wire_c(wires, c_label0, c_label1)?;

                Ok(None)
            }
            GateType::Not => {
                assert_eq!(self.wire_a, self.wire_b);
                assert_eq!(self.wire_b, self.wire_c);

                self.wire_a(wires, &mut issue_fn)?;

                wires
                    .toggle_wire_not_mark(self.wire_c)
                    .map_err(|err| Error::InitWire { wire: "c", err })?;

                Ok(None)
            }
            _ => {
                let a = self.wire_a(wires, &mut issue_fn)?.clone();
                let b = self.wire_b(wires, &mut issue_fn)?;

                let (ciphertext, w0) = garble::<H>(gate_id, self.gate_type, &a, b, delta);

                self.init_wire_c(wires, w0, w0 ^ delta)?;

                Ok(Some(ciphertext))
            }
        }
    }

    pub fn evaluate(&self, a: &EvaluatedWire, b: &EvaluatedWire, c: &GarbledWire) -> EvaluatedWire {
        let evaluated_value = (self.gate_type.f())(a.value, b.value);

        EvaluatedWire {
            active_label: c.select(evaluated_value),
            value: evaluated_value,
        }
    }
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
    pub fn calculate_output(
        &self,
        gate_id: GateId,
        a: &EvaluatedWire,
        b: &EvaluatedWire,
        garble_table: &[S],
        table_gate_index: &mut usize,
    ) -> EvaluatedWire {
        let expected_value = (self.gate_type.f())(a.value, b.value);

        let expected_label = match self.gate_type {
            GateType::Xor => a.active_label ^ &b.active_label,
            GateType::Xnor => a.active_label ^ &b.active_label,
            GateType::Not => {
                // For NOT gates, all wires are the same, so return the input
                a.active_label
            }
            _ => {
                let ct = garble_table[*table_gate_index];
                *table_gate_index += 1;
                degarble::<DefaultHasher>(gate_id, self.gate_type, &ct, a, b)
            }
        };

        EvaluatedWire {
            active_label: expected_label,
            value: expected_value,
        }
    }

    pub fn check_correctness<'s, 'w>(
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

        log::debug!("gate_eval: {:?} a={:?} b={:?}", self.gate_type, a, b);

        let expected_output = self.calculate_output(gate_id, a, b, garble_table, table_gate_index);

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
                log::debug!("gate_eval: XOR result={:?}", expected_output.active_label);

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

mod garbling;
use garbling::{degarble, garble};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::test_utils::trng;

    const GATE_ID: GateId = 0;

    const TEST_CASES: [(bool, bool); 4] =
        [(false, false), (false, true), (true, false), (true, true)];

    fn create_test_delta() -> Delta {
        Delta::generate()
    }

    fn issue_test_wire() -> GarbledWires {
        GarbledWires::new(1000)
    }

    fn create_test_wire_ids() -> (WireId, WireId, WireId) {
        (WireId(0), WireId(1), WireId(2))
    }

    fn test_gate_e2e(gate: Gate, expected_fn: fn(bool, bool) -> bool, gate_name: &str) {
        let delta = create_test_delta();
        let mut wires = issue_test_wire();

        let table = gate
            .garble::<blake3::Hasher>(GATE_ID, &mut wires, &delta, &mut trng())
            .expect("Garbling should succeed")
            .map(|row| vec![row])
            .unwrap_or_default();

        let wire_a_garbled = wires.get(gate.wire_a).expect("Wire A should exist");
        let wire_b_garbled = wires.get(gate.wire_b).expect("Wire B should exist");
        let wire_c_garbled = wires.get(gate.wire_c).expect("Wire C should exist");

        for (input_a, input_b) in TEST_CASES {
            let eval_a = EvaluatedWire {
                active_label: wire_a_garbled.select(input_a),
                value: input_a,
            };
            let eval_b = EvaluatedWire {
                active_label: wire_b_garbled.select(input_b),
                value: input_b,
            };

            let eval_c = gate.evaluate(&eval_a, &eval_b, wire_c_garbled);

            let expected_output = expected_fn(input_a, input_b);
            assert_eq!(
                eval_c.value, expected_output,
                "Evaluation should be correct for {gate_name}({input_a}, {input_b})"
            );

            let mut evaluations = HashMap::new();
            evaluations.insert(gate.wire_a, eval_a);
            evaluations.insert(gate.wire_b, eval_b);
            evaluations.insert(gate.wire_c, eval_c);

            let mut table_index = 0;

            let correctness_result = gate.check_correctness(
                GATE_ID,
                &|wire_id: WireId| evaluations.get(&wire_id),
                &table,
                &mut table_index,
            );

            assert_eq!(
                correctness_result,
                Ok(()),
                "Correctness check should pass for {gate_name}({input_a}, {input_b})"
            );
        }
    }

    fn test_not_gate_e2e(gate: Gate) {
        let delta = create_test_delta();
        let mut wires = issue_test_wire();

        let table = gate
            .garble::<blake3::Hasher>(GATE_ID, &mut wires, &delta, &mut trng())
            .expect("Garbling should succeed")
            .map(|row| vec![row])
            .unwrap_or_default();

        let wire_garbled = wires.get(gate.wire_a).expect("Wire should exist");

        for input in [false, true] {
            let eval_wire = EvaluatedWire {
                active_label: wire_garbled.select(input),
                value: input,
            };

            let eval_c = gate.evaluate(&eval_wire, &eval_wire, wire_garbled);

            let expected_output = !input;
            assert_eq!(
                eval_c.value, expected_output,
                "Evaluation should be correct for NOT({input})"
            );

            let mut evaluations = HashMap::new();
            evaluations.insert(gate.wire_a, eval_wire.clone());
            evaluations.insert(gate.wire_b, eval_wire.clone());
            evaluations.insert(gate.wire_c, eval_wire);

            let mut table_index = 0;

            let correctness_result = gate.check_correctness(
                GATE_ID,
                &|wire_id: WireId| evaluations.get(&wire_id),
                &table,
                &mut table_index,
            );

            assert_eq!(
                correctness_result,
                Ok(()),
                "Correctness check should pass for NOT({input})"
            );
        }
    }

    #[test]
    fn test_and_gate() {
        let (wire_a, wire_b, wire_c) = create_test_wire_ids();
        let gate = Gate::and(wire_a, wire_b, wire_c);
        test_gate_e2e(gate, |a, b| a && b, "AND");
    }

    #[test]
    fn test_nand_gate() {
        let (wire_a, wire_b, wire_c) = create_test_wire_ids();
        let gate = Gate::nand(wire_a, wire_b, wire_c);
        test_gate_e2e(gate, |a, b| !(a && b), "NAND");
    }

    #[test]
    fn test_nimp_gate() {
        let (wire_a, wire_b, wire_c) = create_test_wire_ids();
        let gate = Gate::nimp(wire_a, wire_b, wire_c);
        test_gate_e2e(gate, |a, b| a && !b, "NIMP");
    }

    #[test]
    fn test_imp_gate() {
        let (wire_a, wire_b, wire_c) = create_test_wire_ids();
        let gate = Gate::imp(wire_a, wire_b, wire_c);
        test_gate_e2e(gate, |a, b| !a || b, "IMP");
    }

    #[test]
    fn test_ncimp_gate() {
        let (wire_a, wire_b, wire_c) = create_test_wire_ids();
        let gate = Gate::ncimp(wire_a, wire_b, wire_c);
        test_gate_e2e(gate, |a, b| !a && b, "NCIMP");
    }

    #[test]
    fn test_cimp_gate() {
        let (wire_a, wire_b, wire_c) = create_test_wire_ids();
        let gate = Gate::cimp(wire_a, wire_b, wire_c);
        test_gate_e2e(gate, |a, b| !b || a, "CIMP");
    }

    #[test]
    fn test_nor_gate() {
        let (wire_a, wire_b, wire_c) = create_test_wire_ids();
        let gate = Gate::nor(wire_a, wire_b, wire_c);
        test_gate_e2e(gate, |a, b| !(a || b), "NOR");
    }

    #[test]
    fn test_or_gate() {
        let (wire_a, wire_b, wire_c) = create_test_wire_ids();
        let gate = Gate::or(wire_a, wire_b, wire_c);
        test_gate_e2e(gate, |a, b| a || b, "OR");
    }

    #[test]
    fn test_xor_gate() {
        let (wire_a, wire_b, wire_c) = create_test_wire_ids();
        let gate = Gate::xor(wire_a, wire_b, wire_c);
        test_gate_e2e(gate, |a, b| a ^ b, "XOR");
    }

    #[test]
    fn test_xnor_gate() {
        let (wire_a, wire_b, wire_c) = create_test_wire_ids();
        let gate = Gate::xnor(wire_a, wire_b, wire_c);
        test_gate_e2e(gate, |a, b| !(a ^ b), "XNOR");
    }

    #[test]
    fn test_not_gate() {
        let mut wire_a = WireId(0);
        let gate = Gate::not(&mut wire_a);
        test_not_gate_e2e(gate);
    }
}
