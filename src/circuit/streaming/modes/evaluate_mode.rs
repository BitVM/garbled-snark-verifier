use std::num::NonZero;

use crossbeam::channel;
use log::{debug, error, info};

use crate::{
    EvaluatedWire, Gate, S, WireId,
    circuit::streaming::{CircuitMode, FALSE_WIRE, TRUE_WIRE},
    core::gate::garbling::{Blake3Hasher, GateHasher, degarble},
    storage::{Credits, Storage},
};

/// Type alias for EvaluateMode with Blake3 hasher (default)
pub type EvaluateModeBlake3 = EvaluateMode<Blake3Hasher>;

/// Storage representation for evaluated wires
#[derive(Clone, Debug, Default)]
pub struct OptionalEvaluatedWire {
    pub wire: Option<EvaluatedWire>,
}

/// Input type for ciphertext consumption - gate ID and ciphertext
pub type CiphertextEntry = (usize, S);

/// Evaluate mode - consumes garbled circuits with streaming ciphertext input
pub struct EvaluateMode<H: GateHasher = Blake3Hasher> {
    gate_index: usize,
    ciphertext_receiver: channel::Receiver<CiphertextEntry>,
    storage: Storage<WireId, Option<EvaluatedWire>>,
    // Store the constant wires (provided externally)
    false_wire: EvaluatedWire,
    true_wire: EvaluatedWire,
    _hasher: std::marker::PhantomData<H>,
}

impl<H: GateHasher> EvaluateMode<H> {
    pub fn new(
        capacity: usize,
        true_wire: EvaluatedWire,
        false_wire: EvaluatedWire,
        ciphertext_receiver: channel::Receiver<CiphertextEntry>,
    ) -> Self {
        Self {
            storage: Storage::new(capacity),
            gate_index: 0,
            ciphertext_receiver,
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

    fn consume_ciphertext(&mut self, gate_id: usize) -> Option<S> {
        // Block and wait to receive the ciphertext for this gate
        match self.ciphertext_receiver.recv() {
            Ok((received_gate_id, ciphertext)) => {
                if received_gate_id == gate_id {
                    Some(ciphertext)
                } else {
                    error!(
                        "Ciphertext gate ID mismatch: expected {}, got {}",
                        gate_id, received_gate_id
                    );
                    None
                }
            }
            Err(channel::RecvError) => {
                error!("Ciphertext channel disconnected at gate {}", gate_id);
                None
            }
        }
    }
}

impl<H: GateHasher> std::fmt::Debug for EvaluateMode<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EvaluateMode")
            .field("gate_index", &self.gate_index)
            .field("has_constants", &true)
            .finish()
    }
}

impl<H: GateHasher> CircuitMode for EvaluateMode<H> {
    type WireValue = EvaluatedWire;

    fn false_value(&self) -> EvaluatedWire {
        self.false_wire.clone()
    }

    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(None, credits)
    }

    fn true_value(&self) -> EvaluatedWire {
        self.true_wire.clone()
    }

    fn evaluate_gate(&mut self, gate: &Gate, a: EvaluatedWire, b: EvaluatedWire) -> EvaluatedWire {
        let gate_id = self.next_gate_index();

        if gate_id % 10_000_000 == 0 {
            fn format_gate_id(gate_id: u64) -> String {
                const THOUSAND: u64 = 1_000;
                const MILLION: u64 = 1_000_000;
                const BILLION: u64 = 1_000_000_000;
                const TRILLION: u64 = 1_000_000_000_000;

                match gate_id {
                    n if n >= TRILLION => format!("{:.1}t", n as f64 / TRILLION as f64),
                    n if n >= BILLION => format!("{:.1}b", n as f64 / BILLION as f64),
                    n if n >= MILLION => format!("{:.1}m", n as f64 / MILLION as f64),
                    n if n >= THOUSAND => format!("{:.1}k", n as f64 / THOUSAND as f64),
                    _ => format!("{}", gate_id),
                }
            }

            info!("evaluated: {}", format_gate_id(gate_id as u64))
        }

        debug!(
            "evaluate_gate: {:?} {}+{}->{} gid={}",
            gate.gate_type, gate.wire_a, gate.wire_b, gate.wire_c, gate_id
        );

        // This follows the same logic as garble_mode but for evaluation
        match gate.gate_type {
            crate::GateType::Xor => {
                // Free-XOR: c = a ⊕ b (both labels and values)
                let c_label = a.active_label ^ &b.active_label;
                let c_value = a.value ^ b.value;
                EvaluatedWire {
                    active_label: c_label,
                    value: c_value,
                }
            }
            crate::GateType::Xnor => {
                // Free-XOR with negation: c = ¬(a ⊕ b)
                let c_label = a.active_label ^ &b.active_label;
                let c_value = !(a.value ^ b.value);
                // Note: In XNOR, if the plaintext result is negated,
                // the garbled result should also account for delta XOR
                EvaluatedWire {
                    active_label: c_label,
                    value: c_value,
                }
            }
            crate::GateType::Not => {
                // NOT gate: swap the semantic meaning
                // The label stays the same but represents the opposite value
                EvaluatedWire {
                    active_label: a.active_label,
                    value: !a.value,
                }
            }
            _ => {
                // All other gates use half-gate degarbling
                let ciphertext = self
                    .consume_ciphertext(gate_id)
                    .unwrap_or_else(|| panic!("Failed to get ciphertext for gate {}", gate_id));

                let c_label = degarble::<H>(gate_id, gate.gate_type, &ciphertext, &a, &b);

                // Compute the plaintext result for verification
                let c_value = gate.gate_type.f()(a.value, b.value);

                EvaluatedWire {
                    active_label: c_label,
                    value: c_value,
                }
            }
        }
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
            TRUE_WIRE => {
                return Some(self.true_value());
            }
            FALSE_WIRE => {
                return Some(self.false_value());
            }
            _ => (),
        }

        match self.storage.get(wire_id).map(|ew| ew.to_owned()) {
            Ok(Some(ew)) => Some(ew),
            Ok(None) => panic!(
                "Called `lookup_wire` for a WireId {wire_id} that was created but not initialized"
            ),
            Err(_) => None,
        }
    }

    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        for wire_id in wires {
            self.storage.add_credits(*wire_id, credits.get()).unwrap();
        }
    }
}
