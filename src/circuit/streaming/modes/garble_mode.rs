use std::{array, num::NonZero, sync::mpsc};

use log::{debug, error};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::{
    Delta, GarbledWire, Gate, S, WireId,
    circuit::streaming::{CircuitMode, FALSE_WIRE, TRUE_WIRE},
    core::gate::garbling::{Blake3Hasher, garble},
    storage::{Credits, Storage},
};

/// Storage representation for garbled wires
#[derive(Clone, Debug, Default)]
pub struct OptionalGarbledWire {
    pub wire: Option<GarbledWire>,
}

/// Output type for garbled tables - only actual ciphertexts
pub type GarbledTableEntry = (usize, S);

/// Garble mode - generates garbled circuits with streaming output
pub struct GarbleMode {
    rng: ChaChaRng,
    delta: Delta,
    gate_index: usize,
    output_sender: mpsc::Sender<GarbledTableEntry>,
    storage: Storage<WireId, Option<GarbledWire>>,
    // Store the constant wires
    false_wire: GarbledWire,
    true_wire: GarbledWire,
}

impl GarbleMode {
    pub fn new(capacity: usize, seed: u64, output_sender: mpsc::Sender<GarbledTableEntry>) -> Self {
        let mut rng = ChaChaRng::seed_from_u64(seed);
        let delta = Delta::generate(&mut rng);

        // Generate constant wires like the original Garble does
        let [false_wire, true_wire] = array::from_fn(|_| GarbledWire::random(&mut rng, &delta));

        Self {
            storage: Storage::new(capacity),
            rng,
            delta,
            gate_index: 0,
            output_sender,
            false_wire,
            true_wire,
        }
    }

    fn next_gate_index(&mut self) -> usize {
        let index = self.gate_index;
        self.gate_index += 1;
        index
    }

    fn stream_table_entry(&mut self, gate_id: usize, entry: Option<S>) {
        // Only send actual ciphertext entries, not None for free gates
        if let Some(ciphertext) = entry {
            // Ignore send errors - receiver might have dropped
            if let Err(err) = self.output_sender.send((gate_id, ciphertext)) {
                error!("Error while send gate_id {gate_id} ciphertext: {err}");
            }
        }
    }
}

impl std::fmt::Debug for GarbleMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarbleMode")
            .field("gate_index", &self.gate_index)
            .field("has_delta", &true)
            .finish()
    }
}

impl CircuitMode for GarbleMode {
    type WireValue = GarbledWire;

    fn false_value(&self) -> GarbledWire {
        self.false_wire.clone()
    }

    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(None, credits)
    }

    fn true_value(&self) -> GarbledWire {
        self.true_wire.clone()
    }

    fn evaluate_gate(&mut self, gate: &Gate, a: GarbledWire, b: GarbledWire) -> GarbledWire {
        let gate_id = self.next_gate_index();

        debug!(
            "garble_gate: {:?} {}+{}->{} gid={}",
            gate.gate_type, gate.wire_a, gate.wire_b, gate.wire_c, gate_id
        );

        // This follows the same logic as Gate::garble but adapted for streaming
        let (c, table_entry) = match gate.gate_type {
            crate::GateType::Xor => {
                // Free-XOR: c = a ⊕ b
                let c_label0 = a.label0 ^ &b.label0;
                let c_label1 = c_label0 ^ &self.delta;
                let c = GarbledWire::new(c_label0, c_label1);
                (c, None)
            }
            crate::GateType::Xnor => {
                // Free-XOR with negation: c = ¬(a ⊕ b)
                let c_label0 = a.label0 ^ &b.label0 ^ &self.delta;
                let c_label1 = c_label0 ^ &self.delta;
                let c = GarbledWire::new(c_label0, c_label1);
                (c, None)
            }
            crate::GateType::Not => {
                // NOT gate: just swap the labels
                // In the original code this modifies the wire in place via toggle_not
                // Here we return a new wire with swapped labels
                let c = GarbledWire::new(a.label1, a.label0);
                (c, None)
            }
            _ => {
                // All other gates use half-gate garbling
                let (ciphertext, w0) =
                    garble::<Blake3Hasher>(gate_id, gate.gate_type, &a, &b, &self.delta);

                let c = GarbledWire::new(w0, w0 ^ &self.delta);
                (c, Some(ciphertext))
            }
        };

        // Stream the table entry if it exists
        self.stream_table_entry(gate_id, table_entry);

        c
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

        match self.storage.get(wire_id).map(|gw| gw.to_owned()) {
            Ok(Some(gw)) => Some(gw),
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
