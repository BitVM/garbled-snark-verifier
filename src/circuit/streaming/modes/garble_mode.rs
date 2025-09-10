use std::{array, num::NonZero};

use crossbeam::channel;
use log::error;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::{
    Delta, GarbledWire, Gate, S, WireId,
    circuit::streaming::{CircuitMode, EncodeInput, FALSE_WIRE, TRUE_WIRE},
    core::{
        gate::{
            GarbleResult,
            garbling::{Blake3Hasher, GateHasher},
        },
        progress::maybe_log_progress,
    },
    storage::{Credits, Storage},
};

/// Type alias for GarbleMode with Blake3 hasher (default)
pub type GarbleModeBlake3 = GarbleMode<Blake3Hasher>;

// Note: We store only one label per wire (label0).
// The complementary label (label1) is restored on demand as label0 ^ delta.

/// Output type for garbled tables - only actual ciphertexts
pub type GarbledTableEntry = (usize, S);

/// Garble mode - generates garbled circuits with streaming output
pub struct GarbleMode<H: GateHasher = Blake3Hasher> {
    rng: ChaChaRng,
    delta: Delta,
    gate_index: usize,
    output_sender: channel::Sender<GarbledTableEntry>,
    // Store only label0 for each wire; reconstruct label1 as label0 ^ delta
    storage: Storage<WireId, Option<S>>,
    // Store the constant wires
    false_wire: GarbledWire,
    true_wire: GarbledWire,
    _hasher: std::marker::PhantomData<H>,
}

impl<H: GateHasher> GarbleMode<H> {
    pub fn new(
        capacity: usize,
        seed: u64,
        output_sender: channel::Sender<GarbledTableEntry>,
    ) -> Self {
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
            _hasher: std::marker::PhantomData,
        }
    }

    pub fn preallocate_input<I: EncodeInput<Self>>(seed: u64, i: &I) -> Vec<GarbledWire> {
        let (sender, _receiver) = channel::bounded(1);
        let mut self_ = Self::new(3200, seed, sender);

        let allocated = i.allocate(|| self_.allocate_wire(1));
        i.encode(&allocated, &mut self_);

        [FALSE_WIRE, TRUE_WIRE]
            .into_iter()
            .chain(I::collect_wire_ids(&allocated))
            .map(|wire_id| self_.lookup_wire(wire_id).unwrap())
            .collect()
    }

    pub fn issue_garbled_wire(&mut self) -> GarbledWire {
        GarbledWire::random(&mut self.rng, &self.delta)
    }

    fn next_gate_index(&mut self) -> usize {
        let index = self.gate_index;
        self.gate_index += 1;
        index
    }

    fn stream_table_entry(&mut self, gate_id: usize, entry: Option<S>) {
        if let Some(ciphertext) = entry
            && let Err(err) = self.output_sender.send((gate_id, ciphertext))
        {
            error!("Error while send gate_id {gate_id} ciphertext: {err}");
        }
    }
}

impl<H: GateHasher> std::fmt::Debug for GarbleMode<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarbleMode")
            .field("gate_index", &self.gate_index)
            .field("has_delta", &true)
            .finish()
    }
}

impl<H: GateHasher> CircuitMode for GarbleMode<H> {
    type WireValue = GarbledWire;

    fn false_value(&self) -> GarbledWire {
        self.false_wire.clone()
    }

    /// Allocate a wire with its initial remaining-use counter (`credits`).
    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(None, credits)
    }

    fn true_value(&self) -> GarbledWire {
        self.true_wire.clone()
    }

    fn evaluate_gate(&mut self, gate: &Gate) {
        // Always consume input credits by looking up A and B.
        let a = self.lookup_wire(gate.wire_a).unwrap();
        let b = self.lookup_wire(gate.wire_b).unwrap();

        // If C is unreachable, skip evaluation and do not advance gate index.
        if gate.wire_c == WireId::UNREACHABLE {
            return;
        }

        let gate_id = self.next_gate_index();

        maybe_log_progress("garbled", gate_id);

        let GarbleResult {
            result: c,
            ciphertext,
        } = gate.garble::<H>(gate_id, &a, &b, &self.delta).unwrap();

        // Stream the table entry if it exists
        self.stream_table_entry(gate_id, ciphertext);

        self.feed_wire(gate.wire_c, c);
    }

    fn feed_wire(&mut self, wire_id: crate::WireId, value: Self::WireValue) {
        if matches!(wire_id, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }

        // Persist only label0; label1 is restored as label0 ^ delta when needed
        self.storage
            .set(wire_id, |val| {
                *val = Some(value.label0);
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

        match self.storage.get(wire_id).map(|lbl0| lbl0.to_owned()) {
            Ok(Some(label0)) => Some(GarbledWire::new(label0, label0 ^ &self.delta)),
            Ok(None) => panic!(
                "Called `lookup_wire` for a WireId {wire_id} that was created but not initialized"
            ),
            Err(_) => None,
        }
    }

    /// Bump remaining-use counters for `wires` by `credits`.
    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        for wire_id in wires {
            self.storage.add_credits(*wire_id, credits.get()).unwrap();
        }
    }
}

#[cfg(test)]
mod garble_test;
