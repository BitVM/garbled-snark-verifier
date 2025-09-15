use std::{array, marker::PhantomData, num::NonZero};

use crossbeam::channel;
use log::error;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::{
    Delta, Gate, S, WireId,
    circuit::{CircuitMode, EncodeInput, FALSE_WIRE, TRUE_WIRE},
    core::progress::maybe_log_progress,
    hashers,
    storage::{Credits, Storage},
};

// Module-scoped garbling/degargbling operations bound to streaming garble mode.
// Operate on raw labels (S) and tweak with gate_id. Keep hot path inlined.
pub(crate) mod halfgates_garbling;

// Public GarbledWire type colocated with garbling logic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GarbledWire {
    pub label0: S,
    pub label1: S,
}

impl GarbledWire {
    #[inline]
    pub(crate) fn new(label0: S, label1: S) -> Self {
        GarbledWire { label0, label1 }
    }

    #[inline]
    pub fn toggle_not(&mut self) {
        core::mem::swap(&mut self.label1, &mut self.label0);
    }

    #[inline]
    pub fn random(rng: &mut impl rand::Rng, delta: &Delta) -> Self {
        let label0 = S::random(rng);
        GarbledWire {
            label0,
            label1: label0 ^ delta,
        }
    }

    #[inline]
    pub fn select(&self, bit: bool) -> S {
        if bit { self.label1 } else { self.label0 }
    }
}

impl Default for GarbledWire {
    fn default() -> Self {
        GarbledWire {
            label0: S::ZERO,
            label1: S::ZERO,
        }
    }
}

/// Type alias for GarbleMode with Blake3 hasher (default)
pub type GarbleModeBlake3 = GarbleMode<hashers::Blake3Hasher>;

// Note: We store only one label per wire (label0).
// The complementary label (label1) is restored on demand as label0 ^ delta.

/// Output type for garbled tables - only actual ciphertexts
pub type GarbledTableEntry = (usize, S);

/// Garble mode - generates garbled circuits with streaming output
pub struct GarbleMode<H: hashers::GateHasher = hashers::Blake3Hasher> {
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

impl<H: hashers::GateHasher> GarbleMode<H> {
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
            _hasher: PhantomData,
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
        let Some(ciphertext) = entry else {
            return;
        };

        if let Err(err) = self.output_sender.send((gate_id, ciphertext)) {
            error!("Error while send gate_id {gate_id} ciphertext: {err}");
        }
    }
}

impl<H: crate::hashers::GateHasher> std::fmt::Debug for GarbleMode<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarbleMode")
            .field("gate_index", &self.gate_index)
            .field("has_delta", &true)
            .finish()
    }
}

impl<H: crate::hashers::GateHasher> CircuitMode for GarbleMode<H> {
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
        // Consume input credits by reading label0 directly (without reconstructing full wires).
        //
        // NOTE: must consume credits even if C is UNREACHABLE to match previous behavior
        // and keep storage occupancy bounded.
        // Constants: pass base label0 for both FALSE and TRUE.
        // Half-gates selection handles Δ internally; providing label1 here would swap α semantics.
        let a_label0 = match gate.wire_a {
            FALSE_WIRE => self.false_wire.label0,
            TRUE_WIRE => self.true_wire.label0,
            _ => match self.storage.get(gate.wire_a).map(|d| d.to_owned()) {
                Ok(Some(base)) => base,
                Ok(None) => panic!(
                    "Called evaluate_gate for WireId {:?} that was created but not initialized",
                    gate.wire_a
                ),
                Err(_) => panic!("Can't find wire_a {:?}", gate.wire_a),
            },
        };

        let b_label0 = match gate.wire_b {
            FALSE_WIRE => self.false_wire.label0,
            TRUE_WIRE => self.true_wire.label0,
            _ => match self.storage.get(gate.wire_b).map(|d| d.to_owned()) {
                Ok(Some(base)) => base,
                Ok(None) => panic!(
                    "Called evaluate_gate for WireId {:?} that was created but not initialized",
                    gate.wire_b
                ),
                Err(_) => panic!("Can't find wire_b {:?}", gate.wire_b),
            },
        };

        let gate_id = self.next_gate_index();

        // If C is unreachable, skip evaluation and do not advance gate index.
        if gate.wire_c == WireId::UNREACHABLE {
            return;
        }

        maybe_log_progress("garbled", gate_id);

        let (c_base, ciphertext): (S, Option<S>) = halfgates_garbling::garble_gate::<H>(
            gate.gate_type,
            a_label0,
            b_label0,
            &self.delta,
            gate_id,
        );

        // Stream the table entry if it exists
        self.stream_table_entry(gate_id, ciphertext);

        assert_ne!(gate.wire_c, FALSE_WIRE);
        assert_ne!(gate.wire_c, TRUE_WIRE);
        assert_ne!(gate.wire_c, WireId::UNREACHABLE);

        // Persist only label0; guard constants/unreachable
        self.storage
            .set(gate.wire_c, |slot| {
                *slot = Some(c_base);
            })
            .unwrap();
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
