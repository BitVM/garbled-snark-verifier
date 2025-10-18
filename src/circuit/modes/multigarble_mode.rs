use std::{array, marker::PhantomData, num::NonZero};

use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::{
    Delta, Gate, GateType, S, WireId,
    circuit::{CircuitMode, FALSE_WIRE, MultiCiphertextHandler, TRUE_WIRE},
    core::progress::maybe_log_progress,
    hashers::GateHasher,
    storage::{Credits, Storage},
};

use super::garble_mode::{GarbledWire, halfgates_garbling};

#[derive(Debug)]
struct LaneCtx {
    rng: ChaChaRng,
    delta: Delta,
    false_wire_label0: S,
    true_wire_label0: S,
}

pub struct MultigarblingMode<H: GateHasher, MCTH: MultiCiphertextHandler<N>, const N: usize> {
    lanes: [LaneCtx; N],
    gate_index: usize,
    output_handler: MCTH,
    storage: Storage<WireId, Option<[S; N]>>,
    _hasher: PhantomData<H>,
}

impl<H: GateHasher, MCTH: MultiCiphertextHandler<N>, const N: usize> MultigarblingMode<H, MCTH, N> {
    pub fn new(capacity: usize, seeds: [u64; N], output_handler: MCTH) -> Self {
        let lanes: [LaneCtx; N] = array::from_fn(|i| {
            let mut rng = ChaChaRng::seed_from_u64(seeds[i]);
            let delta = Delta::generate(&mut rng);
            let false_wire_label0 = GarbledWire::random(&mut rng, &delta).label0;
            let true_wire_label0 = GarbledWire::random(&mut rng, &delta).label0;
            LaneCtx {
                rng,
                delta,
                false_wire_label0,
                true_wire_label0,
            }
        });

        Self {
            storage: Storage::new(capacity),
            lanes,
            gate_index: 0,
            output_handler,
            _hasher: PhantomData,
        }
    }

    #[inline]
    pub fn issue_garbled_wire_batch(&mut self) -> [GarbledWire; N] {
        array::from_fn(|i| GarbledWire::random(&mut self.lanes[i].rng, &self.lanes[i].delta))
    }

    #[inline]
    fn next_gate_index(&mut self) -> usize {
        let idx = self.gate_index;
        self.gate_index += 1;
        idx
    }

    fn stream_table_entries(&mut self, _gate_id: usize, entries: Option<[S; N]>) {
        if let Some(cts) = entries {
            self.output_handler.handle(cts);
        }
    }

    #[inline]
    fn read_label0s(&mut self, wire: WireId) -> [S; N] {
        match wire {
            FALSE_WIRE => array::from_fn(|i| self.lanes[i].false_wire_label0),
            TRUE_WIRE => array::from_fn(|i| self.lanes[i].true_wire_label0),
            _ => match self.storage.get(wire).map(|d| d.to_owned()) {
                Ok(Some(arr)) => arr,
                Ok(None) => panic!(
                    "Called evaluate_gate for WireId {:?} that was created but not initialized",
                    wire
                ),
                Err(_) => panic!("Can't find wire {:?}", wire),
            },
        }
    }
}

impl<H: GateHasher, MCTH: MultiCiphertextHandler<N>, const N: usize> std::fmt::Debug
    for MultigarblingMode<H, MCTH, N>
where
    MCTH::Result: Default,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultigarblingMode")
            .field("gate_index", &self.gate_index)
            .field("lanes", &N)
            .finish()
    }
}

impl<H: GateHasher, MCTH: MultiCiphertextHandler<N>, const N: usize> CircuitMode
    for MultigarblingMode<H, MCTH, N>
where
    MCTH::Result: Default,
{
    type WireValue = [GarbledWire; N];
    type CiphertextAcc = MCTH::Result;

    fn false_value(&self) -> Self::WireValue {
        array::from_fn(|i| {
            let l0 = self.lanes[i].false_wire_label0;
            let l1 = l0 ^ &self.lanes[i].delta;
            GarbledWire::new(l0, l1)
        })
    }

    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(None, credits)
    }

    fn true_value(&self) -> Self::WireValue {
        array::from_fn(|i| {
            let l0 = self.lanes[i].true_wire_label0;
            let l1 = l0 ^ &self.lanes[i].delta;
            GarbledWire::new(l0, l1)
        })
    }

    fn evaluate_gate(&mut self, gate: &Gate) {
        let a_label0s: [S; N] = self.read_label0s(gate.wire_a);

        let b_label0s: [S; N] = self.read_label0s(gate.wire_b);

        let gate_id = self.next_gate_index();
        if gate.wire_c == WireId::UNREACHABLE {
            return;
        }
        maybe_log_progress("garbled", gate_id);
        match gate.gate_type {
            GateType::Xor | GateType::Xnor | GateType::Not => {
                let (c_base, ciphertext): ([S; N], Option<[S; N]>) =
                    halfgates_garbling::garble_gate_batch::<N>(
                        gate.gate_type,
                        a_label0s,
                        b_label0s,
                        &array::from_fn(|i| self.lanes[i].delta),
                        gate_id,
                    );
                debug_assert!(ciphertext.is_none());
                assert_ne!(gate.wire_c, FALSE_WIRE);
                assert_ne!(gate.wire_c, TRUE_WIRE);
                assert_ne!(gate.wire_c, WireId::UNREACHABLE);
                self.storage
                    .set(gate.wire_c, |slot| {
                        *slot = Some(c_base);
                    })
                    .unwrap();
            }
            _ => {
                let (c_base, ciphertext): ([S; N], Option<[S; N]>) =
                    halfgates_garbling::garble_gate_batch::<N>(
                        gate.gate_type,
                        a_label0s,
                        b_label0s,
                        &array::from_fn(|i| self.lanes[i].delta),
                        gate_id,
                    );
                self.stream_table_entries(gate_id, ciphertext);
                self.storage
                    .set(gate.wire_c, |slot| {
                        *slot = Some(c_base);
                    })
                    .unwrap();
            }
        }
    }

    fn feed_wire(&mut self, wire_id: crate::WireId, value: Self::WireValue) {
        if matches!(wire_id, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }

        self.storage
            .set(wire_id, |val| {
                *val = Some(array::from_fn(|i| value[i].label0));
            })
            .unwrap();
    }

    fn lookup_wire(&mut self, wire_id: crate::WireId) -> Option<Self::WireValue> {
        match wire_id {
            TRUE_WIRE => return Some(self.true_value()),
            FALSE_WIRE => return Some(self.false_value()),
            _ => {}
        }
        match self.storage.get(wire_id).map(|lbls| lbls.to_owned()) {
            Ok(Some(label0s)) => Some(array::from_fn(|i| {
                let l0 = label0s[i];
                GarbledWire::new(l0, l0 ^ &self.lanes[i].delta)
            })),
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

    fn finalize_ciphertext_accumulator(self) -> Self::CiphertextAcc {
        self.output_handler.finalize()
    }
}
