use std::{array, marker::PhantomData, num::NonZero};

use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::{
    Delta, Gate, GateType, S, WireId,
    circuit::{CiphertextHandler, CircuitMode, FALSE_WIRE, TRUE_WIRE},
    core::progress::maybe_log_progress,
    hashers::GateHasher,
    storage::{Credits, Storage},
};

use super::garble_mode::{GarbledWire, halfgates_garbling};

pub struct MultigarblingMode<H: GateHasher, CTH: CiphertextHandler, const N: usize> {
    rngs: [ChaChaRng; N],
    deltas: [Delta; N],
    gate_index: usize,
    output_handler: CTH,
    storage: Storage<WireId, Option<[S; N]>>,
    false_label0s: [S; N],
    true_label0s: [S; N],
    _hasher: PhantomData<H>,
    // Cross-gate batching queue for non-free gates
    non_free_queue: Vec<QueuedGate<N>>,
    // Target number of 16-byte blocks to batch per AES call series
    queue_target_blocks: usize,
}

impl<H: GateHasher, CTH: CiphertextHandler, const N: usize> MultigarblingMode<H, CTH, N> {
    pub fn new(capacity: usize, seeds: [u64; N], output_handler: CTH) -> Self {
        let mut rngs: [ChaChaRng; N] = array::from_fn(|i| ChaChaRng::seed_from_u64(seeds[i]));
        let deltas: [Delta; N] = array::from_fn(|i| Delta::generate(&mut rngs[i]));
        let false_label0s = array::from_fn(|i| {
            let gw = GarbledWire::random(&mut rngs[i], &deltas[i]);
            gw.label0
        });
        let true_label0s = array::from_fn(|i| false_label0s[i] ^ &deltas[i]);

        const DEFAULT_QUEUE_TARGET: usize = 1024;

        Self {
            storage: Storage::new(capacity),
            rngs,
            deltas,
            gate_index: 0,
            output_handler,
            false_label0s,
            true_label0s,
            _hasher: PhantomData,
            non_free_queue: Vec::with_capacity(32),
            queue_target_blocks: DEFAULT_QUEUE_TARGET,
        }
    }

    #[inline]
    pub fn issue_garbled_wire_batch(&mut self) -> [GarbledWire; N] {
        array::from_fn(|i| GarbledWire::random(&mut self.rngs[i], &self.deltas[i]))
    }

    #[inline]
    fn next_gate_index(&mut self) -> usize {
        let idx = self.gate_index;
        self.gate_index += 1;
        idx
    }

    pub fn set_queue_target_blocks(&mut self, blocks: usize) {
        let b = blocks.clamp(1, 8192);
        self.queue_target_blocks = b;
    }

    fn stream_table_entries(&mut self, _gate_id: usize, entries: Option<[S; N]>) {
        if let Some(cts) = entries {
            for ct in cts {
                self.output_handler.handle(ct);
            }
        }
    }

    #[inline]
    fn read_label0s_or_flush(&mut self, wire: WireId) -> [S; N] {
        match wire {
            FALSE_WIRE => self.false_label0s,
            TRUE_WIRE => self.true_label0s,
            _ => {
                if self.non_free_queue.iter().any(|q| q.wire_c == wire) {
                    self.flush_non_free_queue();
                }

                match self.storage.get(wire).map(|d| d.to_owned()) {
                    Ok(Some(arr)) => arr,
                    Ok(None) => panic!(
                        "Called evaluate_gate for WireId {:?} that was created but not initialized",
                        wire
                    ),
                    Err(_) => panic!("Can't find wire {:?}", wire),
                }
            }
        }
    }

    #[inline]
    fn enqueue_non_free(
        &mut self,
        gate_type: GateType,
        a_label0s: [S; N],
        b_label0s: [S; N],
        gate_id: usize,
        wire_c: WireId,
    ) {
        let (alpha_a, alpha_b, alpha_c) = gate_type.alphas_const();
        let tweak = crate::hashers::to_tweak(gate_id);
        self.non_free_queue.push(QueuedGate {
            alpha_a,
            alpha_b,
            alpha_c,
            tweak,
            a_label0s,
            b_label0s,
            gate_id,
            wire_c,
        });
        let blocks = self.non_free_queue.len() * N;
        if blocks >= self.queue_target_blocks {
            self.flush_non_free_queue();
        }
    }

    fn flush_non_free_queue(&mut self) {
        use crate::hashers::aes_ni;
        if self.non_free_queue.is_empty() {
            return;
        }

        let qlen = self.non_free_queue.len();
        let mut h_sel: Vec<[S; N]> = (0..qlen).map(|_| [S::ZERO; N]).collect();
        let mut h_oth: Vec<[S; N]> = (0..qlen).map(|_| [S::ZERO; N]).collect();

        // We iterate gates in insertion order to preserve ciphertext stream order.
        let mut process_path = |selected: bool| {
            // Working buffers for up to 16/8/4/2 blocks
            let mut buf16 = [[0u8; 16]; 16];
            let mut m16 = [[0u8; 16]; 16];
            let mut buf8 = [[0u8; 16]; 8];
            let mut m8 = [[0u8; 16]; 8];
            let mut buf4 = [[0u8; 16]; 4];
            let mut m4 = [[0u8; 16]; 4];
            let mut buf2 = [[0u8; 16]; 2];
            let mut m2 = [[0u8; 16]; 2];

            let mut gate_idx = 0usize;
            let mut lane_idx = 0usize;

            let total_blocks = qlen * N;
            let mut emitted = 0usize;

            // Macro to emit K blocks at a time
            macro_rules! emit_k {
                ($K:expr, $buf:ident, $masks:ident, $enc:path) => {{
                    for t in 0..$K {
                        let qg = &self.non_free_queue[gate_idx];
                        let (a, delta) = (qg.a_label0s[lane_idx], self.deltas[lane_idx]);
                        let input = if selected == qg.alpha_a {
                            a ^ &delta
                        } else {
                            a
                        };
                        $buf[t] = input.to_bytes();
                        $masks[t] = qg.tweak;
                        lane_idx += 1;
                        if lane_idx == N {
                            lane_idx = 0;
                            gate_idx += 1;
                        }
                    }
                    let out = $enc($buf, $masks).unwrap();
                    let mut gidx = gate_idx;
                    let mut lidx = lane_idx;
                    for _ in 0..$K {
                        if lidx == 0 {
                            lidx = N;
                            gidx -= 1;
                        }
                        lidx -= 1;
                    }
                    for t in 0..$K {
                        let val = S::from_bytes(out[t]);
                        let (g, l) = {
                            let tg = gidx;
                            let tl = lidx;
                            lidx += 1;
                            if lidx == N {
                                lidx = 0;
                                gidx += 1;
                            }
                            (tg, tl)
                        };
                        if selected {
                            h_sel[g][l] = val;
                        } else {
                            h_oth[g][l] = val;
                        }
                    }
                    emitted += $K;
                    continue;
                }};
            }
            while emitted < total_blocks {
                // Choose largest batch size that fits remaining
                let rem = total_blocks - emitted;
                if rem >= 16 {
                    emit_k!(
                        16,
                        buf16,
                        m16,
                        aes_ni::aes128_encrypt16_blocks_static_xor_masks
                    );
                }
                if rem >= 8 {
                    emit_k!(8, buf8, m8, aes_ni::aes128_encrypt8_blocks_static_xor_masks);
                }
                if rem >= 4 {
                    emit_k!(4, buf4, m4, aes_ni::aes128_encrypt4_blocks_static_xor_masks);
                }
                if rem >= 2 {
                    emit_k!(2, buf2, m2, aes_ni::aes128_encrypt2_blocks_static_xor_masks);
                }
                {
                    let qg = &self.non_free_queue[gate_idx];
                    let (a, delta) = (qg.a_label0s[lane_idx], self.deltas[lane_idx]);
                    let input = if selected == qg.alpha_a {
                        a ^ &delta
                    } else {
                        a
                    };
                    let out = aes_ni::aes128_encrypt_block_static_xor(input.to_bytes(), qg.tweak)
                        .unwrap();
                    let val = S::from_bytes(out);
                    if selected {
                        h_sel[gate_idx][lane_idx] = val;
                    } else {
                        h_oth[gate_idx][lane_idx] = val;
                    }
                    lane_idx += 1;
                    if lane_idx == N {
                        lane_idx = 0;
                        gate_idx += 1;
                    }
                    emitted += 1;
                }
            }
        };

        process_path(true);
        process_path(false);

        // Combine to produce w0 and ciphertexts per gate; write outputs and stream
        let queue_data: Vec<_> = self
            .non_free_queue
            .iter()
            .enumerate()
            .map(|(gix, qg)| {
                let (alpha_b, alpha_c) = (qg.alpha_b, qg.alpha_c);
                let mut w0 = [S::ZERO; N];
                let mut ct = [S::ZERO; N];
                for i in 0..N {
                    let b_sel = if alpha_b {
                        qg.b_label0s[i] ^ &self.deltas[i]
                    } else {
                        qg.b_label0s[i]
                    };
                    ct[i] = h_sel[gix][i] ^ &h_oth[gix][i] ^ &b_sel;
                    w0[i] = if alpha_c {
                        h_sel[gix][i] ^ &self.deltas[i]
                    } else {
                        h_sel[gix][i]
                    };
                }
                (qg.gate_id, ct, qg.wire_c, w0)
            })
            .collect();

        for (gate_id, ct, wire_c, w0) in queue_data {
            self.stream_table_entries(gate_id, Some(ct));
            assert_ne!(wire_c, FALSE_WIRE);
            assert_ne!(wire_c, TRUE_WIRE);
            assert_ne!(wire_c, WireId::UNREACHABLE);
            self.storage
                .set(wire_c, |slot| {
                    *slot = Some(w0);
                })
                .unwrap();
        }

        self.non_free_queue.clear();
    }
}

impl<H: GateHasher, CTH: CiphertextHandler, const N: usize> std::fmt::Debug
    for MultigarblingMode<H, CTH, N>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultigarblingMode")
            .field("gate_index", &self.gate_index)
            .field("lanes", &N)
            .finish()
    }
}

impl<H: GateHasher, CTH: CiphertextHandler, const N: usize> CircuitMode
    for MultigarblingMode<H, CTH, N>
{
    type WireValue = [GarbledWire; N];
    type CiphertextAcc = CTH::Result;

    fn false_value(&self) -> Self::WireValue {
        array::from_fn(|i| {
            let l0 = self.false_label0s[i];
            let l1 = l0 ^ &self.deltas[i];
            GarbledWire::new(l0, l1)
        })
    }

    fn allocate_wire(&mut self, credits: Credits) -> WireId {
        self.storage.allocate(None, credits)
    }

    fn true_value(&self) -> Self::WireValue {
        array::from_fn(|i| {
            let l0 = self.true_label0s[i];
            let l1 = l0 ^ &self.deltas[i];
            GarbledWire::new(l0, l1)
        })
    }

    fn evaluate_gate(&mut self, gate: &Gate) {
        let a_label0s: [S; N] = self.read_label0s_or_flush(gate.wire_a);

        let b_label0s: [S; N] = self.read_label0s_or_flush(gate.wire_b);

        if gate.wire_c == WireId::UNREACHABLE {
            return;
        }

        let gate_id = self.next_gate_index();
        maybe_log_progress("garbled", gate_id);
        match gate.gate_type {
            GateType::Xor | GateType::Xnor | GateType::Not => {
                let (c_base, ciphertext): ([S; N], Option<[S; N]>) =
                    halfgates_garbling::garble_gate_batch::<N>(
                        gate.gate_type,
                        a_label0s,
                        b_label0s,
                        &self.deltas,
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
                // Enqueue non-free gate to batch across multiple gates
                self.enqueue_non_free(gate.gate_type, a_label0s, b_label0s, gate_id, gate.wire_c);
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

        // If this wire is scheduled as an output of a queued non-free gate, ensure it's flushed
        if self.non_free_queue.iter().any(|q| q.wire_c == wire_id) {
            self.flush_non_free_queue();
        }

        match self.storage.get(wire_id).map(|lbls| lbls.to_owned()) {
            Ok(Some(label0s)) => Some(array::from_fn(|i| {
                let l0 = label0s[i];
                GarbledWire::new(l0, l0 ^ &self.deltas[i])
            })),
            Ok(None) => {
                // One more attempt after a flush in case of late enqueues
                self.flush_non_free_queue();
                match self.storage.get(wire_id).map(|lbls| lbls.to_owned()) {
                    Ok(Some(label0s)) => Some(array::from_fn(|i| {
                        let l0 = label0s[i];
                        GarbledWire::new(l0, l0 ^ &self.deltas[i])
                    })),
                    Ok(None) => panic!(
                        "Called `lookup_wire` for a WireId {wire_id} that was created but not initialized"
                    ),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    }

    fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        for wire_id in wires {
            self.storage.add_credits(*wire_id, credits.get()).unwrap();
        }
    }

    fn finalize_ciphertext_accumulator(self) -> Self::CiphertextAcc {
        let mut this = self;
        this.flush_non_free_queue();
        this.output_handler.finalize()
    }
}

#[derive(Clone)]
struct QueuedGate<const N: usize> {
    alpha_a: bool,
    alpha_b: bool,
    alpha_c: bool,
    tweak: [u8; 16],
    a_label0s: [S; N],
    b_label0s: [S; N],
    gate_id: usize,
    wire_c: WireId,
}
