use crate::{
    Gate, WireId,
    circuit::streaming::{CircuitBuilder, CircuitContext},
};

// Simple implementations without the component macro for testing
fn and_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
    let c = ctx.issue_wire();
    ctx.add_gate(Gate::and(a, b, c));
    c
}

fn triple_and(ctx: &mut impl CircuitContext, a: WireId, b: WireId, c: WireId) -> WireId {
    let ab = and_gate(ctx, a, b);
    and_gate(ctx, ab, c)
}

// A tiny gadget that emits many gates in one go (kept simple to avoid boilerplate)
// Tuned so that leaves * BIG_CHAIN_LEN ≈ 5,000,000 gates.
const BIG_CHAIN_LEN: usize = 2304; // per-call gates count

fn big_chain(ctx: &mut impl CircuitContext, a: WireId) -> WireId {
    let mut cur = a;
    for _ in 0..BIG_CHAIN_LEN {
        let nxt = ctx.issue_wire();
        // XOR with FALSE acts as identity (free-XOR)
        ctx.add_gate(Gate::xor(cur, crate::circuit::streaming::FALSE_WIRE, nxt));
        cur = nxt;
    }
    cur
}

// Evaluate-style variant to avoid trait dispatch in some tests
fn big_chain_eval(ctx: &mut impl CircuitContext, a: WireId) -> WireId {
    let mut cur = a;
    for _ in 0..BIG_CHAIN_LEN {
        let nxt = ctx.issue_wire();
        ctx.add_gate(Gate::xor(cur, crate::circuit::streaming::FALSE_WIRE, nxt));
        cur = nxt;
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GarbledWire, S,
        circuit::streaming::{CircuitContext, CircuitMode},
    };

    // Deterministic label helpers for tests
    fn lbl_pair(w: WireId) -> GarbledWire {
        let mut buf0 = [0u8; 24];
        buf0[..8].copy_from_slice(&(w.0 as u64).to_le_bytes());
        let s0 = b"garble-lbl0";
        buf0[8..8 + s0.len()].copy_from_slice(s0);
        let h0 = blake3::hash(&buf0);
        let mut l0 = [0u8; 16];
        l0.copy_from_slice(&h0.as_bytes()[..16]);

        let mut buf1 = [0u8; 24];
        buf1[..8].copy_from_slice(&(w.0 as u64).to_le_bytes());
        let s1 = b"garble-lbl1";
        buf1[8..8 + s1.len()].copy_from_slice(s1);
        let h1 = blake3::hash(&buf1);
        let mut l1 = [0u8; 16];
        l1.copy_from_slice(&h1.as_bytes()[..16]);

        GarbledWire {
            label0: S::from_bytes(l0),
            label1: S::from_bytes(l1),
        }
    }

    //fn lbl_single(w: WireId, bit: bool) -> EvaluatedWire {
    //    let mut buf = [0u8; 25];
    //    buf[..8].copy_from_slice(&(w.0 as u64).to_le_bytes());
    //    let s = b"check-lbl-single"; // 16 bytes fits exactly
    //    buf[8..8 + s.len()].copy_from_slice(s);
    //    buf[24] = bit as u8;
    //    let h = blake3::hash(&buf);
    //    let mut out = [0u8; 16];
    //    out.copy_from_slice(&h.as_bytes()[..16]);
    //    out
    //}

    #[test]
    fn test_component_macro_basic_evaluate() {
        let inputs = [true, false];

        fn and_gate_eval(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
            let c = ctx.issue_wire();
            ctx.add_gate(Gate::and(a, b, c));
            c
        }

        let result: crate::circuit::streaming::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let c = and_gate_eval(root, inputs_wire[0], inputs_wire[1]);
                vec![c]
            });

        assert_eq!(result.output_wires, vec![false]); // true AND false = false
    }

    #[test]
    fn test_component_macro_nested_evaluate() {
        let inputs = [true, true, false];

        fn triple_and_eval(
            ctx: &mut impl CircuitContext,
            a: WireId,
            b: WireId,
            c: WireId,
        ) -> WireId {
            let ab = {
                let t = ctx.issue_wire();
                ctx.add_gate(Gate::and(a, b, t));
                t
            };
            let res = ctx.issue_wire();
            ctx.add_gate(Gate::and(ab, c, res));
            res
        }

        let result: crate::circuit::streaming::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let r = triple_and_eval(root, inputs_wire[0], inputs_wire[1], inputs_wire[2]);
                vec![r]
            });

        assert_eq!(result.output_wires, vec![false]); // (true AND true) AND false = false
    }

    #[test]
    fn test_component_macro_true_case() {
        let inputs = [true, true, true];

        fn triple_and_eval(
            ctx: &mut impl CircuitContext,
            a: WireId,
            b: WireId,
            c: WireId,
        ) -> WireId {
            let ab = {
                let t = ctx.issue_wire();
                ctx.add_gate(Gate::and(a, b, t));
                t
            };
            let res = ctx.issue_wire();
            ctx.add_gate(Gate::and(ab, c, res));
            res
        }

        let result: crate::circuit::streaming::StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let r = triple_and_eval(root, inputs_wire[0], inputs_wire[1], inputs_wire[2]);
                vec![r]
            });

        assert_eq!(result.output_wires, vec![true]); // (true AND true) AND true = true
    }

    // Minimal, streaming garbling stress: builds a very large circuit structure
    // and also exercises input allocation in garble mode.
    //#[test]
    //#[offcircuit_args = "tmp wip"]
    //fn test_streaming_garble_large_circuit() {
    //    // Single-boolean input to exercise input allocation in garble mode too
    //    struct OneInput {
    //        x: bool,
    //    }
    //    struct OneInputWire {
    //        x: WireId,
    //    }
    //    impl crate::circuit::streaming::CircuitInput for OneInput {
    //        type WireRepr = OneInputWire;
    //        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
    //            OneInputWire { x: (issue)() }
    //        }
    //        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
    //            vec![repr.x]
    //        }
    //    }
    //    impl crate::circuit::streaming::EncodeInput<GarbledWire> for OneInput {
    //        fn encode<M: CircuitMode<WireValue = GarbledWire>>(
    //            &self,
    //            repr: &OneInputWire,
    //            cache: &mut M,
    //        ) {
    //            cache.feed_wire(repr.x, lbl_pair(repr.x));
    //            let _ = self; // value not used in garble-mode structure build
    //        }
    //    }

    //    // Build a deep fanout tree of child components, each leaf emits BIG_CHAIN_LEN gates.
    //    const FANOUT: usize = 3;
    //    const DEPTH: usize = 7; // leaves = FANOUT^DEPTH = 2187; total gates ≈ 5,038,848

    //    fn expand_tree<C: CircuitContext>(ctx: &mut C, seed: WireId, depth: usize) {
    //        if depth == 0 {
    //            let _ = big_chain(ctx, seed);
    //        } else {
    //            for _ in 0..FANOUT {
    //                ctx.with_child(
    //                    vec![seed],
    //                    |child| {
    //                        expand_tree(child, seed, depth - 1);
    //                        // Return no outputs to keep garble extraction minimal
    //                        Vec::<WireId>::new()
    //                    },
    //                    0,
    //                );
    //            }
    //        }
    //    }

    //    let out = CircuitBuilder::<Garble>::streaming_process::<_, _, Vec<GarbledWire>>(
    //        OneInput { x: true },
    //        Garble::new(0, 20_000),
    //        |root, iw| {
    //            let seed = iw.x;
    //            expand_tree(root, seed, DEPTH);
    //            // Return an output (the input seed wire) to exercise output collection
    //            vec![seed]
    //        },
    //    );
    //    // Ensure we got back the expected pair of labels for the input wire
    //    assert_eq!(out.output_wires, vec![lbl_pair(WireId(2))]);
    //}

    // Evaluate-mode correctness on a smaller tree: big_chain keeps the input value; OR-reduction preserves it
    #[test]
    fn test_streaming_evaluate_tree_correctness() {
        struct OneInput {
            x: bool,
        }
        struct OneInputWire {
            x: WireId,
        }
        impl crate::circuit::streaming::CircuitInput for OneInput {
            type WireRepr = OneInputWire;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                OneInputWire { x: (issue)() }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                vec![repr.x]
            }
        }
        impl<M: CircuitMode<WireValue = bool>> crate::circuit::streaming::EncodeInput<M> for OneInput {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
                cache.feed_wire(repr.x, self.x);
            }
        }

        const LEAVES: usize = 16; // keep runtime modest while checking input-dependence

        fn or_gate_eval(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
            let o = ctx.issue_wire();
            ctx.add_gate(Gate::or(a, b, o));
            o
        }

        for &input in &[false, true] {
            let out: crate::circuit::streaming::StreamingResult<_, _, Vec<bool>> =
                CircuitBuilder::streaming_execute(OneInput { x: input }, 10_000, |root, iw| {
                    // Build many big chains and OR them to keep dependency on input
                    let mut acc: Option<WireId> = None;
                    for _ in 0..LEAVES {
                        let w = big_chain_eval(root, iw.x);
                        acc = Some(match acc {
                            Some(prev) => or_gate_eval(root, prev, w),
                            None => w,
                        });
                    }
                    vec![acc.unwrap()]
                });
            assert_eq!(out.output_wires, vec![input]);
        }
    }

    // Evaluate-mode correctness on a large deep tree (~5M gates via 3^7 leaves × BIG_CHAIN_LEN)
    // Verifies output depends on input at scale by running with false/true and comparing outputs.
    #[test]
    #[ignore = "WIP"]
    fn test_streaming_evaluate_large_tree_correctness() {
        struct OneInput {
            x: bool,
        }
        struct OneInputWire {
            x: WireId,
        }
        impl crate::circuit::streaming::CircuitInput for OneInput {
            type WireRepr = OneInputWire;

            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                OneInputWire { x: (issue)() }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                vec![repr.x]
            }
        }
        impl<M: CircuitMode<WireValue = bool>> crate::circuit::streaming::EncodeInput<M> for OneInput {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
                cache.feed_wire(repr.x, self.x);
            }
        }

        const FANOUT: usize = 3;
        const DEPTH: usize = 7; // 3^7 = 2187 leaves; gates ≈ 2187 × BIG_CHAIN_LEN

        fn or_gate_eval(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
            let o = ctx.issue_wire();
            ctx.add_gate(Gate::or(a, b, o));
            o
        }

        fn expand_tree_eval(ctx: &mut impl CircuitContext, seed: WireId, depth: usize) -> WireId {
            if depth == 0 {
                big_chain_eval(ctx, seed)
            } else {
                let mut acc: Option<WireId> = None;
                for _ in 0..FANOUT {
                    let w = ctx.with_child(
                        vec![seed],
                        |child, inputs| {
                            let seed = inputs[0];
                            let out = expand_tree_eval(child, seed, depth - 1);
                            // Return a bridged value present in the child frame
                            let bridged = child.issue_wire();
                            child.add_gate(Gate::and(
                                out,
                                crate::circuit::streaming::TRUE_WIRE,
                                bridged,
                            ));
                            vec![bridged]
                        },
                        1,
                    )[0];
                    acc = Some(match acc {
                        Some(prev) => or_gate_eval(ctx, prev, w),
                        None => w,
                    });
                }
                acc.unwrap()
            }
        }

        for &input in &[false, true] {
            let out: crate::circuit::streaming::StreamingResult<_, _, Vec<bool>> =
                CircuitBuilder::streaming_execute(OneInput { x: input }, 10_000, |root, iw| {
                    let r = expand_tree_eval(root, iw.x, DEPTH);
                    vec![r]
                });
            assert_eq!(out.output_wires, vec![input]);
        }
    }
}
