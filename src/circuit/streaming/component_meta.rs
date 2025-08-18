//! ComponentMeta: collect wire metadata without computation.
//!
//! Purpose
//! - This mode (an implementation of `CircuitMode` and `CircuitContext`) does not execute valve logic and does not stores values on the wires. It only calculates the "credits" of wire usage for subsequent resource scheduling and/or reconciliation with the actual run.
//!
//! Credits model (reads-only)
//! - External wires (inputs and declared outputs of the component) are accounted for in the vector `external_credits = [inputs..., outputs...]`.
//! - Internal wires (issued via `issue_wire`) are accounted for in `credits_stack`, index is calculated as `wire_id - offset`, where `offset = max(inputs ∪ outputs) + 1`.
//! - Credit is added only when the wire is "read": when it is used as a fan-in input (`wire_a`, `wire_b`) or when the wire is passed to a child component via `with_named_child`.
//! - Writing the result to `wire_c` is not considered a read and does not increment credits.
//! - The `TRUE_WIRE`/`FALSE_WIRE` constants are ignored.
//!
//! Model security
//! - If an id less than `offset` is encountered that is not among the I/Os, a panic is generated - such a wire is unknown to the current component.
//! - Calls to child components increase credits only for input wires passed to them; child internals are not analyzed in this mode.

use std::{cell::RefCell, cmp, collections::HashMap, iter};

use crate::{
    CircuitContext, Gate, WireId,
    circuit::streaming::{CircuitMode, ComponentHandle, FALSE_WIRE, TRUE_WIRE, WiresObject},
    storage::Credits,
};

pub struct ComponentMeta {
    /// This variable should be used as follows
    /// During the real execution of the component, we take from here as from the stack
    /// lifetime (credits) for real wires, during their issue
    ///
    /// Since the order in which they are released is deterministic, everything is fairly trivial
    credits_stack: RefCell<Vec<u32>>,
    external_credits: RefCell<Vec<u32>>,
    /// Fast lookup from external wire id -> position in `external_credits`
    external_index: HashMap<WireId, usize>,

    offset: WireId,
    cursor: WireId,
}

impl ComponentMeta {
    pub fn new(inputs: &[WireId], outputs: &[WireId], outputs_credits: &[Credits]) -> Self {
        let mut external_credits = vec![0; inputs.len() + outputs.len()];

        let mut external_index = HashMap::with_capacity(inputs.len() + outputs.len());

        let mut offset = WireId(0);
        for (i, (&wire_id, credits)) in inputs
            .iter()
            .zip(iter::repeat(0))
            .chain(
                outputs
                    .iter()
                    .zip(outputs_credits.iter().copied().map(|cr| cr.into())),
            )
            .enumerate()
        {
            offset = cmp::max(offset, wire_id);

            external_index.insert(wire_id, i);
            external_credits[i] += credits;
        }

        offset.0 += 1;

        Self {
            credits_stack: RefCell::new(vec![]),
            external_credits: RefCell::new(external_credits),
            external_index,
            cursor: offset,
            offset,
        }
    }

    pub fn increment_credits(&self, wires: &[WireId]) {
        let mut stack = self.credits_stack.borrow_mut();
        let mut external = self.external_credits.borrow_mut();
        let offset = self.offset.0;

        for wire_id in wires.iter().copied() {
            match wire_id {
                TRUE_WIRE | FALSE_WIRE => (),
                // External wire: increment in external_credits using precomputed map
                index if index < self.offset => match self.external_index.get(&index) {
                    Some(&pos) => external[pos] += 1,
                    None => panic!("I don't know this wire id"),
                },
                index => {
                    let idx = index.0 - offset;
                    if idx < stack.len() {
                        stack[idx] += 1;
                    } else {
                        panic!("internal wire index out of bounds");
                    }
                }
            }
        }
    }
}

impl CircuitMode for ComponentMeta {
    type WireValue = ();

    fn lookup_wire(&self, _wire: WireId) -> Option<&Self::WireValue> {
        Some(&())
    }

    fn feed_wire(&mut self, _wire: WireId, _value: Self::WireValue) {}

    fn total_size(&self) -> usize {
        self.current_size() + self.external_credits.borrow().len()
    }

    fn current_size(&self) -> usize {
        self.credits_stack.borrow().len()
    }

    /// This function is called on the component's input
    fn push_frame(&mut self, _name: &'static str, _inputs: &[WireId]) {}

    fn pop_frame(&mut self, _outputs: &[WireId]) -> Vec<(WireId, Self::WireValue)> {
        vec![]
    }

    fn evaluate_gate(&mut self, _gate: &Gate) -> Option<()> {
        None
    }
}

impl CircuitContext for ComponentMeta {
    type Mode = Self;

    fn issue_wire(&mut self) -> WireId {
        let next = self.cursor;
        self.cursor.0 += 1;

        self.credits_stack.borrow_mut().push(0);

        next
    }

    fn add_gate(&mut self, gate: Gate) {
        // Consider only reads: wire_a and wire_b; wire_c is a write, it is not counted.
        self.increment_credits(&[gate.wire_a, gate.wire_b]);
    }

    fn with_named_child<O: WiresObject>(
        &mut self,
        _name: &'static str,
        input_wires: Vec<WireId>,
        _f: impl FnOnce(&mut ComponentHandle<Self::Mode>) -> O,
        arity: impl FnOnce() -> usize,
    ) -> O {
        self.increment_credits(&input_wires);

        let mock_output = std::iter::repeat_with(|| self.issue_wire())
            .take((arity)())
            .collect::<Vec<_>>();

        O::from_wires(&mock_output).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::gate_type::GateType;

    fn and(a: WireId, b: WireId, c: WireId) -> Gate {
        Gate {
            gate_type: GateType::And,
            wire_a: a,
            wire_b: b,
            wire_c: c,
        }
    }

    fn xor(a: WireId, b: WireId, c: WireId) -> Gate {
        Gate {
            gate_type: GateType::Xor,
            wire_a: a,
            wire_b: b,
            wire_c: c,
        }
    }

    /// Build a simple gadget on a generic CircuitContext.
    /// Structure:
    /// - r1 = AND(i0, i1)
    /// - r2 = child(i0): XOR(i0, TRUE)
    /// - out = AND(r1, r2)
    fn build_gadget<C: CircuitContext>(ctx: &mut C, inputs: &[WireId]) -> WireId {
        let r1 = ctx.issue_wire();
        ctx.add_gate(and(inputs[0], inputs[1], r1));

        let r2 = ctx.with_named_child(
            "sub1",
            vec![inputs[0]],
            |child| {
                let out = child.issue_wire();
                child.add_gate(xor(inputs[0], TRUE_WIRE, out));
                out
            },
            || 1,
        );

        let out = ctx.issue_wire();
        ctx.add_gate(and(r1, r2, out));
        out
    }

    #[test]
    fn component_meta_matches_execute_counts() {
        use crate::circuit::streaming::CircuitBuilder;

        // Inputs use ids 2 and 3 to mirror typical builder allocation
        let inputs_ids = [WireId(2), WireId(3)];

        // First pass: ComponentMeta only (collect metadata)
        let mut meta = ComponentMeta::new(&inputs_ids, &[], &[]);
        let _out = build_gadget(&mut meta, &inputs_ids);

        let meta_internal_counts: Vec<u32> = meta.credits_stack.borrow().clone();
        let meta_input_counts: Vec<u32> = meta
            .external_credits
            .borrow()
            .iter()
            .copied()
            .take(inputs_ids.len())
            .collect();

        // Second pass: Execute mode with the same structure
        let mut issued: Vec<WireId> = vec![]; // track issuance order across root+child
        let mut child_pass_counts = vec![0u32; inputs_ids.len()];
        let mut root_gates: Vec<Gate> = vec![]; // record root gates only

        let _output =
            CircuitBuilder::<crate::circuit::streaming::modes::Execute>::streaming_execute(
                [true, false],
                |root, inputs_wire| {
                    let i0 = inputs_wire[0];
                    let i1 = inputs_wire[1];

                    let r1 = root.issue_wire();
                    root_gates.push(and(i0, i1, r1));
                    root.add_gate(and(i0, i1, r1));
                    issued.push(r1);

                    let r2 = root.with_named_child(
                        "sub1",
                        vec![i0],
                        |child| {
                            child_pass_counts[0] += 1; // i0 passed to child once
                            let out = child.issue_wire();
                            // child's internal gate (not part of root actions)
                            child.add_gate(xor(i0, TRUE_WIRE, out));
                            out
                        },
                        || 1,
                    );
                    issued.push(r2);

                    let out = root.issue_wire();
                    root_gates.push(and(r1, r2, out));
                    root.add_gate(and(r1, r2, out));
                    issued.push(out);

                    vec![out]
                },
            );

        // Compute input usage from root gates (reads-only: A,B) + child pass counts
        let mut exec_input_counts = vec![0u32; inputs_ids.len()];
        for g in &root_gates {
            for (idx, &inp) in inputs_ids.iter().enumerate() {
                if g.wire_a == inp {
                    exec_input_counts[idx] += 1;
                }
                if g.wire_b == inp {
                    exec_input_counts[idx] += 1;
                }
            }
        }
        for i in 0..exec_input_counts.len() {
            exec_input_counts[i] += child_pass_counts[i];
        }

        // Compute internal wire usage in issuance order, considering only root gates (reads-only: A,B)
        let mut exec_internal_counts = vec![0u32; issued.len()];
        for (wi, w) in issued.iter().enumerate() {
            for g in &root_gates {
                if g.wire_a == *w {
                    exec_internal_counts[wi] += 1;
                }
                if g.wire_b == *w {
                    exec_internal_counts[wi] += 1;
                }
            }
        }

        assert_eq!(
            meta_input_counts, exec_input_counts,
            "input usage counts should match"
        );
        assert_eq!(
            meta_internal_counts, exec_internal_counts,
            "internal wire counts should match"
        );
    }

    #[test]
    #[should_panic]
    fn increment_panics_on_unknown_external_wire() {
        // Choose inputs far from zero so there exist ids < offset that are not inputs/outputs/constants
        let inputs = [WireId(10), WireId(11)];
        let mut meta = ComponentMeta::new(&inputs, &[], &[]);

        // 9 < offset (12) and is not an input/output/constant
        let unknown = WireId(9);
        let r = meta.issue_wire();
        meta.add_gate(and(unknown, TRUE_WIRE, r));
    }

    #[test]
    fn internal_wire_used_in_child_and_after() {
        // Arrange
        let inputs = [WireId(2), WireId(3)];
        let mut meta = ComponentMeta::new(&inputs, &[], &[]);

        // r1 produced, then passed to child, then used after child
        let r1 = meta.issue_wire();
        meta.add_gate(and(inputs[0], inputs[1], r1)); // r1 as c

        let _child_out =
            meta.with_named_child("child", vec![r1], |_child| Vec::<WireId>::new(), || 1); // r1 passed into child

        let r2 = meta.issue_wire();
        meta.add_gate(xor(r1, TRUE_WIRE, r2)); // r1 used again; r2 as c

        // Assert counts
        let off = meta.offset.0;
        let counts = meta.credits_stack.borrow().clone();
        let idx_r1 = r1.0 - off;
        let idx_r2 = r2.0 - off;
        assert_eq!(
            counts[idx_r1], 2,
            "r1 should have 2 credits: child input + post-child use"
        );
        assert_eq!(counts[idx_r2], 0, "r2 is only written (c) and never read");
    }

    #[test]
    fn wire_lifetime_finishes_in_child() {
        let inputs = [WireId(2), WireId(3)];
        let mut meta = ComponentMeta::new(&inputs, &[], &[]);

        let w = meta.issue_wire();
        // The only use of w is as child input; never used afterwards
        let _child_out =
            meta.with_named_child("child2", vec![w], |_child| Vec::<WireId>::new(), || 1);

        let off = meta.offset.0;
        let counts = meta.credits_stack.borrow().clone();
        let idx_w = w.0 - off;
        assert_eq!(
            counts[idx_w], 1,
            "w should have exactly 1 credit from child input"
        );
    }

    #[test]
    fn external_output_credit_is_tracked() {
        use crate::storage::ONE_CREDIT;
        // outputs_credits initializes external credits for outputs; using output as input increments outputs area
        let inputs = [WireId(2), WireId(3)];
        let outputs = [WireId(7)];
        let mut meta = ComponentMeta::new(&inputs, &outputs, &[ONE_CREDIT]);

        // Use output[0] as an input to a gate producing an internal wire
        let r = meta.issue_wire();
        meta.add_gate(and(outputs[0], TRUE_WIRE, r));

        let external = meta.external_credits.borrow().clone();
        assert_eq!(external.len(), inputs.len() + outputs.len());
        assert_eq!(external[0], 0);
        assert_eq!(external[1], 0);
        // initial ONE_CREDIT + one use in gate on inputs side of outputs area
        assert_eq!(external[2], ONE_CREDIT.get() + 1);
    }

    #[test]
    fn internal_wire_reused_across_multiple_children_and_parent() {
        let inputs = [WireId(2), WireId(3)];
        let mut meta = ComponentMeta::new(&inputs, &[], &[]);

        let w = meta.issue_wire();
        // Write to w (does not add credits in reads-only mode)
        meta.add_gate(and(inputs[0], TRUE_WIRE, w));

        // Pass to two children
        let _ = meta.with_named_child("c1", vec![w], |_c| Vec::<WireId>::new(), || 1);
        let _ = meta.with_named_child("c2", vec![w], |_c| Vec::<WireId>::new(), || 1);

        // Use again in parent gate
        let r = meta.issue_wire();
        meta.add_gate(xor(w, inputs[1], r));

        let off = meta.offset.0;
        let counts = meta.credits_stack.borrow().clone();
        let idx_w = w.0 - off;
        assert_eq!(
            counts[idx_w], 3,
            "w used in two children and one parent read"
        );
    }

    #[test]
    fn inputs_used_multiple_times_and_in_children() {
        let inputs = [WireId(2), WireId(3)];
        let mut meta = ComponentMeta::new(&inputs, &[], &[]);

        let r1 = meta.issue_wire();
        let r2 = meta.issue_wire();

        // i0 used twice in gates and once in child
        meta.add_gate(and(inputs[0], TRUE_WIRE, r1));
        meta.add_gate(xor(inputs[0], FALSE_WIRE, r2));
        let _ = meta.with_named_child("child", vec![inputs[0]], |_c| Vec::<WireId>::new(), || 1);

        // i1 used once in a gate
        let r3 = meta.issue_wire();
        meta.add_gate(and(inputs[1], TRUE_WIRE, r3));

        let ext = meta.external_credits.borrow().clone();
        assert_eq!(ext[0], 3, "i0 used twice in gates + once in child");
        assert_eq!(ext[1], 1, "i1 used once in gate");
    }

    #[test]
    fn outputs_credits_multiple_outputs() {
        use crate::storage::ONE_CREDIT;
        let inputs = [WireId(2), WireId(3)];
        let outputs = [WireId(8), WireId(9)];
        let init = [ONE_CREDIT, ONE_CREDIT.saturating_add(ONE_CREDIT.into())]; // 1 and 2
        let mut meta = ComponentMeta::new(&inputs, &outputs, &init);

        let r = meta.issue_wire();
        // Use outputs[0] twice, outputs[1] once
        meta.add_gate(and(outputs[0], TRUE_WIRE, r));
        let r2 = meta.issue_wire();
        meta.add_gate(xor(outputs[0], FALSE_WIRE, r2));
        let r3 = meta.issue_wire();
        meta.add_gate(and(outputs[1], TRUE_WIRE, r3));

        let ext = meta.external_credits.borrow().clone();
        assert_eq!(ext.len(), inputs.len() + outputs.len());
        // inputs area unchanged
        assert_eq!(ext[0], 0);
        assert_eq!(ext[1], 0);
        // outputs area incremented appropriately: [1+2, 2+1] = [3,3]
        assert_eq!(ext[2], ONE_CREDIT.get() + 2);
        assert_eq!(ext[3], ONE_CREDIT.get() * 2 + 1);
    }

    #[test]
    fn wire_only_written_never_read_has_zero_credits() {
        let inputs = [WireId(2), WireId(3)];
        let mut meta = ComponentMeta::new(&inputs, &[], &[]);
        let w = meta.issue_wire();
        // Write into w; never read or passed to child
        meta.add_gate(and(TRUE_WIRE, FALSE_WIRE, w));
        let counts = meta.credits_stack.borrow().clone();
        let idx = w.0 - meta.offset.0;
        assert_eq!(counts[idx], 0);
    }

    #[test]
    fn issued_wires_contiguous_and_stack_len_matches() {
        let inputs = [WireId(2), WireId(3)];
        let mut meta = ComponentMeta::new(&inputs, &[], &[]);
        let w1 = meta.issue_wire();
        let w2 = meta.issue_wire();
        let w3 = meta.issue_wire();
        // Simple reads to increment some
        meta.add_gate(and(w1, w2, w3));

        let counts = meta.credits_stack.borrow().clone();
        assert_eq!(counts.len(), 3, "three issued wires => 3 credit slots");
        assert_eq!(w1.0 + 1, w2.0);
        assert_eq!(w2.0 + 1, w3.0);
        let base = meta.offset.0;
        assert_eq!(w1.0 - base, 0);
        assert_eq!(w2.0 - base, 1);
        assert_eq!(w3.0 - base, 2);
    }
}
