use std::iter;

use log::trace;

pub use super::execute_mode::ExecuteMode;
use crate::{
    CircuitContext, WireId,
    circuit::streaming::{
        CircuitMode, ComponentTemplatePool, EncodeInput,
        component_key::ComponentKey,
        component_meta::ComponentMetaBuilder,
        streaming_mode::{StreamingContext, StreamingMode},
    },
    core::gate_type::GateCount,
    storage::Credits,
};

const ROOT_KEY: ComponentKey = [0u8; 8];

// OptionalBoolean moved to execute_mode.rs, re-exported above

// ExecuteContext is now part of StreamingContext<ExecuteMode>
// Keeping this type alias for any code that references it directly
pub type ExecuteContext = StreamingContext<ExecuteMode>;

// Extension methods for StreamingContext<ExecuteMode>
impl StreamingContext<ExecuteMode> {
    pub fn pop_credits(&mut self, len: usize) -> Vec<Credits> {
        let stack = self.stack.last_mut().unwrap();

        iter::repeat_with(|| stack.next_credit().unwrap())
            .take(len)
            .collect::<Vec<_>>()
    }
}

/// Type alias for backward compatibility - Execute is now StreamingMode<ExecuteMode>
pub type Execute = StreamingMode<ExecuteMode>;

impl StreamingMode<ExecuteMode> {
    pub fn new(capacity: usize) -> Self {
        Self::new_execute(capacity)
    }

    fn new_execute(capacity: usize) -> Self {
        StreamingMode::ExecutionPass(StreamingContext {
            mode: ExecuteMode::with_capacity(capacity),
            stack: vec![],
            templates: ComponentTemplatePool::new(),
            gate_count: GateCount::default(),
        })
    }
}

impl<M: CircuitMode> StreamingMode<M> {
    fn new_meta(inputs: &[WireId]) -> Self {
        StreamingMode::MetadataPass(ComponentMetaBuilder::new(inputs.len()))
    }

    pub fn to_root_ctx<I: EncodeInput<M::WireValue>>(
        self,
        mode: M,
        input: &I,
        meta_output_wires: &[WireId],
    ) -> (Self, I::WireRepr) {
        if let StreamingMode::MetadataPass(meta) = self {
            trace!("start root ctx");
            let meta = meta.build(meta_output_wires);
            trace!("Build template: {meta:?}");

            let mut input_credits = vec![0; meta.get_input_len()];

            let mut instance =
                meta.to_instance(&vec![1; meta_output_wires.len()], |index, credits| {
                    let rev_index = meta.get_input_len() - 1 - index;
                    input_credits[rev_index] += credits.get();
                });

            // Extend the credit stack by adding the ability to allocate input through these
            // credits
            instance.credits_stack.extend_from_slice(&input_credits);

            trace!("meta before input encode: {instance:?}");

            let mut ctx = StreamingMode::ExecutionPass(StreamingContext {
                mode,
                stack: vec![instance],
                templates: {
                    let mut pool = ComponentTemplatePool::new();
                    pool.insert(ROOT_KEY, meta);
                    pool
                },
                gate_count: GateCount::default(),
            });

            let input_repr = input.allocate(|| ctx.issue_wire());
            input.encode(&input_repr, ctx.get_mut_mode().unwrap());

            if let StreamingMode::ExecutionPass(ctx) = &ctx {
                trace!("meta after input encode: {:?}", ctx.stack.last().unwrap());
            }

            (ctx, input_repr)
        } else {
            panic!()
        }
    }

    pub fn issue_wire_with_credit(&mut self) -> (WireId, Credits) {
        match self {
            StreamingMode::MetadataPass(meta) => (meta.issue_wire(), 0),
            StreamingMode::ExecutionPass(ctx) => ctx.issue_wire_with_credit(),
        }
    }

    pub fn non_free_gates_count(&self) -> usize {
        match self {
            StreamingMode::MetadataPass(_meta) => 0,
            StreamingMode::ExecutionPass(ctx) => ctx.gate_count.nonfree_gate_count() as usize,
        }
    }

    pub fn total_gates_count(&self) -> usize {
        match self {
            StreamingMode::MetadataPass(_meta) => 0,
            StreamingMode::ExecutionPass(ctx) => ctx.gate_count.total_gate_count() as usize,
        }
    }
}

// Old CircuitMode and CircuitContext implementations removed
// These are now handled by the generic StreamingMode implementation

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Gate, core::gate_type::GateType};

    fn and(a: WireId, b: WireId, c: WireId) -> Gate {
        Gate {
            gate_type: GateType::And,
            wire_a: a,
            wire_b: b,
            wire_c: c,
        }
    }

    // Sanity check: internal wires created inside a child component are freed
    // (no leftover credits in storage) once the child returns.
    //#[test]
    //fn no_zombie_credits_after_child_returns() {
    //    // Prepare root inputs (two bits) and run a metadata pass identical to execution.
    //    let inputs = SimpleInputs::<2>([true, true]);

    //    // Allocate root input wire IDs for metadata pass
    //    let mut cursor = WireId::MIN;
    //    let allocated_inputs = <SimpleInputs<2> as CircuitInput>::allocate(&inputs, || {
    //        let next = cursor;
    //        cursor.0 += 1;
    //        next
    //    });
    //    let meta_input_wires = <SimpleInputs<2> as CircuitInput>::collect_wire_ids(&allocated_inputs);

    //    // Root meta builder mirrors streaming_execute: pin root inputs for one read
    //    let mut root_meta = Execute::MetadataPass({
    //        let mut meta = ComponentMetaBuilder::new(&meta_input_wires);
    //        meta.add_credits(&meta_input_wires, 1);
    //        meta
    //    });

    //    // Describe the circuit at meta time: one child that allocates two internal wires
    //    // and returns a result derived from them.
    //    let root_meta_output = root_meta.with_child(
    //        meta_input_wires.clone(),
    //        |child| {
    //            let w1 = child.issue_wire();
    //            let w2 = child.issue_wire();
    //            let out = child.issue_wire();
    //            child.add_gate(Gate::and(meta_input_wires[0], TRUE_WIRE, w1));
    //            child.add_gate(Gate::and(w1, meta_input_wires[1], w2));
    //            child.add_gate(Gate::xor(w1, w2, out));
    //            vec![out]
    //        },
    //        1,
    //    );

    //    let root_meta_output_wires = root_meta_output.clone();

    //    // Create execution context from metadata and encode inputs
    //    let (mut ctx, exec_inputs) = root_meta.to_root_ctx(
    //        10_000,
    //        &inputs,
    //        &meta_input_wires,
    //        &root_meta_output_wires,
    //    );

    //    // Track internal wires issued inside the child during execution
    //    use std::cell::RefCell;
    //    let internals: RefCell<Vec<WireId>> = RefCell::new(Vec::new());

    //    // Execute same child logic as in metadata
    //    let _exec_output = ctx.with_child(
    //        exec_inputs.to_vec(),
    //        |child| {
    //            let w1 = child.issue_wire();
    //            let w2 = child.issue_wire();
    //            internals.borrow_mut().extend([w1, w2]);
    //            let out = child.issue_wire();
    //            child.add_gate(Gate::and(exec_inputs[0], TRUE_WIRE, w1));
    //            child.add_gate(Gate::and(w1, exec_inputs[1], w2));
    //            child.add_gate(Gate::xor(w1, w2, out));
    //            vec![out]
    //        },
    //        1,
    //    );

    //    // After child returns, its internal wires must have been fully consumed
    //    let [w1, w2]: [WireId; 2] = internals
    //        .borrow()
    //        .as_slice()
    //        .try_into()
    //        .expect("expected exactly two internals");

    //    if let Execute::ExecutePass(exec) = &ctx {
    //        let storage = exec.storage.borrow();
    //        assert!(
    //            !storage.contains(w1) && !storage.contains(w2),
    //            "child internals should not remain in storage: w1={w1:?} present={} w2={w2:?} present={}",
    //            storage.contains(w1),
    //            storage.contains(w2)
    //        );
    //    } else {
    //        panic!("expected ExecutePass context");
    //    }
    //}
}
