use std::{iter, num::NonZero};

use tracing::{debug, trace};

use crate::{
    CircuitContext, Gate, WireId,
    circuit::{
        CircuitMode, ComponentMetaBuilder, ComponentTemplatePool, EncodeInput, FALSE_WIRE,
        TRUE_WIRE, WiresObject, component_key::ComponentKey, component_meta::ComponentMetaInstance,
        into_wire_list::FromWires,
    },
    core::gate_type::GateCount,
    storage::Credits,
};
const ROOT_KEY: ComponentKey = [0u8; 8];

/// Generic streaming context that holds mode-specific evaluation logic
/// along with shared infrastructure (storage, templates, component stack).
#[derive(Debug)]
pub struct StreamingContext<M: CircuitMode> {
    pub mode: M,
    pub stack: Vec<ComponentMetaInstance>,
    pub templates: ComponentTemplatePool,
    pub gate_count: GateCount,
}

/// Two-phase streaming execution: metadata collection (fanout totals) and execution
/// (consuming remaining-use credits). This generic enum replaces the Execute-specific pattern.
#[derive(Debug)]
pub enum StreamingMode<M: CircuitMode> {
    MetadataPass(ComponentMetaBuilder),
    ExecutionPass(StreamingContext<M>),
}

impl<M: CircuitMode> StreamingMode<M> {
    pub fn lookup_wire(&mut self, wire: WireId) -> Option<M::WireValue> {
        match self {
            StreamingMode::MetadataPass(_) => None,
            StreamingMode::ExecutionPass(ctx) => ctx.lookup_wire(wire),
        }
    }

    pub fn feed_wire(&mut self, wire: WireId, value: M::WireValue) {
        if matches!(wire, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }

        match self {
            StreamingMode::MetadataPass(_) => (),
            StreamingMode::ExecutionPass(ctx) => ctx.feed_wire(wire, value),
        }
    }

    pub fn issue_wire(&mut self) -> WireId {
        match self {
            StreamingMode::MetadataPass(meta) => meta.issue_wire(),
            StreamingMode::ExecutionPass(ctx) => {
                let (wire_id, _) = ctx.issue_wire_with_credit();
                wire_id
            }
        }
    }

    pub fn get_mode(&self) -> Option<&M> {
        match self {
            StreamingMode::MetadataPass(_meta) => None,
            StreamingMode::ExecutionPass(ctx) => Some(&ctx.mode),
        }
    }

    pub fn get_mut_mode(&mut self) -> Option<&mut M> {
        match self {
            StreamingMode::MetadataPass(_meta) => None,
            StreamingMode::ExecutionPass(ctx) => Some(&mut ctx.mode),
        }
    }

    // Build execution context from collected metadata and encode inputs.
    pub fn to_root_ctx<I: EncodeInput<M>>(
        self,
        mode: M,
        input: &I,
        meta_output_wires: &[WireId],
    ) -> (Self, I::WireRepr) {
        if let StreamingMode::MetadataPass(meta) = self {
            let meta = meta.build(meta_output_wires);

            // Seed with 1 to make each input externally readable once (result extraction).
            let mut input_credits = vec![1; meta.get_input_len()];

            let mut instance =
                meta.to_instance(&vec![1; meta_output_wires.len()], |index, credits| {
                    let rev_index = meta.get_input_len() - 1 - index;
                    input_credits[rev_index] += credits.get();
                });

            // Extend the credit stack with input remaining-use counters.
            instance.credits_stack.extend_from_slice(&input_credits);

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

            (ctx, input_repr)
        } else {
            panic!()
        }
    }
}

impl<M: CircuitMode> CircuitContext for StreamingMode<M> {
    type Mode = M;

    fn issue_wire(&mut self) -> WireId {
        match self {
            StreamingMode::MetadataPass(meta) => meta.issue_wire(),
            StreamingMode::ExecutionPass(ctx) => {
                let (wire_id, _) = ctx.issue_wire_with_credit();
                wire_id
            }
        }
    }

    fn add_gate(&mut self, gate: Gate) {
        match self {
            StreamingMode::MetadataPass(meta) => {
                meta.add_gate(gate);
            }
            StreamingMode::ExecutionPass(ctx) => {
                ctx.gate_count.handle(gate.gate_type);

                assert_ne!(gate.wire_a, WireId::UNREACHABLE);
                assert_ne!(gate.wire_b, WireId::UNREACHABLE);

                ctx.mode.evaluate_gate(&gate);
            }
        }
    }

    fn with_named_child<I: WiresObject, O: FromWires>(
        &mut self,
        key: ComponentKey,
        inputs: I,
        f: impl Fn(&mut Self, &I) -> O,
        arity: usize,
    ) -> O {
        let input_wires = inputs.to_wires_vec();

        match self {
            StreamingMode::MetadataPass(meta) => {
                debug!("with_named_child: metapass enter name={key:?} arity={arity}");
                meta.increment_credits(&input_wires);

                // We just pre-alloc all outputs for handle credits
                let mock_output = iter::repeat_with(|| meta.issue_wire())
                    .take(arity)
                    .collect::<Vec<_>>();

                O::from_wires(&mock_output).unwrap()
            }
            StreamingMode::ExecutionPass(ctx) => {
                debug!("with_named_child: enter name={key:?} arity={arity}");

                // Extract per-output remaining-use counters and push to stack
                let pre_alloc_output_credits = {
                    let last = ctx.stack.last_mut().unwrap();

                    iter::repeat_with(|| last.next_credit().unwrap())
                        .take(arity)
                        .collect::<Vec<_>>()
                };

                trace!("Start component {key:?} meta instantiation");

                let StreamingContext {
                    mode, templates, ..
                } = ctx;

                let template = templates.get_or_insert_with(key, || {
                    // Calculate arity from the real input structure
                    let expected_wire_count = input_wires.len();

                    trace!(
                        "For key {key:?} generate template: arity {arity}, expected_wire_count: {}",
                        expected_wire_count
                    );

                    let mut child_component_meta = ComponentMetaBuilder::new(expected_wire_count);

                    // Use clone_from to recreate the input structure with mock wire IDs from child_component_meta
                    let mock_input = inputs.clone_from(&mut || child_component_meta.issue_wire());

                    let mut child_mode = StreamingMode::<M>::MetadataPass(child_component_meta);
                    let meta_wires_output = f(&mut child_mode, &mock_input).to_wires_vec();

                    match child_mode {
                        StreamingMode::MetadataPass(meta) => meta.build(&meta_wires_output),
                        _ => unreachable!(),
                    }
                });

                let instance =
                    template.to_instance(&pre_alloc_output_credits, |input_index, credits| {
                        let wire_id = input_wires[input_index];

                        if wire_id != TRUE_WIRE && wire_id != FALSE_WIRE {
                            trace!("try to add credits to {wire_id:?}");
                            mode.add_credits(&[wire_id], credits);
                        }
                    });

                // Unpin inputs: consume one remaining-use credit per input position.
                for input_wire_id in input_wires {
                    match input_wire_id {
                        WireId::UNREACHABLE => (),
                        TRUE_WIRE => (),
                        FALSE_WIRE => (),
                        wire_id => {
                            let _ = ctx.lookup_wire(wire_id).unwrap();
                        }
                    }
                }
                ctx.stack.push(instance);

                let output = f(self, &inputs);

                if let StreamingMode::ExecutionPass(ctx) = self {
                    let _used_child_meta = ctx.stack.pop();
                    #[cfg(test)]
                    assert!(_used_child_meta.unwrap().is_empty());
                }

                debug!("with_named_child: exit name={key:?} arity={arity}");
                output
            }
        }
    }
}

impl<M: CircuitMode> StreamingContext<M> {
    /// Pop `len` remaining-use counters from the current stack frame.
    pub fn pop_credits(&mut self, len: usize) -> Vec<Credits> {
        let stack = self.stack.last_mut().unwrap();

        iter::repeat_with(|| stack.next_credit().unwrap())
            .take(len)
            .collect::<Vec<_>>()
    }

    /// Allocate a new wire with its initial remaining-use counter.
    pub fn issue_wire_with_credit(&mut self) -> (WireId, Credits) {
        let meta = self.stack.last_mut().unwrap();

        if let Some(credit) = meta.next_credit() {
            let wire_id = self.mode.allocate_wire(credit);
            trace!("issue wire {wire_id:?} with {credit} remaining-use credits");
            (wire_id, credit)
        } else {
            unreachable!("No credits available")
        }
    }

    pub fn lookup_wire(&mut self, wire: WireId) -> Option<M::WireValue> {
        self.mode.lookup_wire(wire)
    }

    pub fn feed_wire(&mut self, wire: WireId, value: M::WireValue) {
        self.mode.feed_wire(wire, value);
    }

    pub fn add_credits(&mut self, wires: &[WireId], credits: NonZero<Credits>) {
        self.mode.add_credits(wires, credits);
    }

    pub fn finalize_ciphertext_accumulator(self) -> M::CiphertextAcc {
        self.mode.finalize_ciphertext_accumulator()
    }
}
