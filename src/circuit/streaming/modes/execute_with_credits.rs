use std::{cell::RefCell, collections::HashMap, iter};

use blake3;
use log::{debug, error, trace};

use crate::{
    CircuitContext, Gate, WireId,
    circuit::streaming::{
        CircuitMode, EncodeInput, FALSE_WIRE, TRUE_WIRE, WiresObject,
        component_meta::{ComponentMetaBuilder, ComponentMetaInstance, ComponentMetaTemplate},
    },
    core::gate_type::GateCount,
    storage::{Credits, Storage},
};

const ROOT_KEY: [u8; 16] = [0u8; 16];

#[derive(Clone, Copy, Debug, Default)]
pub enum OptionalBoolean {
    #[default]
    None,
    True,
    False,
}

#[derive(Debug)]
pub struct ExecuteContext {
    storage: RefCell<Storage<WireId, OptionalBoolean>>,
    stack: Vec<ComponentMetaInstance>,
    templates: HashMap<[u8; 16], ComponentMetaTemplate>,
    gate_count: GateCount,
}

impl ExecuteContext {
    pub fn issue_wire_with_credit(&mut self) -> (WireId, Credits) {
        let meta = self.stack.last_mut().unwrap();

        if let Some(credit) = meta.next_credit() {
            let wire_id = self
                .storage
                .borrow_mut()
                .allocate(OptionalBoolean::None, credit);
            trace!("issue wire {wire_id:?} with {credit} credit");
            (wire_id, credit)
        } else {
            unreachable!("{self:?}")
        }
    }

    pub fn pop_credits(&mut self, len: usize) -> Vec<Credits> {
        let stack = self.stack.last_mut().unwrap();

        iter::repeat_with(|| stack.next_credit().unwrap())
            .take(len)
            .collect::<Vec<_>>()
    }
}

impl CircuitMode for ExecuteContext {
    type WireValue = bool;

    fn lookup_wire(&self, wire: WireId) -> Option<&bool> {
        match wire {
            TRUE_WIRE => return Some(&true),
            FALSE_WIRE => return Some(&false),
            _ => (),
        }

        match self.storage.borrow_mut().get(wire).as_deref() {
            Ok(&OptionalBoolean::True) => Some(&true),
            Ok(&OptionalBoolean::False) => Some(&false),
            Ok(&OptionalBoolean::None) => {
                error!("lookup_wire: wire_id={} has no value yet", wire.0);
                panic!("value not writed: {wire:?}")
            }
            Err(err) => {
                error!(
                    "lookup_wire: storage error for wire_id={} err={:?}",
                    wire.0, err
                );
                panic!("Error: {err:?}")
            }
        }
    }

    fn feed_wire(&mut self, wire: WireId, value: bool) {
        trace!("feed wire {wire:?} with value: {value}");
        self.storage
            .borrow_mut()
            .set(wire, |data| {
                *data = if value {
                    OptionalBoolean::True
                } else {
                    OptionalBoolean::False
                };
            })
            .unwrap();
    }

    fn total_size(&self) -> usize {
        self.storage.borrow().len()
    }

    fn current_size(&self) -> usize {
        self.storage.borrow().len()
    }

    fn evaluate_gate(&mut self, gate: &Gate) -> Option<()> {
        self.gate_count.handle(gate.gate_type);

        if gate.wire_c == WireId::UNREACHABLE {
            return None;
        }

        assert_ne!(gate.wire_a, WireId::UNREACHABLE);
        assert_ne!(gate.wire_b, WireId::UNREACHABLE);

        let a = self.lookup_wire(gate.wire_a)?;
        let b = self.lookup_wire(gate.wire_b)?;

        let c = gate.execute(*a, *b);
        self.feed_wire(gate.wire_c, c);

        Some(())
    }
}

/// Prototype mode: single global storage keyed by `WireId` with credit-based lifetimes.
///
/// Notes:
/// - For now there is no prepass integration here; callers can `feed_wire` to seed inputs
///   and we consume credits on reads during gate evaluation.
/// - Constants are stored outside of `WireStorage` and don't consume credits.
#[derive(Debug)]
pub enum Execute {
    MetadataPass(ComponentMetaBuilder),
    ExecutePass(ExecuteContext),
}

impl Execute {
    pub fn new(capacity: usize) -> Self {
        Self::new_execute(capacity)
    }

    fn new_execute(capacity: usize) -> Self {
        Self::ExecutePass(ExecuteContext {
            storage: RefCell::new(Storage::new(capacity)),
            stack: vec![],
            templates: HashMap::default(),
            gate_count: GateCount::default(),
        })
    }

    fn new_meta(inputs: &[WireId]) -> Self {
        Self::MetadataPass(ComponentMetaBuilder::new(inputs))
    }

    pub fn to_root_ctx<I: EncodeInput<<Self as CircuitMode>::WireValue>>(
        self,
        capacity: usize,
        input: &I,
        meta_input_wires: &[WireId],
        meta_output_wires: &[WireId],
    ) -> (Self, I::WireRepr) {
        if let Self::MetadataPass(meta) = self {
            let meta = meta.build(meta_output_wires);

            let mut input_credits = vec![0; meta_input_wires.len()];

            let mut instance = meta.to_instance(
                meta_input_wires,
                &vec![1; meta_output_wires.len()],
                |wire_id, credits| {
                    let index = wire_id.0 - WireId::MIN.0;
                    let rev_index = meta_input_wires.len() - 1 - index;
                    input_credits[rev_index] += credits;
                },
            );

            instance.credits_stack.extend_from_slice(&input_credits);

            trace!("meta before input encode: {instance:?}");

            let mut ctx = Self::ExecutePass(ExecuteContext {
                storage: RefCell::new(Storage::new(capacity)),
                stack: vec![instance],
                templates: {
                    let mut map = HashMap::default();
                    map.insert(ROOT_KEY, meta);
                    map
                },
                gate_count: GateCount::default(),
            });

            let input_repr = input.allocate(|| ctx.issue_wire());
            input.encode(&input_repr, &mut ctx);

            if let Self::ExecutePass(ctx) = &ctx {
                trace!("meta after input encode: {:?}", ctx.stack.last().unwrap());
            }

            (ctx, input_repr)
        } else {
            panic!()
        }
    }

    pub fn issue_wire_with_credit(&mut self) -> (WireId, Credits) {
        match self {
            Self::MetadataPass(meta) => (meta.issue_wire(), 0),
            Self::ExecutePass(ctx) => ctx.issue_wire_with_credit(),
        }
    }

    pub fn non_free_gates_count(&self) -> usize {
        match self {
            Self::MetadataPass(_meta) => 0,
            Self::ExecutePass(ctx) => ctx.gate_count.nonfree_gate_count() as usize,
        }
    }

    pub fn total_gates_count(&self) -> usize {
        match self {
            Self::MetadataPass(_meta) => 0,
            Self::ExecutePass(ctx) => ctx.gate_count.total_gate_count() as usize,
        }
    }
}

impl CircuitMode for Execute {
    type WireValue = bool;

    fn lookup_wire(&self, wire: WireId) -> Option<&bool> {
        match wire {
            TRUE_WIRE => Some(&true),
            FALSE_WIRE => Some(&false),
            // Unreachable wires don't have values
            WireId::UNREACHABLE => None,
            wire => match self {
                Self::MetadataPass(_) => None,
                Self::ExecutePass(ctx) => ctx.lookup_wire(wire),
            },
        }
    }

    fn feed_wire(&mut self, wire: WireId, value: Self::WireValue) {
        if matches!(wire, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }

        match self {
            Self::ExecutePass(ctx) => ctx.feed_wire(wire, value),
            Self::MetadataPass(_meta) => (),
        }
    }

    fn total_size(&self) -> usize {
        match self {
            Self::ExecutePass(ctx) => ctx.total_size(),
            Self::MetadataPass(meta) => meta.credits_stack.len(),
        }
    }

    fn current_size(&self) -> usize {
        match self {
            Self::ExecutePass(ctx) => ctx.current_size(),
            Self::MetadataPass(meta) => meta.credits_stack.len(),
        }
    }

    fn evaluate_gate(&mut self, gate: &Gate) -> Option<()> {
        match self {
            Execute::MetadataPass(_meta) => None,
            Execute::ExecutePass(ctx) => ctx.evaluate_gate(gate),
        }
    }
}

impl CircuitContext for Execute {
    type Mode = Self;

    fn issue_wire(&mut self) -> WireId {
        self.issue_wire_with_credit().0
    }

    fn add_gate(&mut self, gate: Gate) {
        match self {
            Self::MetadataPass(meta) => meta.add_gate(gate),
            Self::ExecutePass(ctx) => {
                ctx.evaluate_gate(&gate);
            }
        }
    }

    fn with_named_child<O: WiresObject>(
        &mut self,
        key: &[u8; 16],
        input_wires: Vec<WireId>,
        f: impl Fn(&mut Self) -> O,
        output_arity: usize,
    ) -> O {
        let arity = output_arity;

        if let Self::MetadataPass(meta) = self {
            debug!("with_named_child: metapass enter name={key:?} arity={arity}");
            meta.increment_credits(&input_wires);

            // We just pre-alloc all outputs for handle credits
            let mock_output = iter::repeat_with(|| meta.issue_wire())
                .take(arity)
                .collect::<Vec<_>>();

            return O::from_wires(&mock_output).unwrap();
        }

        debug!("with_named_child: enter name={key:?} arity={arity}");

        let pre_alloc_output_credits = match self {
            Self::ExecutePass(ctx) => ctx.pop_credits(arity),
            _ => unreachable!(),
        };

        match self {
            Self::ExecutePass(ctx) => {
                trace!("Start component {key:?} meta take");

                // Derive a template-cache key that mixes the provided key with arity.
                // This avoids collisions between components that share the same key
                // but differ in output arity, while preserving a compact 16-byte key.
                let mut hasher = blake3::Hasher::new();
                hasher.update(key);
                hasher.update(&(arity as u64).to_le_bytes());
                hasher.update(&(input_wires.len() as u64).to_le_bytes());
                // Include the per-input "kind" (const true/false, unreachable, variable)
                // so templates keyed by the same name/arity but different constant layouts
                // don't collide and cause mismatched extra_input_credits.
                for w in &input_wires {
                    let tag: u8 = match *w {
                        TRUE_WIRE => 0x01,
                        FALSE_WIRE => 0x00,
                        WireId::UNREACHABLE => 0x02,
                        _ => 0x03,
                    };
                    hasher.update(&[tag]);
                }
                let hash = hasher.finalize();

                let mut template_key = [0u8; 16];
                template_key.copy_from_slice(&hash.as_bytes()[..16]);

                let child_component_meta_template =
                    ctx.templates.entry(template_key).or_insert_with(|| {
                        trace!("For key {key:?} generate template: arity {arity}, input_wires_len: {}, hash: {hash}", input_wires.len());
                        let mut child_component_meta = Self::new_meta(&input_wires);

                        let meta_wires_output = f(&mut child_component_meta).to_wires_vec();

                        match child_component_meta {
                            Self::MetadataPass(meta) => meta.build(&meta_wires_output),
                            _ => unreachable!(),
                        }
                    });

                let mut storage = ctx.storage.borrow_mut();

                let instance = child_component_meta_template.to_instance(
                    &input_wires,
                    &pre_alloc_output_credits,
                    |wire_id, credits| {
                        storage.add_credits(wire_id, credits).unwrap();
                    },
                );

                //#[cfg(test)]
                //{
                //    let child_component_meta_template = ctx.templates.get(&template_key).unwrap();

                //    let instance_from_cache = child_component_meta_template.to_instance(
                //        &input_wires,
                //        &pre_alloc_output_credits,
                //        |wire_id, credits| {
                //            storage.add_credits(wire_id, credits).unwrap();
                //        },
                //    );

                //    assert_eq!(instance, instance_from_cache);
                //}

                // TODO Optimize unpin input
                for input_wire_id in input_wires {
                    match input_wire_id {
                        WireId::UNREACHABLE => (),
                        TRUE_WIRE => (),
                        FALSE_WIRE => (),
                        wire_id => {
                            let _ = storage.get(wire_id).unwrap();
                        }
                    }
                }
                ctx.stack.push(instance);
            }
            _ => unreachable!(),
        };

        let output = f(self);

        match self {
            Self::ExecutePass(ctx) => {
                let _used_child_meta = ctx.stack.pop();
                #[cfg(test)]
                assert!(_used_child_meta.unwrap().is_empty());
            }
            _ => unreachable!(),
        };

        debug!("with_named_child: exit name={key:?} arity={arity}");

        output
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
