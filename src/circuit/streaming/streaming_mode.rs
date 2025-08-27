use std::collections::{HashMap, hash_map::Entry};

use log::{debug, error, trace};

use crate::{
    CircuitContext, Gate, WireId,
    circuit::streaming::{
        CircuitMode, ComponentMetaBuilder, FALSE_WIRE, TRUE_WIRE, WiresObject,
        component_key::ComponentKey,
        component_meta::{ComponentMetaInstance, ComponentMetaTemplate},
    },
    core::gate_type::GateCount,
    storage::{Credits, Storage},
};

/// Generic streaming context that holds mode-specific evaluation logic
/// along with shared infrastructure (storage, templates, component stack)
#[derive(Debug)]
pub struct StreamingContext<M: CircuitMode> {
    pub mode: M,
    pub storage: Storage<WireId, M::StorageValue>,
    pub stack: Vec<ComponentMetaInstance>,
    pub templates: HashMap<ComponentKey, ComponentMetaTemplate>,
    pub gate_count: GateCount,
}

/// Two-phase streaming execution: metadata collection and actual execution
/// This generic enum replaces the Execute-specific enum pattern
#[derive(Debug)]
pub enum StreamingMode<M: CircuitMode> {
    MetadataPass(ComponentMetaBuilder),
    ExecutionPass(StreamingContext<M>),
}

// Implement CircuitMode for StreamingMode for backward compatibility
impl<M: CircuitMode> CircuitMode for StreamingMode<M> {
    type WireValue = M::WireValue;
    type StorageValue = M::StorageValue;

    fn false_value(&self) -> M::WireValue {
        match self {
            StreamingMode::MetadataPass(_) => panic!("Cannot get false value in metadata pass"),
            StreamingMode::ExecutionPass(ctx) => ctx.mode.false_value(),
        }
    }

    fn true_value(&self) -> M::WireValue {
        match self {
            StreamingMode::MetadataPass(_) => panic!("Cannot get true value in metadata pass"),
            StreamingMode::ExecutionPass(ctx) => ctx.mode.true_value(),
        }
    }

    fn default_storage_value() -> M::StorageValue {
        M::default_storage_value()
    }

    fn storage_to_wire(&self, stored: &M::StorageValue) -> Option<M::WireValue> {
        match self {
            StreamingMode::MetadataPass(_) => None,
            StreamingMode::ExecutionPass(ctx) => ctx.mode.storage_to_wire(stored),
        }
    }

    fn wire_to_storage(&self, value: M::WireValue) -> M::StorageValue {
        match self {
            StreamingMode::MetadataPass(_) => M::default_storage_value(),
            StreamingMode::ExecutionPass(ctx) => ctx.mode.wire_to_storage(value),
        }
    }

    fn evaluate_gate(&mut self, gate: &Gate, a: M::WireValue, b: M::WireValue) -> M::WireValue {
        match self {
            StreamingMode::MetadataPass(_) => panic!("Cannot evaluate gate in metadata pass"),
            StreamingMode::ExecutionPass(ctx) => ctx.mode.evaluate_gate(gate, a, b),
        }
    }

    fn lookup_wire(&mut self, wire: WireId) -> Option<M::WireValue> {
        match self {
            StreamingMode::MetadataPass(_) => None,
            StreamingMode::ExecutionPass(ctx) => ctx.lookup_wire(wire),
        }
    }

    fn feed_wire(&mut self, wire: WireId, value: M::WireValue) {
        if matches!(wire, TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE) {
            return;
        }

        match self {
            StreamingMode::MetadataPass(_) => (),
            StreamingMode::ExecutionPass(ctx) => ctx.feed_wire(wire, value),
        }
    }
}

// Helper methods for StreamingMode to support existing code
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

    pub fn is_storage_empty(&self) -> bool {
        match self {
            StreamingMode::MetadataPass(component_meta_builder) => {
                component_meta_builder.credits_stack.is_empty()
            }
            StreamingMode::ExecutionPass(streaming_context) => streaming_context.storage.is_empty(),
        }
    }

    pub fn iter_storage(&self) -> impl IntoIterator<Item = (WireId, M::StorageValue)> {
        match self {
            StreamingMode::ExecutionPass(streaming_context) => {
                streaming_context.storage.clone().to_iter()
            }
            StreamingMode::MetadataPass(_component_meta_builder) => {
                todo!()
            }
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

                let a = ctx.lookup_wire(gate.wire_a).unwrap();
                let b = ctx.lookup_wire(gate.wire_b).unwrap();

                if gate.wire_c == WireId::UNREACHABLE {
                    return;
                }

                let c_val = ctx.mode.evaluate_gate(&gate, a, b);
                ctx.feed_wire(gate.wire_c, c_val);
            }
        }
    }

    fn with_named_child<O: WiresObject>(
        &mut self,
        key: ComponentKey,
        input_wires: Vec<WireId>,
        f: impl Fn(&mut Self) -> O,
        arity: usize,
    ) -> O {
        match self {
            StreamingMode::MetadataPass(meta) => {
                debug!("with_named_child: metapass enter name={key:?} arity={arity}");
                meta.increment_credits(&input_wires);

                // We just pre-alloc all outputs for handle credits
                let mock_output = std::iter::repeat_with(|| meta.issue_wire())
                    .take(arity)
                    .collect::<Vec<_>>();

                O::from_wires(&mock_output).unwrap()
            }
            StreamingMode::ExecutionPass(ctx) => {
                debug!("with_named_child: enter name={key:?} arity={arity}");

                // Extract what we need and push to stack
                let pre_alloc_output_credits =
                    std::iter::repeat_with(|| ctx.stack.last_mut().unwrap().next_credit().unwrap())
                        .take(arity)
                        .collect::<Vec<_>>();

                trace!("Start component {key:?} meta take");
                let build_template = || {
                    trace!(
                        "For key {key:?} generate template: arity {arity}, input_wires_len: {}",
                        input_wires.len()
                    );
                    let child_component_meta = ComponentMetaBuilder::new(&input_wires);
                    let mut child_mode = StreamingMode::<M>::MetadataPass(child_component_meta);
                    let meta_wires_output = f(&mut child_mode).to_wires_vec();

                    match child_mode {
                        StreamingMode::MetadataPass(meta) => meta.build(&meta_wires_output),
                        _ => unreachable!(),
                    }
                };

                let storage = &mut ctx.storage;

                let misscache = input_wires
                    .iter()
                    .any(|wire_id| wire_id == &TRUE_WIRE || wire_id == &FALSE_WIRE);

                let mut to_instance = |template: &ComponentMetaTemplate| {
                    template.to_instance(
                        &input_wires,
                        &pre_alloc_output_credits,
                        |wire_id, credits| {
                            storage.add_credits(wire_id, credits).unwrap();
                        },
                    )
                };

                let instance = match (misscache, ctx.templates.entry(key)) {
                    (_, Entry::Occupied(template)) => to_instance(template.get()),
                    // Can't save result in cache, build and go
                    (true, Entry::Vacant(_)) => to_instance(&build_template()),
                    // Save result in cache and reuse
                    (false, Entry::Vacant(place)) => to_instance(place.insert(build_template())),
                };

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

                // Now call f with self
                let output = f(self);

                // Pop from stack
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
    pub fn issue_wire_with_credit(&mut self) -> (WireId, Credits) {
        let meta = self.stack.last_mut().unwrap();

        if let Some(credit) = meta.next_credit() {
            let wire_id = self.storage.allocate(M::default_storage_value(), credit);
            trace!("issue wire {wire_id:?} with {credit} credit");
            (wire_id, credit)
        } else {
            unreachable!("No credits available")
        }
    }

    pub fn lookup_wire(&mut self, wire: WireId) -> Option<M::WireValue> {
        match wire {
            TRUE_WIRE => return Some(self.mode.true_value()),
            FALSE_WIRE => return Some(self.mode.false_value()),
            WireId::UNREACHABLE => return None,
            _ => (),
        }

        match self.storage.get(wire) {
            Ok(stored) => self.mode.storage_to_wire(&*stored),
            Err(err) => {
                error!(
                    "lookup_wire: storage error for wire_id={} err={:?}",
                    wire.0, err
                );
                panic!("Error: {err:?}")
            }
        }
    }

    pub fn feed_wire(&mut self, wire: WireId, value: M::WireValue) {
        trace!("feed wire {wire:?}");
        let stored = self.mode.wire_to_storage(value);
        self.storage.set(wire, |data| *data = stored).unwrap();
    }
}
