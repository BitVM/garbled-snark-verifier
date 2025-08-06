#![allow(dead_code)]

use std::collections::HashMap;

use slotmap::{new_key_type, SlotMap};

use crate::{Gate, WireId};

mod into_wire_list;
pub use into_wire_list::IntoWireList;

// Compatibility alias for existing code
pub trait IntoWires {
    fn get_wires_vec(&self) -> Vec<WireId>;
}

impl<T: IntoWireList + Clone> IntoWires for T {
    fn get_wires_vec(&self) -> Vec<WireId> {
        self.clone().into_wire_list()
    }
}

/// Simplified CircuitContext trait for hierarchical circuit building
/// Focuses on core operations without flat circuit input/output designation
pub trait CircuitContext {
    type Mode: CircuitMode;

    /// Allocates a new wire and returns its identifier
    fn issue_wire(&mut self) -> WireId;

    /// Adds a gate to the current component
    fn add_gate(&mut self, gate: Gate);

    fn with_child<O: IntoWires>(
        &mut self,
        input_wires: Vec<WireId>,
        f: impl FnOnce(&mut ComponentHandle<Self::Mode>) -> O,
    ) -> O;
}

// Constants available to all context users
pub const FALSE_WIRE: WireId = WireId(0);
pub const TRUE_WIRE: WireId = WireId(1);

new_key_type! { pub struct ComponentId; }

#[derive(Clone, Debug)]
pub enum Action {
    Gate(Gate),
    Call { id: ComponentId },
}

#[derive(Clone, Debug)]
pub struct Component {
    pub internal_wire_offset: usize,
    pub num_wire: usize,
    pub input_wires: Vec<WireId>,
    pub output_wires: Vec<WireId>,
    pub actions: Vec<Action>,
}

impl Component {
    pub fn empty_root() -> Self {
        Self {
            internal_wire_offset: 0,
            num_wire: 2,
            input_wires: Vec::new(),
            output_wires: Vec::new(),
            actions: Vec::new(),
        }
    }
}

pub struct ComponentPool(SlotMap<ComponentId, Component>);

impl ComponentPool {
    fn insert(&mut self, c: Component) -> ComponentId {
        self.0.insert(c)
    }

    fn remove(&mut self, id: ComponentId) {
        self.0.remove(id);
    }

    fn get(&self, id: ComponentId) -> &Component {
        &self.0[id]
    }

    fn get_mut(&mut self, id: ComponentId) -> &mut Component {
        &mut self.0[id]
    }

    fn take(&mut self, id: ComponentId) -> Component {
        self.0.remove(id).unwrap()
    }
}

pub trait ModeCache: Default {
    type Value;

    fn lookup_wire(&self, wire: WireId) -> Option<Self::Value>;

    fn feed_wire(&mut self, wire: WireId, value: Self::Value);

    fn size(&self) -> usize;

    fn clean_session(&mut self, keep_wires: &[WireId]);
}

#[derive(Default, Clone)]
pub struct WireCache<T> {
    values: HashMap<WireId, T>,
}

impl ModeCache for WireCache<bool> {
    type Value = bool;

    fn lookup_wire(&self, wire: WireId) -> Option<bool> {
        match wire {
            FALSE_WIRE => Some(false),
            TRUE_WIRE => Some(true),
            wire => self.values.get(&wire).copied(),
        }
    }

    fn feed_wire(&mut self, wire: WireId, value: bool) {
        self.values.insert(wire, value);
    }

    fn size(&self) -> usize {
        self.values.len()
    }

    fn clean_session(&mut self, keep_wires: &[WireId]) {
        self.values
            .retain(|wire_id, _| keep_wires.contains(wire_id));
    }
}

fn is_true_leaf(component: &Component) -> bool {
    component
        .actions
        .iter()
        .all(|action| matches!(action, Action::Gate(_)))
}

pub struct ComponentHandle<'a, M: CircuitMode> {
    id: ComponentId,
    builder: &'a mut CircuitBuilder<M>,
}

impl<'a, M: CircuitMode> ComponentHandle<'a, M> {
    /// Direct access to the underlying component (for metadata operations)
    pub fn get_component(&mut self) -> &mut Component {
        self.builder.pool.get_mut(self.id)
    }
}

// Implement the CircuitContext trait for ComponentHandle
impl<'a, M: CircuitMode> CircuitContext for ComponentHandle<'a, M> {
    type Mode = M;

    fn issue_wire(&mut self) -> WireId {
        self.builder.allocate_wire()
    }

    fn add_gate(&mut self, gate: Gate) {
        self.builder
            .pool
            .get_mut(self.id)
            .actions
            .push(Action::Gate(gate));
    }

    /// Creates a child component with the given input wires
    /// Returns the output wires produced by the child
    fn with_child<O: IntoWires>(
        &mut self,
        input_wires: Vec<WireId>,
        f: impl FnOnce(&mut ComponentHandle<M>) -> O,
    ) -> O {
        // Create child component
        let mut child = Component::empty_root();
        child.input_wires = input_wires.clone();
        // Set internal wire tracking for streaming garbling
        child.internal_wire_offset = self.builder.next_wire_id;

        // Insert child into pool
        let child_id = self.builder.pool.insert(child);

        // Push to stack
        self.builder.stack.push(child_id);

        let mut child_handle = ComponentHandle {
            id: child_id,
            builder: self.builder,
        };

        // Execute closure to build child and get output wires
        // Pass input wires as slice to the closure
        let output_wires = f(&mut child_handle);

        // Update child's output wires and wire count for truncation
        let child_component = self.builder.pool.get_mut(child_id);
        child_component.output_wires = output_wires.get_wires_vec();
        child_component.num_wire = self.builder.next_wire_id - child_component.internal_wire_offset;

        // TODO Check order of two next expression

        // Pop from stack and handle exit logic
        self.builder.exit_component();

        // Add call action to parent
        self.builder
            .pool
            .get_mut(self.id)
            .actions
            .push(Action::Call { id: child_id });

        output_wires
    }
}

pub trait CircuitMode {
    type Cache: ModeCache;

    fn evaluate_component(
        component: ComponentId,
        pool: &mut ComponentPool,
        cache: &mut Self::Cache,
    ) -> Result<Vec<(WireId, bool)>, &'static str>;
}

pub struct Evaluate;
impl CircuitMode for Evaluate {
    type Cache = WireCache<bool>;

    fn evaluate_component(
        component_id: ComponentId,
        pool: &mut ComponentPool,
        parent_cache: &mut WireCache<bool>,
    ) -> Result<Vec<(WireId, bool)>, &'static str> {
        let component = pool.get(component_id).clone();

        let mut local_cache = WireCache::default();

        println!(
            "DEBUG: evaluate_component({component_id:?}) processing input wires: {:?}",
            component.input_wires
        );
        for &wire_id in &component.input_wires {
            println!("DEBUG: Looking for input wire {wire_id:?} in parent cache");
            let value = parent_cache
                .lookup_wire(wire_id)
                .ok_or("Missing input wire value")?;

            local_cache.feed_wire(wire_id, value);
            println!("DEBUG: Fed wire {wire_id:?} into local cache");
        }

        // Process actions
        for action in &component.actions {
            match action {
                Action::Gate(gate) => {
                    println!("Process {gate:?}");
                    let a = local_cache
                        .lookup_wire(gate.wire_a)
                        .ok_or("Wire A not evaluated")?;
                    let b = local_cache
                        .lookup_wire(gate.wire_b)
                        .ok_or("Wire B not evaluated")?;

                    let c = (gate.gate_type.f())(a, b);
                    local_cache.feed_wire(gate.wire_c, c);
                }
                Action::Call { id } => {
                    let child_outputs = Self::evaluate_component(*id, pool, &mut local_cache)?;

                    println!(
                        "  Successfully evaluated child component {:?} with {} outputs",
                        id,
                        child_outputs.len()
                    );

                    // Feed child outputs into our local cache
                    for (wire_id, value) in child_outputs {
                        local_cache.feed_wire(wire_id, value);
                    }
                }
            }
        }

        let outputs: Vec<(WireId, bool)> = component
            .output_wires
            .iter()
            .map(|&wire_id| {
                let value = local_cache
                    .lookup_wire(wire_id)
                    .ok_or("Output wire not evaluated")?;
                Ok((wire_id, value))
            })
            .collect::<Result<Vec<_>, &'static str>>()?;

        for (wire_id, value) in &outputs {
            parent_cache.feed_wire(*wire_id, *value);
        }

        Ok(outputs)
    }
}

//pub struct Garble;
//impl CircuitMode for Garble {
//    type Cache = HashMap<WireId, ([u8; 16], [u8; 16])>;
//}
//
//pub struct CheckGarbling;
//impl CircuitMode for CheckGarbling {
//    type Cache = HashMap<WireId, [u8; 16]>;
//}

pub struct CircuitBuilder<M: CircuitMode> {
    pool: ComponentPool,
    stack: Vec<ComponentId>,
    counting_mode: bool,
    depth_count: usize,
    max_depth: usize,
    wire_cache: M::Cache,
    next_wire_id: usize,
}

impl<M: CircuitMode> CircuitBuilder<M> {
    pub fn streaming_process<I, F>(
        max_depth: usize,
        inputs: I,
        f: F,
    ) -> Vec<<M::Cache as ModeCache>::Value>
    where
        I: CircuitInput + EncodeInput<M>,
        F: FnOnce(&mut ComponentHandle<M>, I::WireRepr) -> Vec<WireId>,
    {
        let mut builder = Self {
            pool: ComponentPool(SlotMap::with_key()),
            stack: vec![],
            counting_mode: false,
            depth_count: 0,
            max_depth,
            wire_cache: M::Cache::default(),
            next_wire_id: 2,
        };

        let root_id = builder.pool.insert(Component::empty_root());
        builder.stack.push(root_id);

        let mut root_handle = ComponentHandle {
            id: root_id,
            builder: &mut builder,
        };

        // Allocate input wires using the input type
        let inputs_wire = I::allocate(&mut root_handle);
        println!("DEBUG: Input wires allocated");

        root_handle.get_component().input_wires = I::collect_wire_ids(&inputs_wire);

        // Push inputs into cache
        inputs.encode(&inputs_wire, &mut root_handle.builder.wire_cache);

        // Here real eval can be start
        let output = f(&mut root_handle, inputs_wire);
        root_handle.get_component().output_wires = output.into_wire_list();

        // Finish evaluation
        root_handle.builder.evaluate_subgraph(root_id);

        let output = root_handle.get_component().output_wires.clone();

        output
            .iter()
            .copied()
            .map(|wire_id| {
                builder
                    .wire_cache
                    .lookup_wire(wire_id)
                    .unwrap_or_else(|| panic!("output wire not presetened: {wire_id:?}"))
            })
            .collect::<Vec<_>>()
    }

    pub fn global_input(&self) -> &[WireId] {
        let root = self.stack.first().unwrap();
        &self.pool.get(*root).input_wires
    }

    pub fn current_component(&mut self) -> ComponentHandle<M> {
        let current_id = *self.stack.last().unwrap();
        ComponentHandle {
            id: current_id,
            builder: self,
        }
    }

    pub fn allocate_wire(&mut self) -> WireId {
        let wire = WireId(self.next_wire_id);
        self.next_wire_id += 1;
        wire
    }

    pub fn exit_component(&mut self) {
        let id = self.stack.pop().expect("unbalanced exit_component");

        // Always evaluate when we exit the root component (stack becomes empty)
        if self.stack.is_empty() {
            println!("Exiting root component {id:?}, evaluating entire graph");
            self.evaluate_subgraph(id);
            return;
        }

        // Streaming evaluation logic for non-root components
        if !self.counting_mode && is_true_leaf(&self.pool.0[id]) {
            self.counting_mode = true;
            self.depth_count = 1;
            println!("Started counting from leaf component {id:?} with output_wires: {:?}", self.pool.get(id).output_wires);
        } else if self.counting_mode {
            self.depth_count += 1;
            println!("Counting depth: {}/{}, component {id:?} with output_wires: {:?}", self.depth_count, self.max_depth, self.pool.get(id).output_wires);

            if self.depth_count == self.max_depth {
                println!("Reached max depth, evaluating buffered components");
                self.evaluate_subgraph(id);
                self.counting_mode = false;
                self.depth_count = 0;
            }
        }
    }

    pub fn add_gate(&mut self, gate: Gate) {
        let &current = self.stack.last().expect("no open component");
        self.pool.get_mut(current).actions.push(Action::Gate(gate));
    }

    pub fn evaluate_subgraph(&mut self, id: ComponentId) {
        // Feed component inputs from existing wire cache
        println!(
            "DEBUG: Component {id:?} expects input wires: {:?}, output wires: {:?}",
            self.pool.get(id).input_wires,
            self.pool.get(id).output_wires
        );
        for wire_id in self.pool.get(id).input_wires.iter().copied() {
            if self.wire_cache.lookup_wire(wire_id).is_none() {
                println!("Warning: Input wire {wire_id:?} not in cache");
            } else {
                println!("DEBUG: Found input wire {wire_id:?} in cache");
            }
        }

        println!("Cache size before evaluation: {}", self.wire_cache.size());
        println!(
            "DEBUG: Cache has WireId(2): {}, WireId(3): {}",
            self.wire_cache.lookup_wire(WireId(2)).is_some(),
            self.wire_cache.lookup_wire(WireId(3)).is_some()
        );

        let outputs = M::evaluate_component(id, &mut self.pool, &mut self.wire_cache).unwrap();

        println!("Evaluated component {id:?}, got {} outputs", outputs.len());

        let mut keep_wires = vec![];
        let output_wires: Vec<WireId> = outputs.iter().map(|(wire_id, _)| *wire_id).collect();

        keep_wires.extend(self.pool.get(id).input_wires.clone());
        keep_wires.extend(output_wires);

        for (wire_id, value) in outputs {
            println!("  Output wire {wire_id:?} = {value}");
        }

        // Clean cache after session, keeping constants, inputs and outputs for next session
        self.wire_cache.clean_session(&keep_wires);

        println!(
            "Cache size after session cleanup: {}",
            self.wire_cache.size()
        );
    }
}

// ――― Input Provisioning System ―――

/// Trait for types that can be converted to bit vectors
pub trait ToBits {
    fn to_bits_le(&self) -> Vec<bool>;
}

impl ToBits for bool {
    fn to_bits_le(&self) -> Vec<bool> {
        vec![*self]
    }
}

impl ToBits for u64 {
    fn to_bits_le(&self) -> Vec<bool> {
        (0..64).map(|i| (self >> i) & 1 == 1).collect()
    }
}

/// Trait for allocating wire representations of input types
pub trait CircuitInput {
    type WireRepr;
    fn allocate<C: CircuitContext>(ctx: &mut C) -> Self::WireRepr;
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId>;
}

/// Trait for encoding semantic values into mode-specific caches
pub trait EncodeInput<M: CircuitMode>: Sized + CircuitInput {
    fn encode(self, repr: &Self::WireRepr, cache: &mut M::Cache);
}

// ――― Example Implementation ―――

/// Example input structure with mixed types
pub struct Inputs {
    pub flag: bool,
    pub nonce: u64,
}

/// Wire representation of Inputs
pub struct InputsWire {
    pub flag: WireId,
    pub nonce: [WireId; 64],
}

impl CircuitInput for Inputs {
    type WireRepr = InputsWire;

    fn allocate<C: CircuitContext>(ctx: &mut C) -> Self::WireRepr {
        InputsWire {
            flag: ctx.issue_wire(),
            nonce: core::array::from_fn(|_| ctx.issue_wire()),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut wires = vec![repr.flag];
        wires.extend_from_slice(&repr.nonce);
        wires
    }
}

impl EncodeInput<Evaluate> for Inputs {
    fn encode(self, repr: &InputsWire, cache: &mut WireCache<bool>) {
        cache.feed_wire(repr.flag, self.flag);
        let bits = self.nonce.to_bits_le();
        for (i, bit) in bits.into_iter().enumerate() {
            cache.feed_wire(repr.nonce[i], bit);
        }
    }
}

// ――― Simple Input Types for Basic Tests ―――

/// Simple two-input structure for basic circuit tests
pub struct SimpleInputs {
    pub a: bool,
    pub b: bool,
}

pub struct SimpleInputsWire {
    pub a: WireId,
    pub b: WireId,
}

impl CircuitInput for SimpleInputs {
    type WireRepr = SimpleInputsWire;

    fn allocate<C: CircuitContext>(ctx: &mut C) -> Self::WireRepr {
        let a = ctx.issue_wire();
        let b = ctx.issue_wire();
        println!("DEBUG: SimpleInputs allocated wire A: {a:?}, wire B: {b:?}");
        SimpleInputsWire { a, b }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![repr.a, repr.b]
    }
}

impl EncodeInput<Evaluate> for SimpleInputs {
    fn encode(self, repr: &SimpleInputsWire, cache: &mut WireCache<bool>) {
        println!(
            "DEBUG: Encoding wire A: {a:?} = {av}, wire B: {b:?} = {bv}",
            a = repr.a,
            av = self.a,
            b = repr.b,
            bv = self.b
        );
        cache.feed_wire(repr.a, self.a);
        cache.feed_wire(repr.b, self.b);
    }
}

/// Three-input structure for macro tests
pub struct TripleInputs {
    pub a: bool,
    pub b: bool,
    pub c: bool,
}

pub struct TripleInputsWire {
    pub a: WireId,
    pub b: WireId,
    pub c: WireId,
}

impl CircuitInput for TripleInputs {
    type WireRepr = TripleInputsWire;

    fn allocate<C: CircuitContext>(ctx: &mut C) -> Self::WireRepr {
        TripleInputsWire {
            a: ctx.issue_wire(),
            b: ctx.issue_wire(),
            c: ctx.issue_wire(),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![repr.a, repr.b, repr.c]
    }
}

impl EncodeInput<Evaluate> for TripleInputs {
    fn encode(self, repr: &TripleInputsWire, cache: &mut WireCache<bool>) {
        cache.feed_wire(repr.a, self.a);
        cache.feed_wire(repr.b, self.b);
        cache.feed_wire(repr.c, self.c);
    }
}

#[cfg(test)]
mod test_macro;

#[cfg(test)]
mod eval_test {
    use super::*;

    #[test]
    fn simple() {
        let inputs = Inputs {
            flag: true,
            nonce: u64::MAX,
        };

        let output =
            CircuitBuilder::<Evaluate>::streaming_process(2, inputs, |root, inputs_wire| {
                let InputsWire { flag, nonce } = inputs_wire;

                let result = root.issue_wire();
                root.add_gate(Gate::and(flag, nonce[0], result));

                vec![result]
            });

        assert!(output[0])
    }

    #[test]
    fn test_multi_wire_inputs() {
        // Define input values
        let inputs = Inputs {
            flag: true,
            nonce: 0xDEADBEEF12345678,
        };

        let output =
            CircuitBuilder::<Evaluate>::streaming_process(2, inputs, |root, inputs_wire| {
                // Create some logic using the allocated wires
                // Test flag AND first bit of nonce
                let InputsWire { flag, nonce } = inputs_wire;

                let result1 = root.issue_wire();
                root.add_gate(Gate::and(flag, nonce[0], result1));

                // Test XOR of two nonce bits
                let result2 = root.with_child(vec![nonce[1], nonce[2]], |child| {
                    let result2 = child.issue_wire();
                    child.add_gate(Gate::xor(nonce[1], nonce[2], result2));
                    result2
                });

                // Final AND of the two results
                let final_result = root.issue_wire();
                root.add_gate(Gate::and(result1, result2, final_result));

                vec![final_result]
            });

        assert!(!output[0]);
    }
}
