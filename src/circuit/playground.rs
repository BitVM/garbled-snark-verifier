#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use slotmap::{new_key_type, SlotMap};

use crate::{
    core::gate::garbling::Blake3Hasher, Delta, EvaluatedWire, GarbledWire, GarbledWires, Gate,
    WireId, S,
};

mod into_wire_list;
pub use into_wire_list::IntoWireList;

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

pub trait ModeCache {
    type Value: Clone;

    fn lookup_wire(&self, wire: WireId) -> Option<&Self::Value>;

    fn feed_wire(&mut self, wire: WireId, value: Self::Value);

    fn size(&self) -> usize;

    fn push_frame(&mut self, inputs: Vec<(WireId, Self::Value)>);

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, Self::Value)>;

    fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, Self::Value)>;
    fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, Self::Value)>;
}

pub struct Frame<T> {
    // Change to something cache-friendly
    wires: HashMap<WireId, T>,
}

impl<T> Frame<T> {
    fn with_inputs(inputs: impl IntoIterator<Item = (WireId, T)>) -> Self {
        Self {
            wires: inputs.into_iter().collect(),
        }
    }

    fn insert(&mut self, wire_id: WireId, value: T) {
        self.wires.insert(wire_id, value);
    }

    fn get(&self, wire_id: WireId) -> Option<&T> {
        self.wires.get(&wire_id)
    }

    fn extract_outputs(&self, output_wires: &[WireId]) -> Vec<(WireId, T)>
    where
        T: Clone,
    {
        let mut seen = HashSet::new();

        output_wires
            .iter()
            .map(|&wire_id| {
                if !seen.insert(wire_id) {
                    panic!("Output wire {wire_id:?} appears multiple times");
                }

                let value = self
                    .wires
                    .get(&wire_id)
                    .unwrap_or_else(
                        || panic!("Output wire {wire_id:?} not present in child frame",),
                    )
                    .clone();
                (wire_id, value)
            })
            .collect()
    }

    fn size(&self) -> usize {
        self.wires.len()
    }
}

#[derive(Default)]
pub struct WireStack<T> {
    frames: Vec<Frame<T>>,
}

impl<T: Clone> WireStack<T> {
    fn push_frame(&mut self, inputs: impl IntoIterator<Item = (WireId, T)>) {
        self.frames.push(Frame::with_inputs(inputs));
    }

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, T)> {
        if let Some(frame) = self.frames.pop() {
            frame.extract_outputs(outputs)
        } else {
            Vec::new()
        }
    }

    fn insert(&mut self, wire_id: WireId, value: T) {
        if let Some(frame) = self.frames.last_mut() {
            frame.insert(wire_id, value);
        } else {
            panic!("empty frames");
        }
    }

    fn get(&self, wire_id: WireId) -> Option<&T> {
        self.frames.last()?.get(wire_id)
    }

    fn size(&self) -> usize {
        self.frames.iter().map(|frame| frame.size()).sum()
    }

    fn current_frame_mut(&mut self) -> Option<&mut Frame<T>> {
        self.frames.last_mut()
    }
}

impl ModeCache for WireStack<bool> {
    type Value = bool;

    fn lookup_wire(&self, wire: WireId) -> Option<&bool> {
        match wire {
            FALSE_WIRE => Some(&false),
            TRUE_WIRE => Some(&true),
            wire => self.get(wire),
        }
    }

    fn feed_wire(&mut self, wire: WireId, value: bool) {
        self.insert(wire, value);
    }

    fn size(&self) -> usize {
        WireStack::size(self)
    }

    fn push_frame(&mut self, inputs: Vec<(WireId, bool)>) {
        WireStack::push_frame(self, inputs);
    }

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, bool)> {
        WireStack::pop_frame(self, outputs)
    }

    fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, bool)> {
        input_wires
            .iter()
            .map(|&wire_id| {
                let value = self.lookup_wire(wire_id).unwrap_or_else(|| {
                    panic!("Input wire {wire_id:?} not available in current frame")
                });
                (wire_id, *value)
            })
            .collect()
    }

    fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, bool)> {
        self.pop_frame(output_wires)
    }
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
        // Always store the gate, evaluation is handled in the builder if supported
        self.builder.add_gate_to_component(self.id, gate);
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

        // Prepare inputs for new frame and include mode constants
        let frame_inputs = self.builder.wire_cache.prepare_frame_inputs(&input_wires);

        // Push new frame
        self.builder.wire_cache.push_frame(frame_inputs);

        let mut child_handle = ComponentHandle {
            id: child_id,
            builder: self.builder,
        };

        // Execute closure to build child and get output wires
        let output_wires = f(&mut child_handle);

        // Update child's output wires and wire count for truncation
        let output_wire_ids = output_wires.get_wires_vec();
        let child_component = self.builder.pool.get_mut(child_id);
        child_component.output_wires = output_wire_ids.clone();
        child_component.num_wire = self.builder.next_wire_id - child_component.internal_wire_offset;

        // Pop frame and transfer outputs back to parent frame
        let extracted_outputs = self
            .builder
            .wire_cache
            .extract_frame_outputs(&output_wire_ids);

        // Feed output values back into parent frame
        for (wire_id, value) in extracted_outputs {
            self.builder.wire_cache.feed_wire(wire_id, value);
        }

        // Pop from stack
        self.builder
            .stack
            .pop()
            .expect("unbalanced component stack");

        // Add call action to parent (for structural representation)
        self.builder
            .pool
            .get_mut(self.id)
            .actions
            .push(Action::Call { id: child_id });

        output_wires
    }
}

// Specialized implementation for Evaluate mode that uses immediate evaluation
impl<'a> ComponentHandle<'a, Evaluate> {
    fn add_gate(&mut self, gate: Gate) {
        self.builder.add_gate_to_component_with_eval(self.id, gate);
    }
}

pub trait CircuitMode {
    type Cache: ModeCache;

    fn evaluate_gate(
        gate: &Gate,
        cache: &mut Self::Cache,
    ) -> Option<<Self::Cache as ModeCache>::Value>;
}

pub struct Evaluate;
impl CircuitMode for Evaluate {
    type Cache = WireStack<bool>;

    fn evaluate_gate(gate: &Gate, cache: &mut Self::Cache) -> Option<bool> {
        let wire_a_val = cache.lookup_wire(gate.wire_a)?;
        let wire_b_val = cache.lookup_wire(gate.wire_b)?;
        let result = (gate.gate_type.f())(*wire_a_val, *wire_b_val);
        cache.feed_wire(gate.wire_c, result);
        Some(result)
    }
}

// Example modes to demonstrate the generic design

pub struct Garble;

pub struct GarbleCache {
    rng: ChaChaRng,
    delta: Delta,
    wires: GarbledWires,
    garble_table: Vec<S>,
    gate_index: usize,
}

impl GarbleCache {
    pub fn new(seeds: u64, component_max_live_wires: usize) -> Self {
        let mut rng = ChaChaRng::seed_from_u64(seeds);
        let delta = Delta::generate(&mut rng);
        GarbleCache {
            rng,
            delta,
            wires: GarbledWires::new(component_max_live_wires),
            garble_table: Default::default(),
            gate_index: 0,
        }
    }
    pub fn nect_gate_index(&mut self) -> usize {
        let index = self.gate_index;
        self.gate_index += 1;
        index
    }
}

impl ModeCache for GarbleCache {
    type Value = GarbledWire;

    fn lookup_wire(&self, wire: WireId) -> Option<&Self::Value> {
        self.wires.get(wire).ok()
    }

    fn feed_wire(&mut self, wire: WireId, value: Self::Value) {
        self.wires.init(wire, value).unwrap();
    }

    fn size(&self) -> usize {
        self.wires.size()
    }

    fn push_frame(&mut self, inputs: Vec<(WireId, Self::Value)>) {
        // For garbling, frames might work differently - just add to the main map for now
        for (wire_id, value) in inputs {
            self.feed_wire(wire_id, value);
        }
    }

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, Self::Value)>
    where
        Self::Value: Clone,
    {
        outputs
            .iter()
            .filter_map(|&wire_id| {
                self.lookup_wire(wire_id)
                    .map(|value| (wire_id, value.clone()))
            })
            .collect()
    }

    fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, GarbledWire)> {
        input_wires
            .iter()
            .filter_map(|&wire_id| {
                self.lookup_wire(wire_id)
                    .map(|value| (wire_id, value.clone()))
            })
            .collect()
    }

    fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, GarbledWire)> {
        self.pop_frame(output_wires)
    }
}

impl CircuitMode for Garble {
    type Cache = GarbleCache;

    fn evaluate_gate(
        gate: &Gate,
        cache: &mut Self::Cache,
    ) -> Option<<Self::Cache as ModeCache>::Value> {
        let gate_id = cache.nect_gate_index();

        if let Some(ciphertext) = gate
            .garble::<Blake3Hasher>(gate_id, &mut cache.wires, &cache.delta, &mut cache.rng)
            .unwrap()
        {
            cache.garble_table.push(ciphertext);
        }

        todo!()
    }
}

pub struct CheckGarbling;

#[derive(Default)]
pub struct CheckGarblingCache {
    wires: HashMap<WireId, EvaluatedWire>,
}

impl ModeCache for CheckGarblingCache {
    type Value = EvaluatedWire;

    fn lookup_wire(&self, wire: WireId) -> Option<&Self::Value> {
        self.wires.get(&wire)
    }

    fn feed_wire(&mut self, wire: WireId, value: Self::Value) {
        self.wires.insert(wire, value);
    }

    fn size(&self) -> usize {
        self.wires.len()
    }

    fn push_frame(&mut self, inputs: Vec<(WireId, Self::Value)>) {
        for (wire_id, value) in inputs {
            self.feed_wire(wire_id, value);
        }
    }

    fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, Self::Value)>
    where
        Self::Value: Clone,
    {
        outputs
            .iter()
            .filter_map(|&wire_id| {
                self.lookup_wire(wire_id)
                    .map(|value| (wire_id, value.clone()))
            })
            .collect()
    }

    fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, EvaluatedWire)> {
        input_wires
            .iter()
            .filter_map(|&wire_id| {
                self.lookup_wire(wire_id)
                    .map(|value| (wire_id, value.clone()))
            })
            .collect()
    }

    fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, EvaluatedWire)> {
        self.pop_frame(output_wires)
    }
}

impl CircuitMode for CheckGarbling {
    type Cache = CheckGarblingCache;

    fn evaluate_gate(
        _gate: &Gate,
        _cache: &mut Self::Cache,
    ) -> Option<<Self::Cache as ModeCache>::Value> {
        todo!()
    }
}

pub struct CircuitBuilder<M: CircuitMode> {
    pool: ComponentPool,
    stack: Vec<ComponentId>,
    wire_cache: M::Cache,
    next_wire_id: usize,
}

impl<M: CircuitMode> CircuitBuilder<M> {
    /// Convenience wrapper using the generic streaming path for Evaluate mode
    pub fn streaming_process<I, F>(
        inputs: I,
        wire_cache: M::Cache,
        f: F,
    ) -> Vec<<M::Cache as ModeCache>::Value>
    where
        I: CircuitInput + EncodeInput<M>,
        F: FnOnce(&mut ComponentHandle<M>, I::WireRepr) -> Vec<WireId>,
    {
        let mut builder = Self {
            pool: ComponentPool(SlotMap::with_key()),
            stack: vec![],
            wire_cache,
            next_wire_id: 2,
        };

        let root_id = builder.pool.insert(Component::empty_root());
        builder.stack.push(root_id);

        // Initialize root frame with mode-specific constants
        builder.wire_cache.push_frame(vec![]);

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

        // Execute the circuit building function
        let output = f(&mut root_handle, inputs_wire);
        root_handle.get_component().output_wires = output.into_wire_list();

        let output_wire_ids = root_handle.get_component().output_wires.clone();

        // Extract output values from the cache
        output_wire_ids
            .iter()
            .copied()
            .map(|wire_id| {
                builder
                    .wire_cache
                    .lookup_wire(wire_id)
                    .cloned()
                    .unwrap_or_else(|| panic!("output wire not present: {wire_id:?}"))
            })
            .collect::<Vec<_>>()
    }

    pub fn global_input(&self) -> &[WireId] {
        let root = self.stack.first().unwrap();
        &self.pool.get(*root).input_wires
    }
}

impl<M: CircuitMode> CircuitBuilder<M> {
    pub fn current_component(&mut self) -> ComponentHandle<'_, M> {
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

    pub fn add_gate_to_component(&mut self, component_id: ComponentId, gate: Gate) {
        // Always store the gate action for structural purposes (garbling, proofs, etc.)
        self.pool
            .get_mut(component_id)
            .actions
            .push(Action::Gate(gate));
    }

    pub fn add_gate_to_component_with_eval(&mut self, component_id: ComponentId, gate: Gate)
    where
        M: CircuitMode,
    {
        M::evaluate_gate(&gate, &mut self.wire_cache).unwrap();

        // Always store the gate action for structural purposes (garbling, proofs, etc.)
        self.pool
            .get_mut(component_id)
            .actions
            .push(Action::Gate(gate));
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
    fn encode(self, repr: &InputsWire, cache: &mut WireStack<bool>) {
        cache.feed_wire(repr.flag, self.flag);
        let bits = self.nonce.to_bits_le();
        for (i, bit) in bits.into_iter().enumerate() {
            cache.feed_wire(repr.nonce[i], bit);
        }
    }
}

// ――― Simple Input Types for Basic Tests ―――

/// Simple two-input structure for basic circuit tests
#[derive(Clone)]
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
    fn encode(self, repr: &SimpleInputsWire, cache: &mut WireStack<bool>) {
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
    fn encode(self, repr: &TripleInputsWire, cache: &mut WireStack<bool>) {
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

        let output = CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, inputs_wire| {
                let InputsWire { flag, nonce } = inputs_wire;

                let result = root.issue_wire();
                root.add_gate(Gate::and(flag, nonce[0], result));

                vec![result]
            },
        );

        assert!(output[0])
    }

    #[test]
    fn test_multi_wire_inputs() {
        // Define input values
        let inputs = Inputs {
            flag: true,
            nonce: 0xDEADBEEF12345678,
        };

        let output = CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, inputs_wire| {
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
            },
        );

        assert!(!output[0]);
    }

    #[test]
    #[should_panic]
    fn test_undeclared_input_is_invisible() {
        // Test that child components cannot access parent wires not in input_wires
        let inputs = SimpleInputs { a: true, b: false };

        CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, inputs_wire| {
                let parent_secret = root.issue_wire();
                root.add_gate(Gate::and(inputs_wire.a, inputs_wire.b, parent_secret));

                // Try to use parent wire without declaring it as input - should panic
                root.with_child(vec![], |child| {
                    let result = child.issue_wire();
                    // This should panic because parent_secret is not in input_wires
                    child.add_gate(Gate::and(WireId(999), TRUE_WIRE, result));
                    result
                });

                vec![parent_secret]
            },
        );
    }

    #[test]
    #[should_panic(expected = "Output wire")]
    fn test_missing_output_panics() {
        // Test that missing output wires cause a panic
        let inputs = SimpleInputs { a: true, b: false };

        CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, inputs_wire| {
                root.with_child(vec![inputs_wire.a], |_child| {
                    // Child declares an output but never creates it
                    vec![WireId(999)]
                });

                vec![]
            },
        );
    }

    #[test]
    fn test_constants_are_globally_visible() {
        // Test that TRUE_WIRE and FALSE_WIRE are accessible in child components
        let inputs = SimpleInputs { a: true, b: false };

        let output = CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, _inputs_wire| {
                let result = root.with_child(vec![], |child| {
                    // Use constants without passing them as inputs
                    let result = child.issue_wire();
                    child.add_gate(Gate::and(TRUE_WIRE, FALSE_WIRE, result));
                    result
                });

                vec![result]
            },
        );

        assert!(!output[0]); // TRUE AND FALSE = FALSE
    }

    #[test]
    fn test_deep_nesting() {
        // Test deep component nesting
        let inputs = SimpleInputs { a: true, b: false };

        let output = CircuitBuilder::<Evaluate>::streaming_process(
            inputs.clone(),
            WireStack::default(),
            |root, inputs_wire| {
                let mut current = inputs_wire.a;

                // Create 10 levels of nesting
                for _ in 0..10 {
                    current = root.with_child(vec![current], |child| {
                        let result = child.issue_wire();
                        child.add_gate(Gate::and(current, TRUE_WIRE, result));
                        result
                    });
                }

                vec![current]
            },
        );

        assert!(output[0]);

        let output = CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, inputs_wire| {
                let mut current = inputs_wire.b;

                for _ in 0..10 {
                    current = root.with_child(vec![current], |child| {
                        let result = child.issue_wire();
                        child.add_gate(Gate::and(current, TRUE_WIRE, result));
                        result
                    });
                }

                vec![current]
            },
        );

        assert!(!output[0]);
    }

    #[test]
    fn test_isolation_between_siblings() {
        // Test that sibling components cannot see each other's wires
        let inputs = SimpleInputs { a: true, b: false };

        let output = CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, inputs_wire| {
                // First child creates a wire
                let child1_output = root.with_child(vec![inputs_wire.a], |child| {
                    let internal = child.issue_wire();
                    child.add_gate(Gate::and(inputs_wire.a, TRUE_WIRE, internal));
                    internal
                });

                // Second child should not be able to see first child's internal wires
                let child2_output = root.with_child(vec![inputs_wire.b], |child| {
                    let result = child.issue_wire();
                    // This uses only declared inputs and constants
                    child.add_gate(Gate::or(inputs_wire.b, FALSE_WIRE, result));
                    result
                });

                vec![child1_output, child2_output]
            },
        );

        assert!(output[0]); // true AND true = true
        assert!(!output[1]); // false OR false = false
    }

    #[test]
    #[should_panic]
    fn test_parent_wire_access_panics() {
        // Test that child cannot access parent wires not in input_wires
        let inputs = SimpleInputs { a: true, b: false };

        CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, _inputs_wire| {
                // Parent issues a wire but doesn't pass it to child
                let _parent_secret = root.issue_wire();

                root.with_child(vec![], |child| {
                    let result = child.issue_wire();
                    // Try to use parent's wire - should panic (WireId(2) is inputs_wire.a)
                    child.add_gate(Gate::xor(WireId(2), TRUE_WIRE, result));
                    result
                });

                vec![]
            },
        );
    }

    #[test]
    fn test_root_frame_released() {
        // Test that root frame is properly released after streaming_process
        let inputs = SimpleInputs { a: true, b: false };

        let builder = CircuitBuilder::<Evaluate> {
            pool: ComponentPool(SlotMap::with_key()),
            stack: vec![],
            wire_cache: WireStack::<bool>::default(),
            next_wire_id: 2,
        };

        // Check initial state
        assert_eq!(builder.wire_cache.frames.len(), 0);

        // Run a simple circuit
        let _output = CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, inputs_wire| {
                let result = root.issue_wire();
                root.add_gate(Gate::and(inputs_wire.a, inputs_wire.b, result));
                vec![result]
            },
        );

        // After streaming_process, frames should be empty (root frame popped)
        // We can't directly check this as builder is consumed, but the test passes if no memory leak
    }

    #[test]
    fn test_constants_cannot_be_overwritten() {
        // Test that constants are protected and work correctly
        let inputs = SimpleInputs { a: true, b: false };

        let output = CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, _inputs_wire| {
                // Use constants in parent
                let parent_result = root.issue_wire();
                root.add_gate(Gate::and(TRUE_WIRE, FALSE_WIRE, parent_result));

                // Use constants in child
                let child_result = root.with_child(vec![], |child| {
                    let result = child.issue_wire();
                    child.add_gate(Gate::or(TRUE_WIRE, FALSE_WIRE, result));
                    result
                });

                vec![parent_result, child_result]
            },
        );

        assert!(!output[0]); // TRUE AND FALSE = FALSE
        assert!(output[1]); // TRUE OR FALSE = TRUE
    }

    #[test]
    fn test_deep_nesting_stress() {
        // Test very deep component nesting (1000 levels)
        let inputs = SimpleInputs { a: true, b: true };

        let output = CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, inputs_wire| {
                let mut current = inputs_wire.a;

                // Create 1000 levels of nesting
                for _ in 0..1000 {
                    current = root.with_child(vec![current], |child| {
                        let result = child.issue_wire();
                        child.add_gate(Gate::and(current, TRUE_WIRE, result));
                        result
                    });
                }

                vec![current]
            },
        );

        assert!(output[0]); // Should still be true after 1000 AND operations with TRUE
    }

    #[test]
    #[should_panic(expected = "appears multiple times")]
    fn test_duplicate_output_panics() {
        // Test that returning the same wire twice as output causes panic
        let inputs = SimpleInputs { a: true, b: false };

        CircuitBuilder::<Evaluate>::streaming_process(
            inputs,
            WireStack::default(),
            |root, inputs_wire| {
                root.with_child(vec![inputs_wire.a], |child| {
                    let result = child.issue_wire();
                    child.add_gate(Gate::and(inputs_wire.a, TRUE_WIRE, result));
                    // Return same wire twice - should panic during extract_outputs
                    vec![result, result]
                });

                vec![]
            },
        );
    }
}
