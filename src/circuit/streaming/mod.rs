#![allow(dead_code)]

use crate::{Gate, WireId};

mod into_wire_list;
pub use into_wire_list::{IntoWireList, IntoWires};

mod circuit_context_trait;
pub use circuit_context_trait::{CircuitContext, FALSE_WIRE, TRUE_WIRE};

pub mod components;
use components::{Action, Component, ComponentId, ComponentPool};

mod cache;
pub use cache::WireStack;

pub mod modes;
pub use modes::{CircuitMode, Evaluate, Execute, Garble};

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

pub struct CircuitBuilder<M: CircuitMode> {
    pool: ComponentPool,
    stack: Vec<ComponentId>,
    wire_cache: M,
    next_wire_id: usize,
}

pub struct StreamingResult<M: CircuitMode, I: CircuitInput> {
    pub input_wires: I::WireRepr,
    pub output_wires: Vec<M::WireValue>,
    pub output_wires_ids: Vec<WireId>,

    pub zero_constant: M::WireValue,
    pub one_constant: M::WireValue,
}

impl<M: CircuitMode> CircuitBuilder<M> {
    /// Convenience wrapper using the generic streaming path for Evaluate mode
    pub fn streaming_process<I, F>(inputs: I, wire_cache: M, f: F) -> StreamingResult<M, I>
    where
        I: CircuitInput + EncodeInput<M>,
        F: FnOnce(&mut ComponentHandle<M>, &I::WireRepr) -> Vec<WireId>,
    {
        let mut builder = Self {
            pool: ComponentPool::new(),
            stack: vec![],
            wire_cache,
            next_wire_id: 2, // 0&1 reserved for constants
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
        let input_wires = I::allocate(&mut root_handle);
        root_handle.get_component().input_wires = I::collect_wire_ids(&input_wires);
        inputs.encode(&input_wires, &mut root_handle.builder.wire_cache);

        let output = f(&mut root_handle, &input_wires);
        root_handle.get_component().output_wires = output.into_wire_list();

        let output_wires_ids = root_handle.get_component().output_wires.clone();

        StreamingResult {
            input_wires,
            output_wires: output_wires_ids
                .iter()
                .copied()
                .map(|wire_id| {
                    builder
                        .wire_cache
                        .lookup_wire(wire_id)
                        .cloned()
                        .unwrap_or_else(|| panic!("output wire not present: {wire_id:?}"))
                })
                .collect::<Vec<_>>(),
            output_wires_ids,
            one_constant: builder.wire_cache.lookup_wire(TRUE_WIRE).unwrap().clone(),
            zero_constant: builder.wire_cache.lookup_wire(FALSE_WIRE).unwrap().clone(),
        }
    }

    pub fn global_input(&self) -> &[WireId] {
        let root = self.stack.first().unwrap();
        &self.pool.get(*root).input_wires
    }
}

impl CircuitBuilder<Execute> {
    /// Convenience wrapper using the generic streaming path for Evaluate mode
    pub fn streaming_execute<I, F>(inputs: I, f: F) -> StreamingResult<Execute, I>
    where
        I: CircuitInput + EncodeInput<Execute>,
        F: FnOnce(&mut ComponentHandle<Execute>, &I::WireRepr) -> Vec<WireId>,
    {
        Self::streaming_process(inputs, Execute::default(), f)
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
        self.wire_cache.evaluate_gate(&gate).unwrap();

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
    fn encode(self, repr: &Self::WireRepr, cache: &mut M);
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

impl EncodeInput<Execute> for Inputs {
    fn encode(self, repr: &InputsWire, cache: &mut Execute) {
        cache.feed_wire(repr.flag, self.flag);
        let bits = self.nonce.to_bits_le();
        for (i, bit) in bits.into_iter().enumerate() {
            cache.feed_wire(repr.nonce[i], bit);
        }
    }
}

pub type SoloInputs = (bool,);
pub type SoloInputsWire = (WireId,);

impl CircuitInput for SoloInputs {
    type WireRepr = SoloInputsWire;

    fn allocate<C: CircuitContext>(ctx: &mut C) -> Self::WireRepr {
        (ctx.issue_wire(),)
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![repr.0]
    }
}

impl EncodeInput<Execute> for SoloInputs {
    fn encode(self, repr: &SoloInputsWire, cache: &mut Execute) {
        cache.feed_wire(repr.0, self.0);
    }
}

pub type SimpleInputs = (bool, bool);
pub type SimpleInputsWire = (WireId, WireId);

impl CircuitInput for SimpleInputs {
    type WireRepr = SimpleInputsWire;

    fn allocate<C: CircuitContext>(ctx: &mut C) -> Self::WireRepr {
        let a = ctx.issue_wire();
        let b = ctx.issue_wire();
        println!("DEBUG: SimpleInputs allocated wire A: {a:?}, wire B: {b:?}");
        (a, b)
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![repr.0, repr.1]
    }
}

impl EncodeInput<Execute> for SimpleInputs {
    fn encode(self, repr: &SimpleInputsWire, cache: &mut Execute) {
        println!(
            "DEBUG: Encoding wire A: {a:?} = {av}, wire B: {b:?} = {bv}",
            a = repr.0,
            av = self.0,
            b = repr.1,
            bv = self.1
        );
        cache.feed_wire(repr.0, self.0);
        cache.feed_wire(repr.1, self.1);
    }
}

/// Three-input structure for macro tests
pub type TripleInputs = (bool, bool, bool);

pub type TripleInputsWire = (WireId, WireId, WireId);

impl CircuitInput for TripleInputs {
    type WireRepr = TripleInputsWire;

    fn allocate<C: CircuitContext>(ctx: &mut C) -> Self::WireRepr {
        (ctx.issue_wire(), ctx.issue_wire(), ctx.issue_wire())
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        vec![repr.0, repr.1, repr.2]
    }
}

impl EncodeInput<Execute> for TripleInputs {
    fn encode(self, repr: &TripleInputsWire, cache: &mut Execute) {
        cache.feed_wire(repr.0, self.0);
        cache.feed_wire(repr.1, self.1);
        cache.feed_wire(repr.2, self.2);
    }
}

#[cfg(test)]
mod test_macro;

#[cfg(test)]
mod exec_test {
    use super::*;

    #[test]
    fn simple() {
        let inputs = Inputs {
            flag: true,
            nonce: u64::MAX,
        };
        let output = CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
            |root, inputs_wire| {
                let InputsWire { flag, nonce } = inputs_wire;

                let result = root.issue_wire();
                root.add_gate(Gate::and(*flag, nonce[0], result));

                vec![result]
            },
        );

        assert!(output.output_wires[0])
    }

    #[test]
    fn test_multi_wire_inputs() {
        // Define input values
        let inputs = Inputs {
            flag: true,
            nonce: 0xDEADBEEF12345678,
        };

        let output = CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
            |root, inputs_wire| {
                // Create some logic using the allocated wires
                // Test flag AND first bit of nonce
                let InputsWire { flag, nonce } = inputs_wire;

                let result1 = root.issue_wire();
                root.add_gate(Gate::and(*flag, nonce[0], result1));

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

        assert!(!output.output_wires[0]);
    }

    #[test]
    #[should_panic]
    fn test_undeclared_input_is_invisible() {
        // Test that child components cannot access parent wires not in input_wires
        let inputs = (true, false);

        CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
            |root, inputs_wire| {
                let parent_secret = root.issue_wire();
                root.add_gate(Gate::and(inputs_wire.0, inputs_wire.1, parent_secret));

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
        let inputs = (true, false);

        CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
            |root, inputs_wire| {
                root.with_child(vec![inputs_wire.0], |_child| {
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
        let inputs = (true, false);

        let output = CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
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

        assert!(!output.output_wires[0]); // TRUE AND FALSE = FALSE
    }

    #[test]
    fn test_deep_nesting() {
        // Test deep component nesting
        let inputs = (true, false);

        let output = CircuitBuilder::<Execute>::streaming_process(
            inputs.clone(),
            Execute::default(),
            |root, inputs_wire| {
                let mut current = inputs_wire.0;

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

        assert!(output.output_wires[0]);

        let output = CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
            |root, inputs_wire| {
                let mut current = inputs_wire.1;

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

        assert!(!output.output_wires[0]);
    }

    #[test]
    fn test_isolation_between_siblings() {
        // Test that sibling components cannot see each other's wires
        let inputs = (true, false);

        let output = CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
            |root, inputs_wire| {
                // First child creates a wire
                let child1_output = root.with_child(vec![inputs_wire.0], |child| {
                    let internal = child.issue_wire();
                    child.add_gate(Gate::and(inputs_wire.0, TRUE_WIRE, internal));
                    internal
                });

                // Second child should not be able to see first child's internal wires
                let child2_output = root.with_child(vec![inputs_wire.1], |child| {
                    let result = child.issue_wire();
                    // This uses only declared inputs and constants
                    child.add_gate(Gate::or(inputs_wire.1, FALSE_WIRE, result));
                    result
                });

                vec![child1_output, child2_output]
            },
        );

        assert!(output.output_wires[0]); // true AND true = true
        assert!(!output.output_wires[1]); // false OR false = false
    }

    #[test]
    #[should_panic]
    fn test_parent_wire_access_panics() {
        // Test that child cannot access parent wires not in input_wires
        let inputs = (true, false);

        CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
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
        let inputs = (true, false);

        // Run a simple circuit
        let _output = CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
            |root, inputs_wire| {
                let result = root.issue_wire();
                root.add_gate(Gate::and(inputs_wire.0, inputs_wire.1, result));
                vec![result]
            },
        );
    }

    #[test]
    fn test_constants_cannot_be_overwritten() {
        // Test that constants are protected and work correctly
        let inputs = (true, false);

        let output = CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
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

        assert!(!output.output_wires[0]); // TRUE AND FALSE = FALSE
        assert!(output.output_wires[1]); // TRUE OR FALSE = TRUE
    }

    #[test]
    fn test_deep_nesting_stress() {
        // Test very deep component nesting (1000 levels)
        let inputs = (true, true);

        let output = CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
            |root, inputs_wire| {
                let mut current = inputs_wire.0;

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

        assert!(output.output_wires[0]); // Should still be true after 1000 AND operations with TRUE
    }

    #[test]
    #[should_panic(expected = "appears multiple times")]
    fn test_duplicate_output_panics() {
        // Test that returning the same wire twice as output causes panic
        let inputs = (true, false);

        CircuitBuilder::<Execute>::streaming_process(
            inputs,
            Execute::default(),
            |root, inputs_wire| {
                root.with_child(vec![inputs_wire.0], |child| {
                    let result = child.issue_wire();
                    child.add_gate(Gate::and(inputs_wire.0, TRUE_WIRE, result));
                    // Return same wire twice - should panic during extract_outputs
                    vec![result, result]
                });

                vec![]
            },
        );
    }
}
