#![allow(dead_code)]

use std::{array, fmt::Debug};

use crate::{
    Gate, WireId,
    circuit::streaming::{component_meta::ComponentMeta, modes::ExecuteWithCredits},
    core::gate_type::GateCount,
};

mod into_wire_list;
pub use into_wire_list::{WiresArity, WiresObject};

mod circuit_context_trait;
pub use circuit_context_trait::{CircuitContext, FALSE_WIRE, TRUE_WIRE};

pub mod components;
use components::{Action, Component, ComponentId, ComponentPool};

mod cache;
pub use cache::WireStack;

pub mod modes;
pub use modes::{CircuitMode, Evaluate, Execute, Garble};

pub mod component_meta;

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

impl<'a, M: CircuitMode> CircuitContext for ComponentHandle<'a, M> {
    type Mode = M;

    fn issue_wire(&mut self) -> WireId {
        self.builder.allocate_wire()
    }

    fn add_gate(&mut self, gate: Gate) {
        self.builder.add_gate_to_component(self.id, gate);
    }

    fn with_named_child<O: WiresObject>(
        &'_ mut self,
        _name: &'static str,
        _input_wires: Vec<WireId>,
        _f: impl Fn(&mut Self) -> O,
        _arity: impl FnOnce() -> usize,
    ) -> O {
        todo!()
        //let mut child = Component::empty_root();

        //child.name = name;
        //child.input_wires = input_wires.clone();
        //child.internal_wire_offset = self.builder.next_wire_id;

        //let child_id = self.builder.pool.insert(child);
        //self.builder.stack.push(child_id);
        //self.builder
        //    .pool
        //    .get_mut(self.id)
        //    .actions
        //    .push(Action::Call { id: child_id });

        //// Track parent cache size and start time for tracing
        //let start_time = Instant::now();

        //self.builder.mode.push_frame(name, &input_wires);

        //let mut child_handle = ComponentHandle {
        //    id: child_id,
        //    builder: self.builder,
        //};

        //let output_wires = f(&mut child_handle);

        //let output_wire_ids = output_wires.to_wires_vec();

        //let child_component = self.builder.pool.get_mut(child_id);
        //child_component.output_wires = output_wire_ids.clone();
        //child_component.num_wire = self.builder.next_wire_id - child_component.internal_wire_offset;

        //// Capture current frame cache usage before popping the frame
        //let child_cache_entries = self.builder.mode.current_size();

        //let total_cahce_size = self.builder.mode.total_size();

        //let extracted_outputs = self.builder.mode.pop_frame(&output_wire_ids);

        //// Feed output values back into parent frame
        //for (wire_id, value) in extracted_outputs {
        //    self.builder.mode.feed_wire(wire_id, value);
        //}

        //self.builder
        //    .stack
        //    .pop()
        //    .expect("unbalanced component stack");

        //let component = self.builder.pool.remove(child_id);

        //// Count actions separately: gates and nested calls
        //let gates = component
        //    .actions
        //    .iter()
        //    .filter(|a| matches!(a, Action::Gate(_)))
        //    .count();
        //let calls = component
        //    .actions
        //    .iter()
        //    .filter(|a| matches!(a, Action::Call { .. }))
        //    .count();

        //let duration_ms = start_time.elapsed().as_nanos();

        //info!(
        //    "component_metrics name={} gates={gates} calls={calls} cache_entries={child_cache_entries} total_cache={total_cahce_size} duration_ns={duration_ms}",
        //    component.name
        //);

        //output_wires
    }
}

pub struct CircuitBuilder<M: CircuitMode> {
    pool: ComponentPool,
    stack: Vec<ComponentId>,
    mode: M,
    next_wire_id: usize,
    gate_count: GateCount,
}

pub struct StreamingResult<M: CircuitMode, I: CircuitInput, O: CircuitOutput<M>> {
    pub input_wires: I::WireRepr,
    pub output_wires: O,
    pub output_wires_ids: Vec<WireId>,

    pub zero_constant: M::WireValue,
    pub one_constant: M::WireValue,
}

impl CircuitBuilder<ExecuteWithCredits> {
    pub fn streaming_process_with_credits<I, F, O>(
        inputs: I,
        live_wires_capacity: usize,
        f: F,
    ) -> StreamingResult<ExecuteWithCredits, I, O>
    where
        I: CircuitInput + EncodeInput<bool>,
        O: CircuitOutput<ExecuteWithCredits>,
        O::WireRepr: Debug,
        F: Fn(&mut ExecuteWithCredits, &I::WireRepr) -> O::WireRepr,
    {
        let mut meta = ExecuteWithCredits::FirstPass(ComponentMeta::new(&[], &[]));
        let allocated_inputs = inputs.allocate(|| {
            let wire_id = meta.issue_wire();

            if let ExecuteWithCredits::FirstPass(meta) = &mut meta {
                meta.increment_credits(&[wire_id]);
            }

            wire_id
        });

        inputs.encode(&allocated_inputs, &mut meta);

        let output = f(&mut meta, &allocated_inputs);

        if let ExecuteWithCredits::FirstPass(meta) = &mut meta {
            dbg!(&output);
            meta.pin(&output.to_wires_vec());
        }

        dbg!(&meta);
        let mut ctx = meta.to_second_pass(live_wires_capacity);

        let allocated_inputs = inputs.allocate(|| ctx.issue_wire());
        inputs.encode(&allocated_inputs, &mut ctx);

        let output_repr = f(&mut ctx, &allocated_inputs);
        let output_wires = output_repr.to_wires_vec();
        dbg!(&output_wires);

        let output = O::decode(output_repr, &ctx);

        StreamingResult {
            input_wires: allocated_inputs,
            output_wires: output,
            output_wires_ids: output_wires,
            one_constant: *ctx.lookup_wire(TRUE_WIRE).unwrap(),
            zero_constant: *ctx.lookup_wire(FALSE_WIRE).unwrap(),
        }
    }
}

impl<M: CircuitMode> CircuitBuilder<M> {
    /// Convenience wrapper using the generic streaming path for Evaluate mode
    pub fn streaming_process<I, F, O>(inputs: I, wire_cache: M, f: F) -> StreamingResult<M, I, O>
    where
        I: CircuitInput + EncodeInput<M::WireValue>,
        O: CircuitOutput<M>,
        F: FnOnce(&mut ComponentHandle<M>, &I::WireRepr) -> O::WireRepr,
    {
        let mut builder = Self {
            pool: ComponentPool::new(),
            stack: vec![],
            mode: wire_cache,
            next_wire_id: 2, // 0&1 reserved for constants
            gate_count: GateCount::default(),
        };

        let root_id = builder.pool.insert(Component::empty_root());
        builder.stack.push(root_id);

        // Initialize root frame with mode-specific constants
        builder.mode.push_frame("root", &[]);

        let mut root_handle = ComponentHandle {
            id: root_id,
            builder: &mut builder,
        };

        // Allocate input wires using the input type
        let input_wires = I::allocate(&inputs, || root_handle.issue_wire());
        root_handle.get_component().input_wires = I::collect_wire_ids(&input_wires);
        inputs.encode(&input_wires, &mut root_handle.builder.mode);

        let output = f(&mut root_handle, &input_wires);
        root_handle.get_component().output_wires = output.to_wires_vec();

        let output_wires_ids = root_handle.get_component().output_wires.clone();

        StreamingResult {
            input_wires,
            output_wires: O::decode(output, &builder.mode),
            output_wires_ids,
            one_constant: builder.mode.lookup_wire(TRUE_WIRE).unwrap().clone(),
            zero_constant: builder.mode.lookup_wire(FALSE_WIRE).unwrap().clone(),
        }
    }

    pub fn global_input(&self) -> &[WireId] {
        let root = self.stack.first().unwrap();
        &self.pool.get(*root).input_wires
    }
}

impl CircuitBuilder<Execute> {
    /// Convenience wrapper using the generic streaming path for Evaluate mode
    pub fn streaming_execute<I, F>(inputs: I, f: F) -> StreamingResult<Execute, I, Vec<bool>>
    where
        I: CircuitInput + EncodeInput<bool>,
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

    pub fn gate_count(&self) -> &GateCount {
        &self.gate_count
    }

    pub fn add_gate_to_component(&mut self, component_id: ComponentId, gate: Gate) {
        self.gate_count.handle(gate.gate_type);
        self.mode.evaluate_gate(&gate).unwrap();

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

    fn allocate(&self, ctx: impl FnMut() -> WireId) -> Self::WireRepr;
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId>;
}

/// Trait for encoding semantic values into mode-specific caches
pub trait EncodeInput<W: Clone>: Sized + CircuitInput {
    fn encode<M: CircuitMode<WireValue = W>>(&self, repr: &Self::WireRepr, cache: &mut M);
}

pub type SimpleInputs<const N: usize> = [bool; N];
pub type SimpleInputsWire<const N: usize> = [WireId; N];

impl<const N: usize> CircuitInput for SimpleInputs<N> {
    type WireRepr = SimpleInputsWire<N>;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        array::from_fn(|_| (issue)())
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.to_vec()
    }
}

impl<const N: usize> EncodeInput<bool> for SimpleInputs<N> {
    fn encode<M: CircuitMode<WireValue = bool>>(&self, repr: &Self::WireRepr, cache: &mut M) {
        self.iter().zip(repr.iter()).for_each(|(v, w)| {
            cache.feed_wire(*w, *v);
        });
    }
}

/// Trait for encoding semantic values into mode-specific caches
pub trait CircuitOutput<M: CircuitMode>: Sized {
    type WireRepr: Clone + WiresObject;

    fn decode(wires: Self::WireRepr, cache: &M) -> Self;
}

impl<M: CircuitMode> CircuitOutput<M> for Vec<M::WireValue> {
    type WireRepr = Vec<WireId>;

    fn decode(wires: Self::WireRepr, cache: &M) -> Self {
        dbg!(format!("start decode: {wires:?}"));
        wires
            .iter()
            .map(|w| {
                cache
                    .lookup_wire(*w)
                    .unwrap_or_else(|| panic!("Can't find {w:?}"))
                    .clone()
            })
            .collect()
    }
}

#[cfg(test)]
mod test_macro;

#[cfg(test)]
mod arity_tests;

pub mod arity_check;
pub use arity_check::{ArityChecker, WireCount, verify_arity};

#[cfg(test)]
mod exec_test {
    use test_log::test;

    use super::*;
    use crate::circuit::streaming::modes::ExecuteWithCredits;

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

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            InputsWire {
                flag: (issue)(),
                nonce: core::array::from_fn(|_| (issue)()),
            }
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            let mut wires = vec![repr.flag];
            wires.extend_from_slice(&repr.nonce);
            wires
        }
    }

    impl EncodeInput<bool> for Inputs {
        fn encode<M: CircuitMode<WireValue = bool>>(&self, repr: &Self::WireRepr, cache: &mut M) {
            cache.feed_wire(repr.flag, self.flag);
            let bits = self.nonce.to_bits_le();
            for (i, bit) in bits.into_iter().enumerate() {
                cache.feed_wire(repr.nonce[i], bit);
            }
        }
    }

    #[test]
    fn simple_with_credits() {
        let inputs = Inputs {
            flag: true,
            nonce: u64::MAX,
        };

        let output: StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::<ExecuteWithCredits>::streaming_process_with_credits(
                inputs,
                100,
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

        let output = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            // Create some logic using the allocated wires
            // Test flag AND first bit of nonce
            let InputsWire { flag, nonce } = inputs_wire;

            let result1 = root.issue_wire();
            root.add_gate(Gate::and(*flag, nonce[0], result1));

            // Test XOR of two nonce bits
            let result2 = root.with_child(
                vec![nonce[1], nonce[2]],
                |child| {
                    let result2 = child.issue_wire();
                    child.add_gate(Gate::xor(nonce[1], nonce[2], result2));
                    result2
                },
                || 1,
            );

            // Final AND of the two results
            let final_result = root.issue_wire();
            root.add_gate(Gate::and(result1, result2, final_result));

            vec![final_result]
        });

        assert!(!output.output_wires[0]);
    }

    #[test]
    #[should_panic]
    fn test_undeclared_input_is_invisible() {
        // Test that child components cannot access parent wires not in input_wires
        let inputs = [true, false];

        CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            let parent_secret = root.issue_wire();
            root.add_gate(Gate::and(inputs_wire[0], inputs_wire[1], parent_secret));

            // Try to use parent wire without declaring it as input - should panic
            root.with_child(
                vec![],
                |child| {
                    let result = child.issue_wire();
                    // This should panic because parent_secret is not in input_wires
                    child.add_gate(Gate::and(WireId(999), TRUE_WIRE, result));
                    result
                },
                || 1,
            );

            vec![parent_secret]
        });
    }

    #[test]
    #[should_panic(expected = "Output wire")]
    fn test_missing_output_panics() {
        // Test that missing output wires cause a panic
        let inputs = [true, false];

        CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            root.with_child(
                vec![inputs_wire[0]],
                |_child| {
                    // Child declares an output but never creates it
                    vec![WireId(999)]
                },
                || 1,
            );

            vec![]
        });
    }

    #[test]
    fn test_constants_are_globally_visible() {
        // Test that TRUE_WIRE and FALSE_WIRE are accessible in child components
        let inputs = [true, false];

        let output = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, _inputs_wire| {
            let result = root.with_child(
                vec![],
                |child| {
                    // Use constants without passing them as inputs
                    let result = child.issue_wire();
                    child.add_gate(Gate::and(TRUE_WIRE, FALSE_WIRE, result));
                    result
                },
                || 1,
            );

            vec![result]
        });

        assert!(!output.output_wires[0]); // TRUE AND FALSE = FALSE
    }

    #[test]
    fn test_deep_nesting() {
        // Test deep component nesting
        let inputs = [true, false];

        let output = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            let mut current = inputs_wire[0];

            // Create 10 levels of nesting
            for _ in 0..10 {
                current = root.with_child(
                    vec![current],
                    |child| {
                        let result = child.issue_wire();
                        child.add_gate(Gate::and(current, TRUE_WIRE, result));
                        result
                    },
                    || 1,
                );
            }

            vec![current]
        });

        assert!(output.output_wires[0]);

        let output = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            let mut current = inputs_wire[1];

            for _ in 0..10 {
                current = root.with_child(
                    vec![current],
                    |child| {
                        let result = child.issue_wire();
                        child.add_gate(Gate::and(current, TRUE_WIRE, result));
                        result
                    },
                    || 1,
                );
            }

            vec![current]
        });

        assert!(!output.output_wires[0]);
    }

    #[test]
    fn test_isolation_between_siblings() {
        // Test that sibling components cannot see each other's wires
        let inputs = [true, false];

        let output = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            // First child creates a wire
            let child1_output = root.with_child(
                vec![inputs_wire[0]],
                |child| {
                    let internal = child.issue_wire();
                    child.add_gate(Gate::and(inputs_wire[0], TRUE_WIRE, internal));
                    internal
                },
                || 1,
            );

            // Second child should not be able to see first child's internal wires
            let child2_output = root.with_child(
                vec![inputs_wire[1]],
                |child| {
                    let result = child.issue_wire();
                    // This uses only declared inputs and constants
                    child.add_gate(Gate::or(inputs_wire[1], FALSE_WIRE, result));
                    result
                },
                || 1,
            );

            vec![child1_output, child2_output]
        });

        assert!(output.output_wires[0]); // true AND true = true
        assert!(!output.output_wires[1]); // false OR false = false
    }

    #[test]
    #[should_panic]
    fn test_parent_wire_access_panics() {
        // Test that child cannot access parent wires not in input_wires
        let inputs = [true, false];

        CircuitBuilder::<Execute>::streaming_execute(inputs, |root, _inputs_wire| {
            // Parent issues a wire but doesn't pass it to child
            let _parent_secret = root.issue_wire();

            root.with_child(
                vec![],
                |child| {
                    let result = child.issue_wire();
                    // Try to use parent's wire - should panic (WireId(2) is inputs_wire.a)
                    child.add_gate(Gate::xor(WireId(2), TRUE_WIRE, result));
                    result
                },
                || 1,
            );

            vec![]
        });
    }

    #[test]
    fn test_root_frame_released() {
        // Test that root frame is properly released after streaming_process
        let inputs = [true, false];

        // Run a simple circuit
        let _output = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            let result = root.issue_wire();
            root.add_gate(Gate::and(inputs_wire[0], inputs_wire[1], result));
            vec![result]
        });
    }

    #[test]
    fn test_constants_cannot_be_overwritten() {
        // Test that constants are protected and work correctly
        let inputs = [true, false];

        let output = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, _inputs_wire| {
            // Use constants in parent
            let parent_result = root.issue_wire();
            root.add_gate(Gate::and(TRUE_WIRE, FALSE_WIRE, parent_result));

            // Use constants in child
            let child_result = root.with_child(
                vec![],
                |child| {
                    let result = child.issue_wire();
                    child.add_gate(Gate::or(TRUE_WIRE, FALSE_WIRE, result));
                    result
                },
                || 1,
            );

            vec![parent_result, child_result]
        });

        assert!(!output.output_wires[0]); // TRUE AND FALSE = FALSE
        assert!(output.output_wires[1]); // TRUE OR FALSE = TRUE
    }

    #[test]
    fn test_deep_nesting_stress() {
        // Test very deep component nesting (1000 levels)
        let inputs = [true, true];

        let output = CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            let mut current = inputs_wire[0];

            // Create 1000 levels of nesting
            for _ in 0..1000 {
                current = root.with_child(
                    vec![current],
                    |child| {
                        let result = child.issue_wire();
                        child.add_gate(Gate::and(current, TRUE_WIRE, result));
                        result
                    },
                    || 1,
                );
            }

            vec![current]
        });

        assert!(output.output_wires[0]); // Should still be true after 1000 AND operations with TRUE
    }

    #[test]
    #[should_panic(expected = "appears multiple times")]
    fn test_duplicate_output_panics() {
        // Test that returning the same wire twice as output causes panic
        let inputs = [true, false];

        CircuitBuilder::<Execute>::streaming_execute(inputs, |root, inputs_wire| {
            root.with_child(
                vec![inputs_wire[0]],
                |child| {
                    let result = child.issue_wire();
                    child.add_gate(Gate::and(inputs_wire[0], TRUE_WIRE, result));
                    // Return same wire twice - should panic during extract_outputs
                    vec![result, result]
                },
                || 2,
            );

            vec![]
        });
    }
}
