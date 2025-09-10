use std::{array, fmt::Debug};

use crossbeam::channel;
use log::info;

use crate::{
    S, WireId,
    circuit::streaming::component_meta::ComponentMetaBuilder,
    core::{gate::garbling::GateHasher, gate_type::GateCount},
};

mod into_wire_list;
pub use into_wire_list::{FromWires, WiresArity, WiresObject};

mod circuit_context_trait;
pub use circuit_context_trait::{CircuitContext, FALSE_WIRE, TRUE_WIRE};

mod component_key;
pub use component_key::{generate_component_key, hash_param};

mod offcircuit_param;
pub use offcircuit_param::OffCircuitParam;

mod component_template_pool;
pub use component_template_pool::ComponentTemplatePool;

/// Macro for generating component keys with optional parameters
///
/// # Examples
///
/// Simple usage without parameters:
/// ```
/// use garbled_snark_verifier::component_key;
/// let key = component_key!("my_component", 10, 5);
/// ```
///
/// With parameters (use semicolon to separate params from arity/len):
/// ```
/// use garbled_snark_verifier::component_key;
/// let window_size: &[u8] = &[8];
/// let key = component_key!("multiplexer", w = window_size ; 10, 5);
/// ```
///
/// The macro handles conversion to bytes for common types automatically.
#[macro_export]
macro_rules! component_key {
    // Simple case: just name with arity and input_len
    ($name:expr, $arity:expr, $input_len:expr) => {
        $crate::circuit::streaming::generate_component_key($name, [] as [(&str, &[u8]); 0], $arity, $input_len)
    };

    // Parameters with arity and input_len - use semicolon to separate params from arity/len
    ($name:expr, $($param_name:ident = $param_value:expr),+ ; $arity:expr, $input_len:expr) => {
        {
            let params = vec![
                $(
                    (stringify!($param_name), $param_value as &[u8]),
                )+
            ];
            $crate::circuit::streaming::generate_component_key($name, params, $arity, $input_len)
        }
    };
}

pub mod modes;
pub use modes::{
    CircuitMode, EvaluateMode, EvaluateModeBlake3, ExecuteMode, GarbleMode, GarbleModeBlake3,
};

pub mod component_meta;

mod streaming_mode;
pub use streaming_mode::{StreamingContext, StreamingMode};

pub struct CircuitBuilder<M: CircuitMode> {
    #[allow(dead_code)]
    mode: M,
}

#[derive(Debug)]
pub struct StreamingResult<M: CircuitMode, I: CircuitInput, O: CircuitOutput<M>> {
    pub input_wires: I::WireRepr,
    pub output_wires: O,
    pub output_wires_ids: Vec<WireId>,

    pub false_constant: M::WireValue,
    pub true_constant: M::WireValue,
    pub input_values: Vec<M::WireValue>,
    pub gate_count: GateCount,
}

impl CircuitBuilder<ExecuteMode> {
    pub fn streaming_execute<I, F, O>(
        inputs: I,
        live_wires_capacity: usize,
        f: F,
    ) -> StreamingResult<ExecuteMode, I, O>
    where
        I: CircuitInput + EncodeInput<ExecuteMode>,
        O: CircuitOutput<ExecuteMode>,
        O::WireRepr: Debug,
        F: Fn(&mut StreamingMode<ExecuteMode>, &I::WireRepr) -> O::WireRepr,
    {
        CircuitBuilder::run_streaming(inputs, ExecuteMode::with_capacity(live_wires_capacity), f)
    }
}

impl<H: GateHasher> CircuitBuilder<GarbleMode<H>> {
    pub fn streaming_garbling<I, F, O>(
        inputs: I,
        live_wires_capacity: usize,
        seed: u64,
        output_sender: channel::Sender<(usize, S)>,
        f: F,
    ) -> StreamingResult<GarbleMode<H>, I, O>
    where
        I: CircuitInput + EncodeInput<GarbleMode<H>>,
        O: CircuitOutput<GarbleMode<H>>,
        O::WireRepr: Debug,
        F: Fn(&mut StreamingMode<GarbleMode<H>>, &I::WireRepr) -> O::WireRepr,
    {
        CircuitBuilder::run_streaming(
            inputs,
            GarbleMode::new(live_wires_capacity, seed, output_sender),
            f,
        )
    }
}

// Convenience impl for Blake3 (backward compatibility)
impl CircuitBuilder<GarbleModeBlake3> {
    pub fn streaming_garbling_blake3<I, F, O>(
        inputs: I,
        live_wires_capacity: usize,
        seed: u64,
        output_sender: channel::Sender<(usize, S)>,
        f: F,
    ) -> StreamingResult<GarbleModeBlake3, I, O>
    where
        I: CircuitInput + EncodeInput<GarbleModeBlake3>,
        O: CircuitOutput<GarbleModeBlake3>,
        O::WireRepr: Debug,
        F: Fn(&mut StreamingMode<GarbleModeBlake3>, &I::WireRepr) -> O::WireRepr,
    {
        Self::streaming_garbling(inputs, live_wires_capacity, seed, output_sender, f)
    }
}

impl<H: GateHasher> CircuitBuilder<EvaluateMode<H>> {
    pub fn streaming_evaluation<I, F, O>(
        inputs: I,
        live_wires_capacity: usize,
        true_wire: u128,
        false_wire: u128,
        ciphertext_receiver: channel::Receiver<(usize, S)>,
        f: F,
    ) -> StreamingResult<EvaluateMode<H>, I, O>
    where
        I: CircuitInput + EncodeInput<EvaluateMode<H>>,
        O: CircuitOutput<EvaluateMode<H>>,
        O::WireRepr: Debug,
        F: Fn(&mut StreamingMode<EvaluateMode<H>>, &I::WireRepr) -> O::WireRepr,
    {
        CircuitBuilder::run_streaming(
            inputs,
            EvaluateMode::new(
                live_wires_capacity,
                S::from_u128(true_wire),
                S::from_u128(false_wire),
                ciphertext_receiver,
            ),
            f,
        )
    }
}

// Convenience impl for Blake3 (backward compatibility)
impl CircuitBuilder<EvaluateModeBlake3> {
    pub fn streaming_evaluation_blake3<I, F, O>(
        inputs: I,
        live_wires_capacity: usize,
        true_wire: u128,
        false_wire: u128,
        ciphertext_receiver: channel::Receiver<(usize, S)>,
        f: F,
    ) -> StreamingResult<EvaluateModeBlake3, I, O>
    where
        I: CircuitInput + EncodeInput<EvaluateModeBlake3>,
        O: CircuitOutput<EvaluateModeBlake3>,
        O::WireRepr: Debug,
        F: Fn(&mut StreamingMode<EvaluateModeBlake3>, &I::WireRepr) -> O::WireRepr,
    {
        Self::streaming_evaluation(
            inputs,
            live_wires_capacity,
            true_wire,
            false_wire,
            ciphertext_receiver,
            f,
        )
    }
}

impl<M: CircuitMode> CircuitBuilder<M> {
    pub fn run_streaming<I, F, O>(inputs: I, mode: M, f: F) -> StreamingResult<M, I, O>
    where
        I: CircuitInput + EncodeInput<M>,
        O: CircuitOutput<M>,
        O::WireRepr: Debug,
        F: Fn(&mut StreamingMode<M>, &I::WireRepr) -> O::WireRepr,
    {
        let (allocated_inputs, root_meta) = ComponentMetaBuilder::new_with_input(&inputs);
        let mut root_meta = StreamingMode::<M>::MetadataPass(root_meta);

        let root_meta_output = f(&mut root_meta, &allocated_inputs);

        let root_meta_output_wires = root_meta_output.to_wires_vec();

        let (mut ctx, allocated_inputs) =
            root_meta.to_root_ctx(mode, &inputs, &root_meta_output_wires);

        let input_values = I::collect_wire_ids(&allocated_inputs)
            .into_iter()
            .map(|wire_id| ctx.lookup_wire(wire_id).unwrap())
            .collect();

        let output_repr = f(&mut ctx, &allocated_inputs);
        let output_wires = output_repr.to_wires_vec();

        let (gate_count, output) = match &mut ctx {
            StreamingMode::ExecutionPass(ctx) => {
                info!("gate count: {}", ctx.gate_count);
                println!("gate count: {}", ctx.gate_count);
                (
                    ctx.gate_count.clone(),
                    O::decode(output_repr, &mut ctx.mode),
                )
            }
            _ => unreachable!(),
        };

        StreamingResult {
            output_wires: output,
            output_wires_ids: output_wires,
            true_constant: ctx.lookup_wire(TRUE_WIRE).unwrap(),
            false_constant: ctx.lookup_wire(FALSE_WIRE).unwrap(),
            input_wires: allocated_inputs,
            input_values,
            gate_count,
        }
    }
}

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
pub trait EncodeInput<M: CircuitMode>: Sized + CircuitInput {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M);
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

impl<const N: usize, M: CircuitMode<WireValue = bool>> EncodeInput<M> for SimpleInputs<N> {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        self.iter().zip(repr.iter()).for_each(|(v, w)| {
            cache.feed_wire(*w, *v);
        });
    }
}

/// Trait for encoding semantic values into mode-specific caches
pub trait CircuitOutput<M: CircuitMode>: Sized {
    type WireRepr: Clone + WiresObject;

    fn decode(wires: Self::WireRepr, cache: &mut M) -> Self;
}

impl<M: CircuitMode> CircuitOutput<M> for Vec<M::WireValue> {
    type WireRepr = Vec<WireId>;

    fn decode(wires: Self::WireRepr, cache: &mut M) -> Self {
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
mod garble_integration_test;

pub mod arity_check;
pub use arity_check::{ArityChecker, WireCount, verify_arity};

#[cfg(test)]
mod exec_test {
    use test_log::test;

    use super::*;
    use crate::Gate;

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

    impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Inputs {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
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
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let InputsWire { flag, nonce } = inputs_wire;

                let result = root.issue_wire();
                root.add_gate(Gate::and(*flag, nonce[0], result));
                vec![result]
            });

        assert!(output.output_wires[0])
    }

    #[test]
    fn nested_with_credits() {
        let inputs = Inputs {
            flag: true,
            nonce: u64::MAX,
        };

        let output: StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let InputsWire { flag, nonce } = inputs_wire;

                let result = root.issue_wire();
                root.add_gate(Gate::and(*flag, nonce[0], result));
                root.with_child(
                    vec![result],
                    |child, inputs| {
                        let result = inputs[0];
                        let result2 = child.issue_wire();
                        child.add_gate(Gate::and(result, result, result2));
                        vec![result2]
                    },
                    1,
                )
            });

        assert!(output.output_wires[0])
    }

    #[test]
    fn nested_components_with_credits() {
        use circuit_component_macro::component;

        #[component]
        fn level3_gadget<C: CircuitContext>(ctx: &mut C, a: WireId, b: WireId) -> WireId {
            let internal = ctx.issue_wire();
            ctx.add_gate(Gate::nimp(a, b, internal));

            internal
        }

        #[component]
        fn level2_gadget<C: CircuitContext>(ctx: &mut C, input: WireId) -> WireId {
            let internal = ctx.issue_wire();
            ctx.add_gate(Gate::and(input, input, internal));

            level3_gadget(ctx, input, internal)
        }

        // Level 1: Calls level2
        #[component]
        fn level1_gadget<C: CircuitContext>(ctx: &mut C, input: WireId) -> WireId {
            let internal = ctx.issue_wire();
            ctx.add_gate(Gate::xor(input, TRUE_WIRE, internal));

            // Call level 2
            level2_gadget(ctx, internal)
        }

        let inputs = Inputs {
            flag: true,
            nonce: u64::MAX,
        };

        let output: StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |ctx, inputs_wire| {
                let InputsWire { flag, nonce } = inputs_wire;
                let w0 = ctx.issue_wire();
                ctx.add_gate(Gate::and(*flag, nonce[0], w0));

                vec![level1_gadget(ctx, w0)]
            });

        // With flag=true and nonce[0]=true:
        // w0 = true AND true = true
        // level1_internal = true XOR true = false
        // level2_internal = false AND false = false
        // level3_temp1 = false XOR false = false
        // level3_temp2 = false AND false = false
        // innermost_result = false XOR false = false
        assert!(!output.output_wires[0])
    }

    #[test]
    fn test_multi_wire_inputs() {
        // Define input values
        let inputs = Inputs {
            flag: true,
            nonce: 0xDEADBEEF12345678,
        };

        let output: StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                // Create some logic using the allocated wires
                // Test flag AND first bit of nonce
                let InputsWire { flag, nonce } = inputs_wire;

                let result1 = root.issue_wire();
                root.add_gate(Gate::and(*flag, nonce[0], result1));

                // Test XOR of two nonce bits
                let result2 = root.with_child(
                    vec![nonce[1], nonce[2]],
                    |child, inputs| {
                        let result2 = child.issue_wire();
                        child.add_gate(Gate::xor(inputs[0], inputs[1], result2));
                        result2
                    },
                    1,
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

        let _: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let parent_secret = root.issue_wire();
                root.add_gate(Gate::and(inputs_wire[0], inputs_wire[1], parent_secret));

                // Try to use parent wire without declaring it as input - should panic
                root.with_child(
                    Vec::<WireId>::new(),
                    |child, _inputs| {
                        let result = child.issue_wire();
                        // This should panic because parent_secret is not in input_wires
                        child.add_gate(Gate::and(WireId(999), TRUE_WIRE, result));
                        result
                    },
                    1,
                );

                vec![parent_secret]
            });
    }

    #[test]
    #[should_panic(expected = "Wrong output wire 999, but cursor is 3")]
    fn test_missing_output_panics() {
        // Test that missing output wires cause a panic
        let inputs = [true, false];

        let _: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                root.with_child(
                    vec![inputs_wire[0]],
                    |_child, _inputs| {
                        // Child declares an output but never creates it
                        vec![WireId(999)]
                    },
                    1,
                );

                vec![]
            });
    }

    #[test]
    fn test_constants_are_globally_visible() {
        // Test that TRUE_WIRE and FALSE_WIRE are accessible in child components
        let inputs = [true, false];

        let output: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, _inputs_wire| {
                let result = root.with_child(
                    Vec::<WireId>::new(),
                    |child, _inputs| {
                        // Use constants without passing them as inputs
                        let result = child.issue_wire();
                        child.add_gate(Gate::and(TRUE_WIRE, FALSE_WIRE, result));
                        result
                    },
                    1,
                );

                vec![result]
            });

        assert!(!output.output_wires[0]); // TRUE AND FALSE = FALSE
    }

    #[test]
    fn test_deep_nesting() {
        // Test deep component nesting
        let inputs = [true, false];

        let output: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let mut current = inputs_wire[0];

                // Create 10 levels of nesting
                for _ in 0..10 {
                    current = root.with_child(
                        vec![current],
                        |child, inputs| {
                            let current = inputs[0];
                            let result = child.issue_wire();
                            child.add_gate(Gate::and(current, TRUE_WIRE, result));
                            result
                        },
                        1,
                    );
                }

                vec![current]
            });

        assert!(output.output_wires[0]);

        let output: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let mut current = inputs_wire[1];

                for _ in 0..10 {
                    current = root.with_child(
                        vec![current],
                        |child, inputs| {
                            let current = inputs[0];
                            let result = child.issue_wire();
                            child.add_gate(Gate::and(current, TRUE_WIRE, result));
                            result
                        },
                        1,
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

        let output: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                // First child creates a wire
                let child1_output = root.with_child(
                    vec![inputs_wire[0]],
                    |child, inputs| {
                        let input0 = inputs[0];
                        let internal = child.issue_wire();
                        child.add_gate(Gate::and(input0, TRUE_WIRE, internal));
                        internal
                    },
                    1,
                );

                // Second child should not be able to see first child's internal wires
                let child2_output = root.with_child(
                    vec![inputs_wire[1]],
                    |child, inputs| {
                        let input1 = inputs[0];
                        let result = child.issue_wire();
                        // This uses only declared inputs and constants
                        child.add_gate(Gate::or(input1, FALSE_WIRE, result));
                        result
                    },
                    1,
                );

                vec![child1_output, child2_output]
            });

        assert!(output.output_wires[0]); // true AND true = true
        assert!(!output.output_wires[1]); // false OR false = false
    }

    #[test]
    fn test_root_frame_released() {
        // Test that root frame is properly released after streaming_process
        let inputs = [true, false];

        // Run a simple circuit
        let _output: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let result = root.issue_wire();
                root.add_gate(Gate::and(inputs_wire[0], inputs_wire[1], result));
                vec![result]
            });
    }

    #[test]
    fn test_constants_cannot_be_overwritten() {
        // Test that constants are protected and work correctly
        let inputs = [true, false];

        let output: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, _inputs_wire| {
                // Use constants in parent
                let parent_result = root.issue_wire();
                root.add_gate(Gate::and(TRUE_WIRE, FALSE_WIRE, parent_result));

                // Use constants in child
                let child_result = root.with_child(
                    Vec::<WireId>::new(),
                    |child, _inputs| {
                        let result = child.issue_wire();
                        child.add_gate(Gate::or(TRUE_WIRE, FALSE_WIRE, result));
                        result
                    },
                    1,
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

        let output: StreamingResult<ExecuteMode, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |root, inputs_wire| {
                let mut current = inputs_wire[0];

                // Create 1000 levels of nesting
                for _ in 0..1000 {
                    current = root.with_child(
                        vec![current],
                        |child, inputs| {
                            let current = inputs[0];
                            let result = child.issue_wire();
                            child.add_gate(Gate::and(current, TRUE_WIRE, result));
                            result
                        },
                        1,
                    );
                }

                vec![current]
            });

        assert!(output.output_wires[0]); // Should still be true after 1000 AND operations with TRUE
    }
}
