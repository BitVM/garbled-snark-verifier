#[cfg(test)]
mod tests {
    use std::thread;

    use crossbeam::channel;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use test_log::test;

    use crate::{
        Delta, GarbledWire, Gate, WireId,
        circuit::{
            CircuitBuilder,
            streaming::{
                CircuitContext, CircuitInput, CircuitMode, EncodeInput, FALSE_WIRE,
                StreamingResult, TRUE_WIRE,
            },
        },
    };

    /// Test input structure with garbled wires
    pub struct TestGarbledInputs {
        pub wires: Vec<GarbledWire>,
    }

    impl CircuitInput for TestGarbledInputs {
        type WireRepr = Vec<WireId>;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            (0..self.wires.len()).map(|_| issue()).collect()
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.clone()
        }
    }

    impl<M: CircuitMode<WireValue = GarbledWire>> EncodeInput<M> for TestGarbledInputs {
        fn encode(&self, repr: &<Self as CircuitInput>::WireRepr, cache: &mut M) {
            self.wires
                .iter()
                .zip(repr.iter())
                .for_each(|(wire, wire_id)| {
                    cache.feed_wire(*wire_id, wire.clone());
                });
        }
    }

    #[test]
    fn test_simple_garble_xor() {
        // Generate random garbled inputs
        let mut rng = ChaChaRng::seed_from_u64(42);
        let delta = Delta::generate(&mut rng);

        let input_wires = vec![
            GarbledWire::random(&mut rng, &delta),
            GarbledWire::random(&mut rng, &delta),
        ];

        let inputs = TestGarbledInputs {
            wires: input_wires.clone(),
        };

        // Create channel for garbled tables
        let (sender, receiver) = channel::unbounded();

        let output: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(
                inputs,
                10_000,
                0, // seed
                sender,
                |ctx, inputs_wire| {
                    // Simple XOR gate - should use Free-XOR (no table)
                    let result = ctx.issue_wire();
                    ctx.add_gate(Gate::xor(inputs_wire[0], inputs_wire[1], result));
                    vec![result]
                },
            );

        // Collect tables from receiver - only non-free gates produce entries
        let tables: Vec<_> = receiver.try_iter().collect();

        // Verify XOR gate produced no garbled table (Free-XOR)
        assert_eq!(tables.len(), 0, "XOR should not produce any table entry");

        // Verify output wire is properly garbled
        assert_eq!(output.output_wires.len(), 1);
        let output_wire = &output.output_wires[0];

        // For XOR with Free-XOR: output.label0 = input1.label0 ^ input2.label0
        let expected_label0 = input_wires[0].label0 ^ &input_wires[1].label0;
        assert_eq!(output_wire.label0, expected_label0);
    }

    #[test]
    fn test_garble_and_gate() {
        // Generate random garbled inputs
        let mut rng = ChaChaRng::seed_from_u64(42);
        let delta = Delta::generate(&mut rng);

        let input_wires = vec![
            GarbledWire::random(&mut rng, &delta),
            GarbledWire::random(&mut rng, &delta),
        ];

        let inputs = TestGarbledInputs {
            wires: input_wires.clone(),
        };

        // Create channel for garbled tables
        let (sender, receiver) = channel::unbounded();

        let _output: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(
                inputs,
                10_000,
                0, // seed
                sender,
                |ctx, inputs_wire| {
                    // AND gate - should use half-gate garbling (produces table)
                    let result = ctx.issue_wire();
                    ctx.add_gate(Gate::and(inputs_wire[0], inputs_wire[1], result));
                    vec![result]
                },
            );

        // Collect tables from receiver - only non-free gates produce entries
        let tables: Vec<_> = receiver.try_iter().collect();

        // Verify AND gate produced a garbled table entry
        assert_eq!(
            tables.len(),
            1,
            "AND should produce exactly one table entry"
        );
    }

    #[test]
    fn test_garble_mixed_gates() {
        // Generate random garbled inputs
        let mut rng = ChaChaRng::seed_from_u64(42);
        let delta = Delta::generate(&mut rng);

        let input_wires = vec![
            GarbledWire::random(&mut rng, &delta),
            GarbledWire::random(&mut rng, &delta),
            GarbledWire::random(&mut rng, &delta),
        ];

        let inputs = TestGarbledInputs { wires: input_wires };

        // Create channel for garbled tables
        let (sender, receiver) = channel::unbounded();

        let _output: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(
                inputs,
                10_000,
                0, // seed
                sender,
                |ctx, inputs_wire| {
                    // Mixed circuit: XOR, AND, OR
                    let xor_result = ctx.issue_wire();
                    ctx.add_gate(Gate::xor(inputs_wire[0], inputs_wire[1], xor_result));

                    let and_result = ctx.issue_wire();
                    ctx.add_gate(Gate::and(xor_result, inputs_wire[2], and_result));

                    let or_result = ctx.issue_wire();
                    ctx.add_gate(Gate::or(and_result, inputs_wire[0], or_result));

                    vec![or_result]
                },
            );

        // Collect tables from receiver - only non-free gates produce entries
        let tables: Vec<_> = receiver.try_iter().collect();

        // Verify:
        // - XOR gate: no table (Free-XOR) - not in output
        // - AND gate: table entry - in output
        // - OR gate: table entry - in output
        assert_eq!(tables.len(), 2, "AND and OR should produce tables");
    }

    #[test]
    fn test_garble_with_constants() {
        // Generate random garbled inputs
        let mut rng = ChaChaRng::seed_from_u64(42);
        let delta = Delta::generate(&mut rng);

        let input_wires = vec![GarbledWire::random(&mut rng, &delta)];

        let inputs = TestGarbledInputs { wires: input_wires };

        // Create channel for garbled tables
        let (sender, receiver) = channel::unbounded();
        thread::spawn(move || while receiver.recv().is_ok() {});

        let output: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(
                inputs,
                10_000,
                0, // seed
                sender,
                |ctx, inputs_wire| {
                    // Gates with constants
                    let and_true = ctx.issue_wire();
                    ctx.add_gate(Gate::and(inputs_wire[0], TRUE_WIRE, and_true));

                    let or_false = ctx.issue_wire();
                    ctx.add_gate(Gate::or(inputs_wire[0], FALSE_WIRE, or_false));

                    vec![and_true, or_false]
                },
            );

        // Verify constants are properly set
        assert_eq!(output.output_wires.len(), 2);
        assert!(output.true_constant.label0 != output.false_constant.label0);
    }

    #[test]
    fn test_garble_nested_components() {
        use circuit_component_macro::component;

        #[component]
        fn xor_chain<C: CircuitContext>(ctx: &mut C, a: WireId, b: WireId) -> WireId {
            let tmp = ctx.issue_wire();
            ctx.add_gate(Gate::xor(a, b, tmp));

            let result = ctx.issue_wire();
            ctx.add_gate(Gate::xor(tmp, TRUE_WIRE, result));

            result
        }

        // Generate random garbled inputs
        let mut rng = ChaChaRng::seed_from_u64(42);
        let delta = Delta::generate(&mut rng);

        let input_wires = vec![
            GarbledWire::random(&mut rng, &delta),
            GarbledWire::random(&mut rng, &delta),
        ];

        let inputs = TestGarbledInputs { wires: input_wires };

        // Create channel for garbled tables
        let (sender, receiver) = channel::unbounded();

        let _output: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(
                inputs,
                10_000,
                0, // seed
                sender,
                |ctx, inputs_wire| vec![xor_chain(ctx, inputs_wire[0], inputs_wire[1])],
            );

        // Collect tables from receiver - only non-free gates produce entries
        let tables: Vec<_> = receiver.try_iter().collect();

        // Both XOR gates should use Free-XOR (no tables)
        assert_eq!(tables.len(), 0, "XOR gates should not produce any tables");
    }
}
