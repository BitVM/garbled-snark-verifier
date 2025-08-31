#[cfg(test)]
mod tests {
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

    /// Simple test inputs with pre-generated garbled wires
    struct SimpleGarbledInputs {
        wires: Vec<GarbledWire>,
    }

    impl CircuitInput for SimpleGarbledInputs {
        type WireRepr = Vec<WireId>;

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            (0..self.wires.len()).map(|_| issue()).collect()
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.clone()
        }
    }

    impl<M: CircuitMode<WireValue = GarbledWire>> EncodeInput<M> for SimpleGarbledInputs {
        fn encode(&self, repr: &Vec<WireId>, cache: &mut M) {
            for (wire, wire_id) in self.wires.iter().zip(repr.iter()) {
                cache.feed_wire(*wire_id, wire.clone());
            }
        }
    }

    #[test]
    fn test_simple_garble_integration() {
        // Generate test inputs with random garbled wires
        let mut rng = ChaChaRng::seed_from_u64(123);
        let delta = Delta::generate(&mut rng);

        let input_wires = vec![
            GarbledWire::random(&mut rng, &delta),
            GarbledWire::random(&mut rng, &delta),
            GarbledWire::random(&mut rng, &delta),
        ];

        let inputs = SimpleGarbledInputs {
            wires: input_wires.clone(),
        };

        // Create channel for garbled tables
        let (sender, receiver) = channel::unbounded();

        // Build and garble a simple circuit: (a AND b) XOR c
        let _result: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(
                inputs,
                10_000,
                456, // seed
                sender,
                |ctx, inputs| {
                    // Create a simple circuit: (a AND b) XOR c
                    let and_result = ctx.issue_wire();
                    ctx.add_gate(Gate::and(inputs[0], inputs[1], and_result));

                    let xor_result = ctx.issue_wire();
                    ctx.add_gate(Gate::xor(and_result, inputs[2], xor_result));

                    vec![xor_result]
                },
            );

        // Collect tables from receiver - only non-free gates produce entries
        let tables: Vec<_> = receiver.try_iter().collect();

        // Verify the circuit was garbled correctly
        // Only the AND gate should produce a table entry (XOR uses Free-XOR)
        assert_eq!(tables.len(), 1, "Only AND gate should produce table");

        // The table entry should be from the AND gate (gate_id 0)
        assert_eq!(tables[0].0, 0, "First table entry should be from gate 0");
    }

    #[test]
    fn test_garble_with_constants() {
        // Generate test inputs
        let mut rng = ChaChaRng::seed_from_u64(789);
        let delta = Delta::generate(&mut rng);

        let input_wires = vec![GarbledWire::random(&mut rng, &delta)];

        let inputs = SimpleGarbledInputs {
            wires: input_wires.clone(),
        };

        // Create channel for garbled tables
        let (sender, receiver) = channel::unbounded();

        // Circuit using constants: (input AND TRUE) OR FALSE
        let result: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(
                inputs,
                10_000,
                321, // seed
                sender,
                |ctx, inputs| {
                    // input AND TRUE
                    let and_true = ctx.issue_wire();
                    ctx.add_gate(Gate::and(inputs[0], TRUE_WIRE, and_true));

                    // result OR FALSE
                    let or_false = ctx.issue_wire();
                    ctx.add_gate(Gate::or(and_true, FALSE_WIRE, or_false));

                    vec![or_false]
                },
            );

        // Collect tables from receiver - only non-free gates produce entries
        let tables: Vec<_> = receiver.try_iter().collect();

        // Verify
        assert_eq!(result.output_wires.len(), 1);
        // Both AND and OR gates should produce tables (not free gates)
        assert_eq!(tables.len(), 2, "Both AND and OR should produce tables");

        // Verify constants are set
        assert!(result.true_constant.label0 != result.false_constant.label0);
    }

    #[test]
    fn test_nested_component_garbling() {
        use circuit_component_macro::component;

        // Define a simple component
        #[component]
        fn xor_gadget<C: CircuitContext>(ctx: &mut C, a: WireId, b: WireId) -> WireId {
            let result = ctx.issue_wire();
            ctx.add_gate(Gate::xor(a, b, result));
            result
        }

        // Generate test inputs
        let mut rng = ChaChaRng::seed_from_u64(999);
        let delta = Delta::generate(&mut rng);

        let input_wires = vec![
            GarbledWire::random(&mut rng, &delta),
            GarbledWire::random(&mut rng, &delta),
            GarbledWire::random(&mut rng, &delta),
        ];

        let inputs = SimpleGarbledInputs { wires: input_wires };

        // Create channel for garbled tables
        let (sender, receiver) = channel::unbounded();

        // Circuit using component: xor_gadget(a, b) AND c
        let _result: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(
                inputs,
                10_000,
                111, // seed
                sender,
                |ctx, inputs| {
                    // Use the component
                    let xor_result = xor_gadget(ctx, inputs[0], inputs[1]);

                    // AND with third input
                    let final_result = ctx.issue_wire();
                    ctx.add_gate(Gate::and(xor_result, inputs[2], final_result));

                    vec![final_result]
                },
            );

        // Collect tables from receiver - only non-free gates produce entries
        let tables: Vec<_> = receiver.try_iter().collect();

        // Verify
        // Only the AND gate should produce a table (XOR uses Free-XOR)
        assert_eq!(tables.len(), 1, "Only AND should produce table");
    }

    #[test]
    fn test_large_circuit_garbling() {
        // Generate test inputs
        let mut rng = ChaChaRng::seed_from_u64(555);
        let delta = Delta::generate(&mut rng);

        let num_inputs = 10;
        let input_wires: Vec<GarbledWire> = (0..num_inputs)
            .map(|_| GarbledWire::random(&mut rng, &delta))
            .collect();

        let inputs = SimpleGarbledInputs { wires: input_wires };

        // Create channel for garbled tables
        let (sender, receiver) = channel::unbounded();

        // Build a larger circuit with mixed gates
        let result: StreamingResult<_, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling_blake3(
                inputs,
                50_000, // larger capacity for more wires
                777,    // seed
                sender,
                |ctx, inputs| {
                    let mut results = vec![];

                    // Create multiple layers of gates
                    for i in 0..inputs.len() / 2 {
                        let xor_wire = ctx.issue_wire();
                        ctx.add_gate(Gate::xor(inputs[i * 2], inputs[i * 2 + 1], xor_wire));

                        let and_wire = ctx.issue_wire();
                        ctx.add_gate(Gate::and(xor_wire, TRUE_WIRE, and_wire));

                        let or_wire = ctx.issue_wire();
                        ctx.add_gate(Gate::or(and_wire, FALSE_WIRE, or_wire));

                        results.push(or_wire);
                    }

                    // Combine all results with XOR chain
                    let mut combined = results[0];
                    for res in results.iter().skip(1) {
                        let new_combined = ctx.issue_wire();
                        ctx.add_gate(Gate::xor(combined, *res, new_combined));
                        combined = new_combined;
                    }

                    vec![combined]
                },
            );

        // Verify the circuit was garbled
        assert_eq!(result.output_wires.len(), 1);

        // Collect tables from receiver - only non-free gates produce entries
        let tables: Vec<_> = receiver.try_iter().collect();

        // In this circuit, we have:
        // - 5 XOR gates (free)
        // - 5 AND gates with TRUE (non-free)
        // - 5 OR gates with FALSE (non-free)
        // - 4 XOR gates for combining (free)
        // Total non-free gates = 10

        println!("Large circuit stats:");
        println!("  Non-free gates (with tables): {}", tables.len());

        // Verify we have the expected non-free gates
        assert_eq!(tables.len(), 10, "Should have 10 non-free gates");
    }
}
