// Export constants at module level
pub const FALSE_WIRE: WireId = WireId(0);
pub const TRUE_WIRE: WireId = WireId(1);

use crate::{
    Gate, WireId,
    circuit::{CircuitMode, WiresObject, component_key::ComponentKey, into_wire_list::FromWires},
};

/// Simplified CircuitContext trait for hierarchical circuit building
/// Focuses on core operations without flat circuit input/output designation
pub trait CircuitContext: Sized {
    type Mode: CircuitMode;

    /// Allocates a new wire and returns its identifier
    fn issue_wire(&mut self) -> WireId;

    /// Adds a gate to the current component
    fn add_gate(&mut self, gate: Gate);

    fn with_named_child<I: WiresObject, O: FromWires>(
        &mut self,
        key: ComponentKey,
        inputs: I,
        f: impl Fn(&mut Self, &I) -> O,
        arity: usize,
    ) -> O;

    /// Compatibility wrapper for old with_child method used in tests
    /// Uses a default key based on "test_child"
    #[cfg(test)]
    fn with_child<I: WiresObject, O: FromWires>(
        &mut self,
        inputs: I,
        f: impl Fn(&mut Self, &I) -> O,
        arity: usize,
    ) -> O {
        use crate::circuit::generate_component_key;
        let input_wires = inputs.to_wires_vec();
        let key = generate_component_key(
            "test_child",
            [] as [(&str, &[u8]); 0],
            arity,
            input_wires.len(),
        );
        self.with_named_child(key, inputs, f, arity)
    }
}
