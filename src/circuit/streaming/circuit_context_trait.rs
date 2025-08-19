// Export constants at module level
pub const FALSE_WIRE: WireId = WireId(0);
pub const TRUE_WIRE: WireId = WireId(1);

use crate::{
    Gate, WireId,
    circuit::streaming::{CircuitMode, ComponentHandle, WiresObject},
};

/// Simplified CircuitContext trait for hierarchical circuit building
/// Focuses on core operations without flat circuit input/output designation
pub trait CircuitContext {
    type Mode: CircuitMode;

    /// Allocates a new wire and returns its identifier
    fn issue_wire(&mut self) -> WireId;

    /// Adds a gate to the current component
    fn add_gate(&mut self, gate: Gate);

    fn with_child<O: WiresObject>(
        &mut self,
        input_wires: Vec<WireId>,
        f: impl Fn(&mut ComponentHandle<Self::Mode>) -> O,
        arity: impl FnOnce() -> usize,
    ) -> O {
        self.with_named_child("anon", input_wires, f, arity)
    }

    fn with_named_child<O: WiresObject>(
        &mut self,
        name: &'static str,
        input_wires: Vec<WireId>,
        f: impl Fn(&mut ComponentHandle<Self::Mode>) -> O,
        arity: impl FnOnce() -> usize,
    ) -> O;
}
