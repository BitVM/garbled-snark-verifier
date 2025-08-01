use crate::{Gate, WireId};

/// A trait defining the context for circuit construction and wire management.
///
/// The `CircuitContext` trait provides the fundamental operations needed to build
/// boolean circuits by managing wires and gates. It abstracts the underlying
/// circuit representation while providing a consistent interface for:
///
/// - Wire allocation and management
/// - Input/output wire designation  
/// - Gate addition to the circuit
///
/// ## Wire Management
///
/// The trait defines two special constant wires:
/// - `FALSE_WIRE` (WireId(0)): Always evaluates to false
/// - `TRUE_WIRE` (WireId(1)): Always evaluates to true
///
/// ## Usage Example
///
/// ```rust
/// use garbled_snark_verifier::{Gate, Circuit, CircuitContext};
///
/// let mut circuit = Circuit::default();
///
/// // Create input wires
/// let a = circuit.issue_input_wire();
/// let b = circuit.issue_input_wire();
///
/// // Create an AND gate
/// let output = circuit.issue_output_wire();
/// circuit.add_gate(Gate::and(a, b, output));
/// ```
pub trait CircuitContext {
    /// Wire that always evaluates to false
    const FALSE_WIRE: WireId = WireId(0);

    /// Wire that always evaluates to true  
    const TRUE_WIRE: WireId = WireId(1);

    /// Allocates a new wire and returns its identifier.
    ///
    /// Each call to this method returns a unique `WireId` that can be used
    /// in gate construction. The wire is not designated as input or output
    /// until explicitly marked using `make_wire_input` or `make_wire_output`.
    fn issue_wire(&mut self) -> WireId;

    /// Creates a new input wire.
    ///
    /// This is a convenience method that combines `issue_wire()` and
    /// `make_wire_input()`. The returned wire will be included in the
    /// circuit's input wire list.
    ///
    /// # Returns
    ///
    /// The `WireId` of the newly created input wire.
    fn issue_input_wire(&mut self) -> WireId;

    /// Creates a new output wire.
    ///
    /// This is a convenience method that combines `issue_wire()` and
    /// `make_wire_output()`. The returned wire will be included in the
    /// circuit's output wire list.
    ///
    /// # Returns
    ///
    /// The `WireId` of the newly created output wire.
    fn issue_output_wire(&mut self) -> WireId;

    /// Marks an existing wire as a circuit input.
    ///
    /// Input wires represent the external values that will be provided
    /// when evaluating the circuit. This method adds the wire to the
    /// circuit's input wire list if it's not already present.
    ///
    /// # Parameters
    ///
    /// * `w` - The wire identifier to mark as input
    fn make_wire_input(&mut self, w: WireId);

    /// Marks an existing wire as a circuit output.
    ///
    /// Output wires represent the final results computed by the circuit.
    /// This method adds the wire to the circuit's output wire list if
    /// it's not already present.
    ///
    /// # Parameters
    ///
    /// * `w` - The wire identifier to mark as output  
    fn make_wire_output(&mut self, w: WireId);

    /// Adds a gate to the circuit.
    ///
    /// Gates define the boolean operations performed on wire values.
    /// The gate's input wires should already exist in the circuit,
    /// and the output wire will be computed based on the gate's function.
    ///
    /// # Parameters
    ///
    /// * `gate` - The gate to add to the circuit
    fn add_gate(&mut self, gate: Gate);
}
