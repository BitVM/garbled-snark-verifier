use circuit_component_macro::component;

// Mock types for testing
struct WireId(usize);

trait CircuitContext {
    fn issue_wire(&mut self) -> WireId;
}

#[component]
fn no_input_gate(ctx: &mut impl CircuitContext) -> WireId {
    ctx.issue_wire()
}

fn main() {}