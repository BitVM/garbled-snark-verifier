use circuit_component_macro::component;

// Mock types for testing
struct WireId(usize);
struct Gate;

trait CircuitContext {
    fn issue_wire(&mut self) -> WireId;
    fn add_gate(&mut self, gate: Gate);
}

impl Gate {
    fn and(a: WireId, b: WireId, c: WireId) -> Self {
        Gate
    }
}

#[component]
fn and_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
    let output = ctx.issue_wire();
    ctx.add_gate(Gate::and(a, b, output));
    output
}

fn main() {}