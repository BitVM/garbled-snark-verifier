use circuit_component_macro::component;

// Mock types for testing
struct WireId(usize);
struct Gate;

trait CircuitContext {
    fn issue_wire(&mut self) -> WireId;
    fn add_gate(&mut self, gate: Gate);
}

impl Gate {
    fn not(a: WireId) -> Self {
        Gate
    }
}

#[component]
fn not_gate(ctx: &mut impl CircuitContext, a: WireId) -> WireId {
    let output = ctx.issue_wire();
    ctx.add_gate(Gate::not(a));
    output
}

fn main() {}