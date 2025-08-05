use circuit_component_macro::component;

// Mock types for testing
struct WireId(usize);

trait CircuitContext {
    fn issue_wire(&mut self) -> WireId;
}

#[component]
fn too_many_inputs(
    ctx: &mut impl CircuitContext,
    a1: WireId, a2: WireId, a3: WireId, a4: WireId,
    a5: WireId, a6: WireId, a7: WireId, a8: WireId,
    a9: WireId, a10: WireId, a11: WireId, a12: WireId,
    a13: WireId, a14: WireId, a15: WireId, a16: WireId,
    a17: WireId  // This should cause a compile error
) -> WireId {
    ctx.issue_wire()
}

fn main() {}