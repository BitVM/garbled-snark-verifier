use circuit_component_macro::component;

// Distinct param types to detect reordering at call sites
struct A(u8);
struct B(u8);
struct X(u8);

// Minimal context and gate stubs so the macro expands in trybuild tests
struct WireId(usize);
struct Gate;

trait CircuitContext {
    fn issue_wire(&mut self) -> WireId;
    fn add_gate(&mut self, _gate: Gate);
}

impl Gate {
    fn and(_a: WireId, _b: WireId, _c: WireId) -> Self { Gate }
}

// The ignored parameter `x` is in the middle. The wrapper must keep
// the original argument order: (a, x, b). If it reorders to (a, b, x),
// the call in `use_it` will fail to type-check due to mismatched types.
#[component(offcircuit_args = "x")]
fn gadget(ctx: &mut impl CircuitContext, a: A, x: X, b: B) -> (A, B) {
    // body can be empty for compile-time validation in trybuild
    (a, b)
}

fn use_it(ctx: &mut impl CircuitContext, a: A, x: X, b: B) {
    let _ = gadget(ctx, a, x, b);
}

fn main() {}

