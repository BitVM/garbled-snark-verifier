use circuit_component_macro::component;

// Minimal streaming layer stubs expected by the macro
mod circuit {
    pub mod streaming {
        use crate::WireId;
        pub type ComponentKey = [u8; 8];
        pub fn generate_component_key<'a>(
            _name: &str,
            _params: impl IntoIterator<Item = (&'a str, &'a [u8])>,
            _arity: usize,
            _input_len: usize,
        ) -> ComponentKey { [0u8; 8] }

        pub trait WiresObject: Clone {
            fn to_wires_vec(&self) -> Vec<WireId> { vec![] }
            fn clone_from(&self, _wire_gen: &mut impl FnMut() -> WireId) -> Self { self.clone() }
        }
        pub trait FromWires: Sized + Clone + WiresObject { fn from_wires(_wires: &[WireId]) -> Option<Self> { None } }
        pub trait WiresArity { const ARITY: usize; }
        pub trait OffCircuitParam { fn to_key_bytes(&self) -> Vec<u8> { vec![] } }

        impl<T: Clone> WiresObject for T {}
        impl<T: Clone> FromWires for T {}
        impl<T> WiresArity for T { const ARITY: usize = 0; }
        impl<T> OffCircuitParam for T {}
        pub mod into_wire_list { pub use super::FromWires; }
    }
}

// Distinct param types to detect reordering at call sites
#[derive(Clone, Copy)]
struct A(u8);
#[derive(Clone, Copy)]
struct B(u8);
#[derive(Clone, Copy)]
struct X(u8);

// Minimal context and gate stubs so the macro expands in trybuild tests
#[derive(Clone, Copy)]
struct WireId(usize);
struct Gate;

trait CircuitContext {
    fn issue_wire(&mut self) -> WireId;
    fn add_gate(&mut self, _gate: Gate);
    fn with_named_child<I: crate::circuit::streaming::WiresObject, O: crate::circuit::streaming::into_wire_list::FromWires>(
        &mut self,
        _key: [u8; 8],
        _inputs: I,
        f: impl Fn(&mut Self, &I) -> O,
        _arity: usize,
    ) -> O { f(self, &_inputs) }
}

impl Gate {
    fn and(_a: WireId, _b: WireId, _c: WireId) -> Self { Gate }
}

// The ignored parameter `x` is in the middle. The wrapper must keep
// the original argument order: (a, x, b). If it reorders to (a, b, x),
// the call in `use_it` will fail to type-check due to mismatched types.
#[component(offcircuit_args = "x")]
fn gadget(ctx: &mut impl CircuitContext, a: A, x: X, b: B) -> (A, B) {
    // Return freshly constructed values; only signature order matters here
    (A(0), B(0))
}

fn use_it(ctx: &mut impl CircuitContext, a: A, x: X, b: B) {
    let _ = gadget(ctx, a, x, b);
}

fn main() {}
