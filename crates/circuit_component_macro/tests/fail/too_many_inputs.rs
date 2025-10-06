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

// Mock types for testing
#[derive(Clone, Copy)]
struct WireId(usize);

trait CircuitContext {
    fn issue_wire(&mut self) -> WireId;
    fn with_named_child<I: crate::circuit::streaming::WiresObject, O: crate::circuit::streaming::into_wire_list::FromWires>(
        &mut self,
        _key: [u8; 8],
        _inputs: I,
        f: impl Fn(&mut Self, &I) -> O,
        _arity: usize,
    ) -> O { f(self, &_inputs) }
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
