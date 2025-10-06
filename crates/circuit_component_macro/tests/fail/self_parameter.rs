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

struct MyContext;

impl MyContext {
    #[component]
    fn with_self(&self, a: WireId) -> WireId {
        a
    }
}

fn main() {}
