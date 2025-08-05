use circuit_component_macro::component;

// Mock types for testing
struct WireId(usize);

struct MyContext;

impl MyContext {
    #[component]
    fn with_self(&self, a: WireId) -> WireId {
        a
    }
}

fn main() {}