pub mod circuit;
mod core;
mod gadgets;
mod math;

// Re-export the procedural macro
pub use core::{
    delta::Delta,
    gate::{Gate, GateError},
    gate_type::GateType,
    s::S,
    wire::{EvaluatedWire, GarbledWire, GarbledWires, WireError, WireId},
};

pub use circuit::{CircuitContext, CircuitError};
pub use circuit_component_macro::component;
pub use gadgets::{groth16_verify, groth16_verify_compressed};
pub use math::*;

#[cfg(test)]
pub mod test_utils {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    pub fn trng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0)
    }
}
