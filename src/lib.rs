mod circuit;
mod core;
mod gadgets;
mod math;

pub use core::{
    delta::Delta,
    gate::{Gate, GateError},
    gate_type::GateType,
    s::S,
    wire::{EvaluatedWire, GarbledWire, GarbledWires, WireError, WireId},
};

pub use circuit::{
    Circuit, CircuitContext, CircuitError, EvaluatedCircuit, FinalizedCircuit, GarbledCircuit,
};
pub use math::*;

#[cfg(test)]
pub mod test_utils {
    use rand_chacha::{ChaCha20Rng};
    use rand::{SeedableRng};

    pub fn trng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(0)
    }
}
