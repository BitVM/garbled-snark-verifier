//! # Garbled Circuit Implementation
//!
//! This module provides a complete implementation of Yao's Garbled Circuits with Free XOR
//! & half-garbling optimization
//!
//! ## Security Level
//! This implementation operates at **privacy-free** security level. The garbled circuit
//! provides correctness guarantees but does not hide intermediate computation values
//! from a semi-honest adversary who has access to both the garbled circuit and input labels.
//!
//! ## Circuit Flow
//!
//! The garbled circuit protocol supports two finalization flows:
//!
//! ### Production Flow (Optimized)
//! ```text
//! ┌─────────────┐    ┌────────────────┐                               ┌──────────────────┐
//! │   Circuit   │───▶│ GarbledCircuit │──────────────────────────────▶│ FinalizedCircuit │
//! │ Construction│    │   (Garbling)   │          finalize()           │ (Commitment)     │
//! └─────────────┘    └────────────────┘                               └──────────────────┘
//!       │                     │                                             │
//!       │                     │                                             │
//!   • Topology Of Gates   • Wires with labels                           • Input Wires with labels
//!   • Count of Wires      • GarbledTable                                • GarbledTable  
//!   • Input/Output Wires  • Global Δ                                    • Output labels commit
//! ```
//!
//! ### Testing Flow (Full Evaluation)
//! ```text
//! ┌─────────────┐    ┌────────────────┐    ┌──────────────────┐         ┌──────────────────┐
//! │   Circuit   │───▶│ GarbledCircuit │───▶│ EvaluatedCircuit │────────▶│ FinalizedCircuit │
//! │ Construction│    │   (Garbling)   │    │  (Evaluation)    │         │ (Commitment)     │
//! └─────────────┘    └────────────────┘    └──────────────────┘         └──────────────────┘
//!                           │                      │                         │
//!                           │                      │                         │
//!                     evaluate()              finalize()               Both flows produce
//!                                                                      identical results
//! ```
//!
//! ## Key Optimization
//!
//! The production flow skips the intermediate wire evaluation phase because **commitment only
//! happens on output wires**. Since we don't need to commit to intermediate wire values, we can:
//! - Use `simple_evaluate()` to compute boolean output values directly
//! - Select the appropriate garbled labels for output wires based on their boolean values
//! - Skip the expensive garbled evaluation of all intermediate gates
//!
//! This optimization significantly improves performance while maintaining cryptographic security,
//! as the final commitment is identical to the full evaluation path.
//!
//! ## Implementation Details
//!
//! ### Phase 1: Circuit Construction ([`Circuit`])
//! - Build the boolean circuit structure with wires and gates
//! - Manage input/output wire assignments  
//! - Support direct boolean evaluation via `simple_evaluate()` for optimization
//!
//! ### Phase 2: Garbling ([`GarbledCircuit`])
//! - Generate global offset Δ for Free XOR optimization
//! - Create garbled wire labels with cryptographic randomness
//! - Build garbled truth tables for non-XOR gates
//! - Optimize XOR gates using Free XOR (no table entries)
//! - **No point-and-permute**: This implementation uses direct label selection
//! - **Production Path**: Direct finalization via `finalize()` using `simple_evaluate()`
//!
//! ### Phase 3: Evaluation ([`EvaluatedCircuit`]) - Testing Only
//! - **Purpose**: Provides intermediate state for testing and verification
//! - Evaluate gates using active wire labels and propagate through circuit
//! - Maintain correctness proofs for verification via `check_correctness()`
//! - **Note**: This phase exists primarily for testing; production code should use direct
//!   finalization
//!
//! ### Phase 4: Finalization ([`FinalizedCircuit`])
//! - **Commitment Mechanism**: Uses Blake3 cryptographic hash function for commit output wires (PoC Only)
//! - Allows you to check if the garbled circuit is correct and if the input and commit outputs match
//! - It is supposed to be sent to the other party

pub mod circuit_context;
pub mod commitment;
pub mod errors;
pub mod evaluation;
pub mod finalized;
pub mod garbling;
pub mod gate_source;
pub mod structure;
pub use circuit_context::CircuitContext;
pub use errors::CircuitError;
pub use evaluation::{Error, EvaluatedCircuit};
pub use finalized::FinalizedCircuit;
pub use garbling::GarbledCircuit;
pub use structure::Circuit;

#[cfg(test)]
pub mod test;
#[cfg(test)]
pub mod test_util;

pub mod streaming;
