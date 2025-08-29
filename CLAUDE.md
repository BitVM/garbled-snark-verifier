# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build & Compile
- `cargo build --workspace --all-features --release` - Full workspace build with all features
- `cargo check` - Quick syntax/type check without full compilation

### Testing
- `cargo test --workspace --all-targets` - Run all tests including unit, integration, and macro trybuild tests
- `cargo test test_name` - Run specific test by name
- `cargo test --lib module_name` - Test specific module
- `cargo test --release` - Run tests in release mode for performance-sensitive tests
- `RUST_BACKTRACE=1 cargo test test_name -- --nocapture` - Debug test with backtrace and output

### Linting & Formatting
- `cargo fmt` - Auto-format code (enforced by CI)
- `cargo fmt --check` - Verify formatting without changes
- `cargo clippy --no-deps --all-targets --all-features` - Lint with all warnings

### Examples
- `cargo run --example groth16_mpc --release` - Run examples with release optimizations

## High-Level Architecture

### Garbled Circuit Framework
This codebase implements a garbled circuit verifier for SNARK (Groth16) verification on the BN254 elliptic curve. The architecture follows a streaming wire-based circuit construction model with these key principles:

1. **Wire-Based Computation**: All computations flow through `WireId` references representing circuit wires carrying bit values. Wires are allocated incrementally and evaluated/garbled in streaming fashion.

2. **Three Execution Modes**:
   - `Garble`: Generate garbled circuit tables with Free-XOR optimization
   - `Evaluate`: Execute garbled circuit with garbled inputs  
   - `Execute`: Direct boolean evaluation for testing

3. **Component Hierarchy**: Circuit construction uses nested components that track input/output wires and gate counts. Components support caching for wire reuse optimization.

### Core Types & Invariants

- **S Type**: 32-byte wrapper ([u8; 32]) for garbled wire labels, supporting XOR operations for Free-XOR
- **Gate**: Triple of wire IDs (a, b, c) with gate type, where c = gate_type(a, b)
- **GateType**: 16 boolean gate types optimized for Free-XOR (XOR/XNOR are free)
- **Delta**: Global secret for Free-XOR garbling (odd parity required)

### Module Organization

- `src/core/`: Fundamental types (S, Wire, Gate, Circuit)
- `src/circuit/`: Streaming circuit builder with component management and caching
- `src/gadgets/`: Reusable arithmetic gadgets:
  - `basic`: Bit operations, adders, multiplexers
  - `bigint`: 254-bit unsigned integer arithmetic  
  - `bn254`: BN254 curve operations - field arithmetic (Fq, Fr), extension fields (Fq2, Fq6, Fq12), elliptic curve points (G1, G2), pairing operations
  - `groth16`: Complete SNARK verifier combining all gadgets
- `circuit_component_macro/`: Procedural macro for ergonomic component definitions

### Key Implementation Details

1. **Montgomery Form**: All BN254 field operations use Montgomery representation internally for efficiency
2. **Streaming Wire Truncation**: Wires are evaluated/garbled incrementally to manage memory
3. **Half-Gate Optimization**: AND gates use half-gate garbling (2 ciphertexts instead of 4)
4. **Component Caching**: Frequently-used wire patterns cached to reduce redundant gates
5. **MSM Window Size**: Multi-scalar multiplication uses configurable window sizes (typically 10-bit)

### Testing Approach
- Unit tests near implementations with `#[cfg(test)]`
- Integration tests verify complete Groth16 verification
- Macro tests in `circuit_component_macro/tests/` for compile-time validation
- Performance benchmarks track gate counts (published as GitHub badges)

## Development Guidelines

- Follow Rust 2024 edition conventions
- Maintain deterministic tests with fixed seeds (ChaCha20Rng::seed_from_u64(0))
- Verify Free-XOR invariants when modifying gate evaluation
- Check Montgomery domain consistency in field operations
- Run full test suite before commits: `cargo test --workspace --all-targets`