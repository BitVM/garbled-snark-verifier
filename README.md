# Garbled SNARK Verifier Circuit

A streaming garbled circuit implementation for verifying Groth16 proofs on the BN254 elliptic curve. This implementation supports three execution modes: direct boolean execution, garbled circuit generation, and garbled circuit evaluation for MPC-style computation.

## Current API Design

### 1. Streaming Garbling Architecture

The implementation uses a **streaming wire-based** circuit construction model that processes circuits incrementally to manage memory efficiently:

- **Wire-Based Model**: All computations flow through `WireId` references representing circuit wires. Wires are allocated incrementally and evaluated/garbled in streaming fashion, avoiding the need to hold the entire circuit in memory.

- **Component Hierarchy**: Circuits are organized as hierarchical components that track input/output wires and gate counts. Components support caching for wire reuse optimization.

- **Three Execution Modes**:
  - `Execute`: Direct boolean evaluation for testing correctness
  - `Garble`: Generate garbled circuit tables with Free-XOR optimization  
  - `Evaluate`: Execute garbled circuit with garbled inputs for MPC

### 2. Component Macro

The `#[component]` procedural macro transforms regular Rust functions into circuit component gadgets, automatically handling wire management and component nesting:

```rust
#[component]
fn and_gate(ctx: &mut impl CircuitContext, a: WireId, b: WireId) -> WireId {
    let c = ctx.issue_wire();
    ctx.add_gate(Gate::and(a, b, c));
    c
}

#[component]
fn full_adder(ctx: &mut impl CircuitContext, a: WireId, b: WireId, cin: WireId) -> (WireId, WireId) {
    let sum1 = xor_gate(ctx, a, b);
    let carry1 = and_gate(ctx, a, b);
    let sum = xor_gate(ctx, sum1, cin);
    let carry2 = and_gate(ctx, sum1, cin);
    let carry = or_gate(ctx, carry1, carry2);
    (sum, carry)
}
```

The macro automatically:
- Collects input parameters into wire lists
- Creates child components with proper input/output tracking
- Manages component caching and wire allocation
- Supports up to 16 input parameters

## How to Run the Example

### Prerequisites
- Rust toolchain (latest stable)
- Clone this repository

### Running the Groth16 Verifier Example

```bash
# Run with info-level logging to see execution progress
RUST_LOG=info cargo run --example groth16_mpc --release

# Run without logging (faster)
cargo run --example groth16_mpc --release
```

The example:
1. Generates a simple multiplicative circuit proof using arkworks
2. Verifies the proof using the streaming garbled circuit implementation
3. Outputs verification result and execution statistics

**Note**: The current implementation takes approximately 20 minutes for basic boolean execution due to the naive caching approach. This is expected and will be optimized.

## Current Status and Remaining Work

Based on the team communication, three main areas need attention before the 4.09 deadline:

### 1. Streaming Optimization (In Progress)
The streaming implementation is functional but slow. The current naive caching approach was implemented as a simple proof-of-concept. 

**Memory Optimization Roadmap**: A comprehensive two-pass optimization strategy has been designed to reduce memory usage from 357GB to 4GB and achieve 10-30x speedup for 11B gate circuits:

- **Pass 1 - Shape Analysis**: Compute wire lifetimes and fanout to enable intelligent memory management
- **Pass 2 - Optimized Execution**: Use lifetime information for memory-efficient evaluation

Key optimizations planned:
- Shape analysis infrastructure for wire lifetime tracking
- Slot-based memory arena replacing frame storage
- In-place wire reuse (targeting >40% reuse rate)
- Cache-friendly paged memory allocation (>90% cache hit rate)
- Streaming garbled tables to disk/network (avoiding 176GB RAM usage)
- Real-time metrics and instrumentation

Target: 11B gates in <20m with <4GB memory usage

### 2. Correctness Bug (Critical)
**Even valid proofs currently return false**, indicating a logic error in the gadgets that likely occurred during porting. Areas to investigate:
- Montgomery domain conversions in field arithmetic operations
- Pairing computation and final exponentiation logic
- MSM (Multi-Scalar Multiplication) implementation for public inputs
- Wire bit ordering and endianness in Fq/Fr representations
- Component input/output wire tracking in nested gadgets

To help debug:
- Check `src/gadgets/groth16.rs` - Main verification logic
- Review `src/gadgets/bn254/pairing.rs` - Miller loop and pairing operations
- Verify `src/gadgets/bn254/fq12.rs` - Extension field arithmetic
- Test `src/gadgets/bn254/g1.rs` - Elliptic curve point operations

### 3. Knowledge Transfer (Ongoing)
Documentation and examples need expansion to enable other team members to contribute effectively.

## Architecture Overview

```
src/
├── circuit/          # Streaming circuit builder and evaluation
│   └── streaming/    # Core streaming implementation
├── core/            # Fundamental types (Wire, Gate, S-values)
├── gadgets/         # Arithmetic gadgets
│   ├── basic.rs     # Bit operations, adders, multiplexers
│   ├── bigint/      # 254-bit unsigned integer arithmetic
│   ├── bn254/       # BN254 curve operations
│   │   ├── fq.rs    # Base field Fq operations
│   │   ├── fr.rs    # Scalar field Fr operations
│   │   ├── fq2/6/12.rs  # Extension field towers
│   │   ├── g1/g2.rs # Elliptic curve groups
│   │   ├── pairing.rs   # Miller loop & pairing
│   │   └── final_exponentiation.rs
│   └── groth16.rs   # Complete SNARK verifier
└── circuit_component_macro/  # Procedural macro for components
```

## Testing

Run the test suite to verify component functionality:

```bash
# Run all tests
cargo test --workspace --all-targets

# Run specific test with output
RUST_BACKTRACE=1 cargo test test_groth16_verify -- --nocapture

# Run tests in release mode (faster for heavy computations)
cargo test --release
```

## Contributing

To help with the correctness debugging:
1. Start with the Groth16 test cases in `src/gadgets/groth16.rs`
2. Add debug output to trace wire values through the computation
3. Compare intermediate values with a known-good arkworks implementation
4. Focus on the pairing computation chain: MSM → Miller loops → Final exponentiation

The branch name is `streaming-garbling` and all work should be based on this branch.
