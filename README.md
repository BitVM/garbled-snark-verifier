# Garbled SNARK Verifier Circuit

## Gate Count Metrics

Gate counts are automatically measured for k=6 (64 constraints) on every push to `main` and published as dynamic badges.

![Total Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/total.json)
![Non-Free Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/nonfree.json)
![Free Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/free.json)


A streaming garbled-circuit implementation of a Groth16 verifier over BN254. It targets large, real‑world verifier circuits while keeping memory bounded via a two‑pass streaming architecture. The crate supports three execution modes: direct boolean execution, garbling, and evaluation (2PC/MPC‑style).

**Background**
- **What:** Encode a SNARK verifier (Groth16 on BN254) as a boolean circuit and run it as a garbled circuit. The verifier’s elliptic‑curve and pairing arithmetic is expressed with reusable gadgets (Fq/Fr/Fq2/Fq6/Fq12, G1/G2, Miller loop, final exponentiation).
- **Why:** Garbled verifiers enable privacy‑preserving and fairness‑friendly verification in 2‑party/MPC settings, or to offload verification from constrained environments while preserving secrecy of inputs. Streaming construction allows circuits with billions of gates to be handled with modest RAM.
- **How:**
  - Use Free‑XOR and half‑gates (Zahur–Rosulek–Evans) to make XOR family gates free and reduce AND to two ciphertexts.
  - Keep field arithmetic in Montgomery form to minimize reductions and wire width churn; convert only at the edges when needed.
  - Run a two‑phase streaming pipeline: first collect a compact “shape” of wire lifetimes (credits), then execute once with precise allocation and immediate reclamation. Garbling and evaluation synchronize via a streaming channel of ciphertexts.

**When To Use**
- You need a 2PC/MPC‑friendly Groth16 verifier with bounded memory.
- You want a reusable library of BN254 gadgets to assemble other pairing‑based checks.
- You prefer deterministic, testable components that mirror arkworks semantics.

**Core Concepts**
- **WireId / Wires:** Logical circuit wires carried through streaming contexts; gadgets implement `WiresObject` to map rich types to wire vectors.
- **S / Delta:** Garbled labels and global offset for Free‑XOR; AES‑NI or BLAKE3 is used as the PRF/RO for half‑gates.
- **Modes:** `Execute` (booleans, for testing), `Garble` (produce ciphertexts + constants), `Evaluate` (consume ciphertexts + constants).
- **Components:** Functions annotated with `#[component]` become cached, nested circuit components; a component‑keyed template pool and a metadata pass compute per‑wire “credits” (fanout‑based lifetimes) for tight memory reuse.

**Project Structure**
- `src/core`: fundamental types and logic (`S`, `Delta`, `WireId`, `Gate`, `GateType`).
- `src/circuit`: streaming builder, modes (`Execute`, `Garble`, `Evaluate`), finalization, and tests.
- `src/gadgets`: reusable gadgets: `bigint/u254`, BN254 fields and groups, pairing ops, and `groth16` verifier composition.
- `src/math`: focused math helpers (Montgomery helpers).
- `circuit_component_macro/`: proc‑macro crate backing `#[component]` ergonomics; trybuild tests live under `tests/`.

## API Overview

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

See `circuit_component_macro/` for details and compile‑time tests.

## Examples

### Prerequisites
- Rust toolchain (latest stable)
- Clone this repository

### Groth16 Verifier (Execute)

```bash
# Info logging for progress
RUST_LOG=info cargo run --example groth16_mpc --release

# Quieter/faster
cargo run --example groth16_mpc --release
```

Does:
- Generates a Groth16 proof with arkworks
- Verifies it using the streaming verifier (execute mode)
- Prints result and basic stats

### Garble + Evaluate (Pipeline)
```bash
RUST_LOG=info cargo run --example groth16_g2e --release
```
- Demonstrates a synchronized garble→evaluate pipeline over a channel; both sides stream the same circuit shape.

### Garble Only
```bash
RUST_LOG=info cargo run --example groth16_garble --release
```
- Builds the garbled table and constants for the verifier circuit and streams ciphertexts to a consumer.

### Focused Micro‑benchmarks
- `fq_inverse_many` – stress streaming overhead in Fq inverse gadgets.
- `g1_multiplexer_flame` – profile hot G1 multiplexer logic (works well with `cargo flamegraph`).

Note: Performance depends on the chosen example size and logging. The design focuses on scaling via streaming; larger gate counts benefit from the two‑pass allocator and component template cache.

## Current Status

- Groth16 verifier gadget implemented and covered by deterministic tests (true/false cases) using arkworks fixtures.
- Streaming modes: `Execute`, `Garble`, and `Evaluate` are implemented with integration tests, including a garble→evaluate pipeline example.
- BN254 gadget suite: Fq/Fr/Fq2/Fq6/Fq12 arithmetic, G1/G2 group ops, Miller loop, and final exponentiation in Montgomery form.
- Component macro crate is integrated; trybuild tests validate signatures and errors.

Planned/ongoing work:
- Continue tuning the two‑pass allocator, component template LRU, and wire crediting to keep peak memory low at high gate counts.
- Extend examples and surface metrics (gate counts, memory, throughput) for reproducible performance tracking.

## Architecture Overview

```
src/
├── core/                 # S, Delta, WireId, Gate, GateType
├── circuit/              # Streaming builder, modes, finalization, tests
│   └── streaming/        # Two‑pass meta + execution, templates, modes
├── gadgets/              # Basic, bigint/u254, BN254 fields, groups, pairing, Groth16
└── math/                 # Montgomery helpers and small math utils

circuit_component_macro/  # #[component] proc‑macro + tests
```

## Testing

Run the test suite to verify component functionality:

```bash
# All unit/integration/macro tests
cargo test --workspace --all-targets

# Focus on Groth16 tests with output
RUST_BACKTRACE=1 cargo test test_groth16_verify -- --nocapture

# Release mode for heavy computations
cargo test --release
```

## Security Notes
- Uses Free‑XOR and half‑gates; AES‑NI or BLAKE3 acts as the PRF/RO for garbling. Review cryptographic assumptions before production use.
- Arithmetic is in Montgomery form; take care when intermixing with non‑Montgomery values.
- Library code avoids panics where practicable; tests use fixed seeds for determinism.

## Contributing
- Start with `src/gadgets/groth16.rs` and BN254 submodules for verifier logic.
- Compare intermediate values to arkworks for debugging field/curve operations.
- Run `cargo fmt`, `cargo clippy`, and the full test suite before sending changes.

## Reflection
- The two‑pass streaming design (metadata “credits” + execution) materially reduces peak memory at scale and keeps the evaluator in lock‑step with the garbler via a simple ciphertext channel.
- Treating high‑level types (Fq, Fq2, Fq12, G1, G2) as first‑class “wire objects” makes complex gadgets compositional and testable, at the cost of careful attention to Montgomery domain boundaries.
- Component templates and an LRU pool are effective for repetitive shapes (e.g., MSM windows), and will keep paying dividends as examples grow in size.
