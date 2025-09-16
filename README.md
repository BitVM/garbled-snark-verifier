# Garbled SNARK Verifier Circuit

## Gate Count Metrics

Gate counts are automatically measured for k=6 (64 constraints) on every push to `main` and published as dynamic badges.

![Total Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/total.json)
![Non-Free Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/nonfree.json)
![Free Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/free.json)

⚡ Performance (cut‑and‑choose oriented; developer laptop, AES‑NI)
- ⏱️ Per‑instance garbling: 11,174,708,821 gates in ~5m50s → ≈32M gates/s (≈31 ns/gate).
- 🧩 16‑instance C&C on 8 physical cores: overall garbling finished in ~11m58s → ≈249M gates/s aggregate. Wall‑clock time ≈ ceil(total_instances / physical_cores) × per_instance_time.
- 🔐 Focus: choose `total` (instances) for cut‑and‑choose soundness; runtime then scales as above. The monitor reports per‑instance progress and overall ETA.
- 💾 Memory (per garbling task): typically < 200 MB peak RSS. Total memory ≈ per‑instance usage × number of concurrently active instances (≈ physical cores).
- 🧪 Build flags: x86_64 with AES/SSE/AVX2/PCLMULQDQ enabled; see `.cargo/config.toml`. If AES‑NI is unavailable, prefer the BLAKE3 hasher in examples that allow selecting it.


A streaming garbled-circuit implementation of a Groth16 verifier over BN254. It targets large, real‑world verifier circuits while keeping memory bounded via a two‑pass streaming architecture. The crate supports three execution modes: direct boolean execution, garbling, and evaluation (2PC/MPC‑style).

**Background**
- **What:** Encode a SNARK verifier (Groth16 on BN254) as a boolean circuit and run it as a garbled circuit. The verifier’s elliptic‑curve and pairing arithmetic is expressed with reusable gadgets (Fq/Fr/Fq2/Fq6/Fq12, G1/G2, Miller loop, final exponentiation).
- **How:**
  - Use Free‑XOR and half‑gates (Zahur–Rosulek–Evans) to make XOR family gates free and reduce AND to two ciphertexts.
  - Keep field arithmetic in Montgomery form to minimize reductions and wire width churn; convert only at the edges when needed.
  - Run a two‑phase streaming pipeline: first collect a compact “shape” of wire lifetimes (credits), then execute once with precise allocation and immediate reclamation. Garbling and evaluation synchronize via a streaming channel of ciphertexts.

**Intended Use**
- Explore/benchmark streaming garbling on a non‑trivial circuit (Groth16 verifier).
- Reuse BN254 gadgets for experiments or educational purposes.
- Work with deterministic, testable building blocks that mirror arkworks semantics.

**Core Concepts**
- **WireId / Wires:** Logical circuit wires carried through streaming contexts; gadgets implement `WiresObject` to map rich types to wire vectors.
- **S / Delta:** Garbled labels and global offset for Free‑XOR; AES‑NI or BLAKE3 is used as the PRF/RO for half‑gates.
- **Modes:** `Execute` (booleans, for testing), `Garble` (produce ciphertexts + constants), `Evaluate` (consume ciphertexts + constants).
- **Components:** Functions annotated with `#[component]` become cached, nested circuit components; a component‑keyed template pool and a metadata pass compute per‑wire fanout totals and derive per‑wire "credits" (remaining‑use counters) for tight memory reuse.

**Terminology**
- **Fanout (total):** Total number of downstream reads/uses a wire will have within a component.
- **Credits (remaining):** The runtime counter that starts at the fanout total and is decremented on each read; when it reaches 1, the next read returns ownership and frees storage.

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
# Default (AES hasher; warns if HW AES is unavailable)
RUST_LOG=info cargo run --example groth16_garble --release

# Use BLAKE3 hasher instead of AES
RUST_LOG=info cargo run --example groth16_garble --release -- --hasher blake3
```
- Runs a complete two‑phase demo in one binary:
  - Pass 1: Garbles the verifier and streams ciphertexts to a hasher thread (reports garbling throughput and a ciphertext hash).
  - Pass 2: Spawns a garbler thread and an evaluator thread and streams ciphertexts over a channel to evaluate the same circuit shape.
- Prints a commit from the garbler with output label hashes and the ciphertext hash, and the evaluator verifies both the result label and ciphertext hash match.
- Tip: tweak the example’s `k` (constraint count) and `CAPACITY` (channel buffer) constants in `examples/groth16_garble.rs` to scale workload and tune throughput.

### Live Gate Monitor (Cut-and-Choose)
Two processes: (1) run the cut-and-choose demo and log stderr, (2) run the monitor.

- Process #1 (cut-and-choose + log): `RUST_LOG=info cargo run --example groth16_cut_and_choose --release 2> cc.log`
- Process #2 (monitor): `python3 .scripts/gates_monitor.py cc.log`
  - Follows `garble:` progress lines emitted during the first garbling pass and auto-detects the total instance count from `Starting cut-and-choose with <N> instances`.
  - Tracks per-instance throughput, ETA, and completion timing. Adjust the sliding window with `WINDOW_SEC=<seconds>`.
  - Ignores the `regarble:` stage so that only the initial garbling effort is measured.
  - Tweak log frequency via `src/core/progress.rs::GATE_LOG_STEP`.
  - The demo spins up a pinned Rayon pool sized to your physical core count (`num_cpus::get_physical()`), so parallelism is managed automatically. Adjust `total` only to change the cut-and-choose security parameter (number of candidate instances).
- Example run (developer laptop, 16 instances ≈178.8B gates): ~5m50s per garbling pass, 11m58s cumulative (~249M gates/s sustained). Adjust `total` primarily to meet your cut-and-choose soundness target—the monitor helps confirm the resulting wall-clock cost.

#### C&C Sizing (What matters)
- Security parameter: `total` (number of candidate instances) — pick this first based on desired soundness; `to_finalize` is how many are kept private and fully evaluated (1 in our demo).
- Parallelism: managed automatically by a pinned Rayon pool sized to physical cores; you don’t need to tune threads.
- Back‑of‑the‑envelope ETA: `ceil(total / physical_cores) × T_instance` where `T_instance` is your per‑instance garbling time (≈5m50s in the example run). The monitor gives a real‑time view of this.

#### Hasher selection
- The garbling/evaluation PRF for half‑gates can be selected via `--hasher`:
  - `aes` (default): AES‑based PRF (uses AES‑NI when available; warns and uses software fallback otherwise).
  - `blake3`: BLAKE3‑based PRF.
- Example: `cargo run --example groth16_garble --release -- --hasher blake3`.

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

## Contributing

Contributions are welcome. If you find a bug, have an idea, or want to improve performance or documentation, please open an issue or submit a pull request. For larger changes, start a discussion in an issue first so we can align on the approach. Thank you for helping improve the project.
