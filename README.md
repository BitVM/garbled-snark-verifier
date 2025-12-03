# Garbled SNARK Verifier (BitVM)

![Total Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/total.json)
![Non-Free Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/nonfree.json)
![Free Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/free.json)

Rust reference implementation of a streaming garbled-circuit Groth16 verifier over BN254, aimed at conditional reveal / cut-and-choose flows (e.g. for Bitcoin-style protocols). It comes with three runnable protocols:
- **Vanilla cut-and-choose** (all finalized inputs revealed).
- **Soldering (SP1)** cut-and-choose (single base input, deltas proven by a zkVM).
- **VSSS + adaptor signatures** cut-and-choose (wide-label commitments for Bitcoin bridging).

## Techniques and features
- Half-gates garbling + Free-XOR.
- Multi-instance cut-and-choose wrapper (vanilla / soldering / VSSS).
- Static-key AES-based hash/PRF for gate labels (optional BLAKE3).
- Streaming, two-pass allocator to keep memory bounded on large circuits.

## Key references
- Groth16 zk-SNARK: J. Groth, “On the Size of Pairing-Based Non-Interactive Arguments”, EUROCRYPT 2016.
- Half-gates garbling: S. Zahur, M. Rosulek, D. Evans, “Two Halves Make a Whole: Reducing Data Transfer in Garbled Circuits Using Half Gates”, EUROCRYPT 2015.
- Free-XOR optimization: V. Kolesnikov, T. Schneider, “Improved Garbled Circuit: Free XOR Gates and Applications”, ICALP 2008.
- Fixed-key AES garbling: M. Bellare, V. T. Hoang, S. Keelveedhi, P. Rogaway, “Efficient Garbling from a Fixed-Key Blockcipher”, IEEE S&P 2013.
- Streaming garbled circuits: Y. Huang, D. Evans, J. Katz, L. Malka, “Faster Secure Two-Party Computation Using Garbled Circuits”, USENIX Security 2011.

## What this project gives you (quick answers)
- **Purpose**: Run a Groth16 verifier as a garbled circuit with cut-and-choose security, then plug its verdict into Bitcoin-style conditional release.
- **Protocol menu**: choose vanilla, soldering, or VSSS depending on how “revealed” your finalized inputs may be.
- **Scalability**: two-pass streaming garbling keeps memory bounded on 10B+ gate circuits.
- **Determinism**: the same circuit executes in three modes (`Execute`, `Garble`, `Evaluate`) for debugging and testing.
- **Docs + code**: runnable examples mirror the specs in `docs/` so you can trace every message.

## How the protocol works (conceptual)
1) **Garbled verifier**: Groth16 verification is compiled to boolean gates (BN254 arithmetic gadgets) and garbled with Free-XOR + half-gates.  
2) **Cut-and-choose**: Garbler commits to many circuit instances; Evaluator opens a random subset to check correctness and keeps the rest for evaluation.  
3) **Reveal policy** (pick one):  
   - *Vanilla*: Garbler sends all input labels for every finalized instance.  
   - *Soldering*: Garbler sends one base-instance input; an SP1 proof plus per-instance deltas binds every finalized instance to the same committed inputs.  
   - *VSSS*: Inputs are secret-shared as “wide labels”; adaptor signatures on Bitcoin transactions reveal just enough to reconstruct the finalized inputs.  
4) **Evaluation**: Evaluator consumes ciphertext streams and labels, evaluates the garbled verifier, and learns the committed verdict label (`L_valid` or `L_invalid`).  
5) **Bitcoin glue**: Verdict labels can gate on-chain actions (e.g., publish `L_invalid` to disprove).

## Tech stack and assumptions
- **Language / toolchain**: Rust 1.90 (`rust-toolchain.toml`).
- **Crypto**: arkworks Groth16 (BN254); half-gates garbling with AES-CCR or BLAKE3 as PRF; Free-XOR. Montgomery field arithmetic gadgets.
- **Parallelism**: rayon + crossbeam; streaming allocator keeps RSS low (typically <200 MB per garbling task).
- **Optional**: SP1 zkVM for soldering proofs (`sp1-soldering-program/`);
- **Hardware**: x86_64 with AES/SSE/AVX2/PCLMULQDQ recommended; software AES fallback works but is slower.

## Installation

### Prerequisites
- [Rust](https://rustup.rs/) (see `rust-toolchain.toml` for version)
- Git
- x86_64 CPU with AES-NI recommended

### Clone and build
```bash
git clone https://github.com/BitVM/garbled-snark-verifier.git
cd garbled-snark-verifier
cargo build --release
```

### SP1 toolchain (required for `sp1-soldering` feature)
If you want to run the soldering protocol with SP1 proofs, install the full [SP1 toolchain](https://docs.succinct.xyz/docs/sp1/getting-started/install):
```bash
curl -L https://sp1up.succinct.xyz | bash
sp1up
```
Verify the installation:
```bash
cargo prove --version
cargo +succinct --version
```

## Pick a protocol track (examples)
- **Vanilla cut-and-choose** — evaluator receives all finalized inputs (baseline correctness check).  
  `RUST_LOG=info cargo run --example gsv_vanilla --release`
- **Soldering (SP1)** — single base input; SP1 proof enforces input consistency across finalized instances (see `docs/gsv_soldering.md`).  
  `RUST_LOG=info cargo run --example gsv_soldering --release --features sp1-soldering`
- **VSSS + adaptor signatures** — wide-label commitments for Bitcoin bridging (see `docs/gsv_vsss.md`).  
  `RUST_LOG=info cargo run --example gsv_vsss --release --features vsss`
- **Minimal verifier demo** — prove+verify without C&C.  
  `RUST_LOG=info cargo run --example groth16_mpc --release`
- **Garble → evaluate pipeline** — single binary runs both passes.  
  `RUST_LOG=info cargo run --example groth16_garble --release -- --hasher blake3`
- **Cut-and-choose monitor** — live throughput/ETA from logs.  
  `RUST_LOG=info cargo run --example groth16_cut_and_choose --release 2> cc.log`  
  `python3 .scripts/gates_monitor.py cc.log`

## Architecture (mental model)
- **Two-pass streaming**: Pass 1 collects circuit “shape” (wire fanouts → credits). Pass 2 garbles/evaluates once with immediate wire reclamation; ciphertexts stream via bounded channels.
- **Gadgets**: BN254 fields/groups (Montgomery), Miller loop, final exponentiation, Groth16 verifier wiring.
- **Modes**: `Execute` (boolean eval), `Garble` (produce ciphertexts + constants), `Evaluate` (consume ciphertexts).
- **Components**: `#[component]` macro caches circuit templates; deterministic layouts for reproducibility.

## Repository map
- `src/core` — wire/label types, gates, PRF plumbing.
- `src/circuit` — streaming builder, two-pass allocator, modes, tests.
- `src/gadgets` — bigint/u254, BN254 fields/groups, pairing, Groth16 verifier.
- `src/math` — Montgomery helpers.
- `examples/` — protocol drivers (`gsv_vanilla`, `gsv_soldering`, `gsv_vsss`), pipeline demos, monitors.
- `docs/` — protocol specs (`gsv_soldering.md`, `gsv_vsss.md`).
- `sp1-soldering-program/` — SP1 zkVM for soldering proofs.
- `circuit_component_macro/` — `#[component]` proc-macro + trybuild tests.

## Performance snapshot (developer laptop, AES-NI)
- Per-instance garbling: ~11.2B gates in ~3m 20s (~57M gates/s).
- Memory: <200 MB RSS per garbling task; total ≈ per-instance × concurrent instances.
- Hasher: AES by default;

## Testing
```bash
# Full workspace
cargo test --workspace --all-targets

# Focused Groth16 verifier tests
RUST_BACKTRACE=1 cargo test test_groth16_verify -- --nocapture

# Heavier coverage
cargo test --release
```

## Contributing
PRs and issues welcome. If you extend the Bitcoin glue (soldering or VSSS/adaptor flows), cite the corresponding doc (`docs/gsv_soldering.md` or `docs/gsv_vsss.md`) so reviewers can track protocol alignment. 

See `LICENCE` for licensing.
