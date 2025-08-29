# Repository Guidelines

## Project Structure & Module Organization
- `src/core`: base types and logic (`S`, `Wire`, `Gate`, `Circuit`).
- `src/circuit`: Groth16 verifier composition and high‑level circuits.
- `src/gadgets`: reusable components (bigint/u254, BN254 field/paired ops).
- `src/math`: lightweight math helpers.
- `circuit_component_macro/`: proc‑macro crate powering circuit component ergonomics; integration tests live in `circuit_component_macro/tests/{success,fail}`.

## Build, Test, and Development Commands
- `cargo build --workspace --all-features --release`: compile all crates.
- `cargo test --workspace --all-targets`: run unit, integration, and macro trybuild tests.
- `cargo fmt` / `cargo fmt --check`: auto‑format / verify formatting (CI enforces).
- `cargo clippy --no-deps --all-targets --all-features`: lint with warnings treated seriously.
- Example (gate counts, when examples are present): `cargo run --example groth16_gc_gate_count --release -- --json`.

## Coding Style & Naming Conventions
- Rust 2024 edition; 4‑space indentation; no trailing whitespace.
- Follow Rust conventions: `TypeName`, `snake_case` functions/modules, `SCREAMING_SNAKE_CASE` consts.
- Imports: keep tidy; rustfmt is configured to reorder and group (`rustfmt.toml`).
- Avoid `unsafe` unless essential and documented; prefer `thiserror` for error types and `Result` returns.

## Testing Guidelines
- Prefer deterministic tests; isolate randomness with fixed seeds.
- Unit tests near code with `#[cfg(test)]`; integration/compile‑fail/trybuild tests in `circuit_component_macro/tests`.
- Name tests descriptively (e.g., `test_gate_count_addition`); keep small and focused.
- Run locally with `cargo test --workspace`; add tests for new behaviors and bug fixes.

## Commit & Pull Request Guidelines
- Commits: imperative mood with scope prefix (e.g., `core: refactor Gate API`, `gadgets: add u254 add`); keep subject ≤ 72 chars; include rationale in body.
- PRs: clear description, linked issues, tests added/updated, CI green (`fmt`, `clippy`, `udeps`, `codespell`). Note any gate‑count changes impacting metrics.
- Keep diffs minimal; update README or docs when public APIs or structure change.

## Security & Toolchain Tips
- Use recent stable Rust (CI uses 1.85–1.88 for checks). Pin with `rustup toolchain install 1.88.0` if reproducing CI.
- Optional local checks: `cargo udeps` (nightly), `codespell` for typos. Avoid panics in library code; validate inputs early.

