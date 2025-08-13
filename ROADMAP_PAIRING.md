# BN254 Pairing Roadmap (Gadgets Layer)

Status Update (current):
- Ell Coeffs: DONE (implemented and tested)
- Line Eval Helpers: DONE (implemented and tested)
- Miller Loop (const Q): DONE (implemented and tested: single + multi)
- Final Exponentiation: DONE (implemented and tested)
- Pairing API (FE ∘ ML): DONE (single + multi)
- Public Exports: DONE; Docs: UPDATED (constant‑Q note in module docs)
- Tests: All planned tests added and pass locally

## Scope
- Implement BN254 pairing (Miller loop + final exponentiation) using the existing streaming gadgets API.
- Treat G2 inputs as arkworks constants; G1 inputs are circuit wires (`G1Projective`).
- No legacy Wires/GateCount/Affine gadget API.

For original working code (SSOT), use `git show origin/main:src/circuits/bn254/pairing.rs` and related files (e.g., `origin/main:src/circuits/bn254/finalexp.rs`).

## Assumptions
- Field and curve gadgets in `src/gadgets/bn254/{fq,fq2,fq6,fq12,g1,g2}.rs` are correct and stable.
- We can precompute G2 line coefficients off‑circuit and feed them as constants.
- Tests compare against arkworks (`ark_bn254`) for correctness.

## Milestones and Success Cases

~~- Line Coefficients (G2)
  - Deliverables: `EllCoeff` type and `ell_coeffs(q: ark_bn254::G2Affine) -> Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>` for BN254 ATE loop (double/add steps).
  - Success: For random `Q`, number/shape of coeffs match arkworks; a spot‑check test evaluates one step and matches arkworks’ intermediate update.

 `git show main:src/circuits/bn254/g2.rs`~~ Already done

~~- Line Evaluation Helpers
  - Deliverables: `ell_eval_const(ctx, f: &Fq12, coeffs: &(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2), p: &G1Projective) -> Fq12` implemented via `Fq12::mul_by_034_constant4_montgomery`.
  - Success: Unit test applies a single line update against arkworks’ step and matches exactly.

  Implemented in `src/gadgets/bn254/pairing.rs` with a deterministic test.~~

- Miller Loop (Constant Q)
  - Deliverables: `miller_loop_const_q(ctx, p: &G1Projective, q: &ark_bn254::G2Affine) -> Fq12`; `multi_miller_loop_const_q(ctx, ps: &[G1Projective], qs: &[ark_bn254::G2Affine]) -> Fq12`.
  - Status: DONE in `src/gadgets/bn254/pairing.rs` with tests comparing against arkworks (single and N=3 multi).

~~- Final Exponentiation
  - Deliverables: `final_exponentiation(ctx, f: &Fq12) -> Fq12` (easy part + hard part) using Frobenius, inverses, cyclotomic square, and multiplications.
  - Success: For `f` from Miller loop, result equals `ark_bn254::pairing(p_affine, q_affine)`.

  Implemented in new module `src/gadgets/bn254/final_exponentiation.rs` mirroring main; streaming and native helpers included. Deterministic test compares FE(miller) to arkworks pairing and passes.~~

- Pairing API
  - Deliverables: `pairing_const_q(ctx, p: &G1Projective, q: &ark_bn254::G2Affine) -> Fq12` and a multi‑pair variant composing Miller loop + final exp.
  - Status: DONE. Implemented `pairing_const_q` and `multi_pairing_const_q` composing `miller_loop_const_q` + `final_exponentiation`, with single and N=3 tests.

- Public Exports and Docs
  - Deliverables: `src/gadgets/bn254/pairing.rs`; export module in `bn254/mod.rs`; module‑level docs describing constant‑Q assumption and inputs.
  - Status: Exports UPDATED (including `pairing_const_q`, `multi_pairing_const_q`). Docs UPDATED: module‑level constant‑Q note added in `pairing.rs`.

- Tests
  - Deliverables: Deterministic tests for:
    - Line evaluation step vs arkworks intermediate update. [DONE]
    - Miller loop output vs arkworks (single + multi). [DONE]
    - Final exponentiation output vs arkworks pairing. [DONE]
    - Multi‑pairing aggregation (e.g., N=3) vs arkworks. [DONE]
  - Notes: FE tests live in `src/gadgets/bn254/final_exponentiation.rs`; line eval step and ML/Pairing tests live in `src/gadgets/bn254/pairing.rs`.

## Optional Follow‑Ups (Out of Scope Now)
- Variable‑Q Miller Loop: compute line coefficients in‑circuit using `G2Projective::{double,add}_montgomery` and evaluate lines with fully variable coeffs.
- Compressed Deserialization Circuits: circuit gadgets to decompress G1/G2 and recover y via sqrt if verifier inputs require compressed points.
- Performance Tuning: micro‑optimize line eval paths using specialized `Fq12` multipliers or batching strategies.
