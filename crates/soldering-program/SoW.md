# SoW: C&C SNARK for XOR-Delta Correctness with Aggregate Poseidon Commitments and Base SHA256

## 1) Scope and goals

Build a zero-knowledge SNARK or STARK for Cut-and-Choose (C&C) that proves:

1. Aggregate Poseidon commitment correctness per selected instance.
2. XOR-delta correctness between the base instance and every other selected instance, for both label polarities.
3. Base-label SHA256 integrity for each input wire.

The SNARK must not compute deltas; it must check the supplied deltas against the witness labels and the aggregate Poseidon commitments. The labels exist only in the prover's witness and must remain zero-knowledge hidden (besides any intentionally revealed by the challenger during dispute).

Assumptions:

- C&C verifies the SHA256 hashes of input labels externally. No RIPEMD160 gadget is needed inside the SNARK.
- During challenge, the challenger publishes specific labels `L_b[i0][j]` on-chain; the Bitcoin script enforces `RIPEMD160(SHA256(L_b[i0][j])) = RIPEMD160(H_b[j])`. Security relies on the collision resistance of SHA256 and RIPEMD160.

## 2) Fixed sizes and notation

- Label size: 128 bits = 16 bytes.
- Input wires per instance: `J = 1019` (configurable at the circuit level).
- Instance count: `N = 7` (configurable at the circuit level).
- Selection set: `K ⊆ {0, …, N-1}` is the subset of instances opened during the challenge.
- Base instance: `i0 ∈ K` is the designated base index. Define `K' = K \ {i0}`.
- Aggregate Poseidon input per instance `i`: `concat_j( L_0[i][j] || L_1[i][j] )`, length `2 * J * 16` bytes.
- SHA256 inputs: each label is 16 bytes (padded per SHA256 standard inside the gadget).

## 3) Data model (shapes only)

All arrays are indexed over the canonical instance order `0 .. N-1`. The selection is given as either an explicit list or a committed bitmask.

- Witness (private):
  - `labels0[i][j]`, `labels1[i][j]` for `i ∈ K`, `j ∈ {0, …, J-1}`; each is 16 bytes.

- Public inputs (known to the verifier):
  - `commitments[i]` – 32-byte Poseidon digest for each `i ∈ K`: `Poseidon( concat_j( L_0[i][j] || L_1[i][j] ) )`.
  - `selection[i]` – Boolean (or committed bitmask) indicating membership in `K`.
  - `base_index` – The index `i0` (must satisfy `selection[i0] = true`).
  - `sha0[j]`, `sha1[j]` – 32-byte SHA256 digests of `L_0[i0][j]` and `L_1[i0][j]` for all `j`.
  - `deltas0[i][j]`, `deltas1[i][j]` – 16-byte XOR deltas for `i ∈ K'`, `j ∈ {0, …, J-1}`. (Implementations may zero-fill or omit non-selected indices as convenient.)

## 4) SNARK statement (what is proven)

Public inputs: `commitments[0..N-1]`, `selection[0..N-1]`, `base_index`, `sha0[0..J-1]`, `sha1[0..J-1]`, `deltas0[0..N-1][0..J-1]`, `deltas1[0..N-1][0..J-1]`.

Witness: `labels0[0..N-1][0..J-1]`, `labels1[0..N-1][0..J-1]` (only required/used where `selection[i] = true`).

Constraints to enforce:

1) Delta correctness (two polarities): for all `i` with `selection[i] = true` and `i != base_index`, and all `j`:

```
deltas0[i][j] == labels0[base_index][j] XOR labels0[i][j]
deltas1[i][j] == labels1[base_index][j] XOR labels1[i][j]
```

2) Aggregate Poseidon commitment correctness: for all `i` with `selection[i] = true`:

```
commitments[i] == Poseidon( concat_j( labels0[i][j] || labels1[i][j] ) )
```

3) Base-label SHA256 integrity: for all `j`:

```
sha0[j] == SHA256( labels0[base_index][j] )
sha1[j] == SHA256( labels1[base_index][j] )
```

Equality and XOR operate on 16-byte values. The Poseidon digest is 32 bytes. SHA256 produces 32-byte digests.

## 5) Backend requirements (agnostic, but explicit)

Each implementation must:

- Implement Poseidon (or Poseidon2) to hash a message of length `2 * J * 16` bytes per selected instance. When the backend cannot absorb large inputs in one shot, chunking via sponge absorption or a Poseidon tree should be used. Maintain the canonical order across `j`.
- Implement XOR checks efficiently over 16-byte labels. For prime-field backends, use bit-decomposition/lookup to realize XOR semantics; for binary-field backends, use native XOR when available.
- Provide a SHA256 gadget that accepts 16-byte messages (with standard SHA256 padding) and outputs 32-byte digests.
- Preserve byte order for all gadgets (Poseidon, XOR, SHA256) exactly as provided at the interface boundary.
- Support compile-time configuration of `N` and `J` with defaults `N = 7`, `J = 1019`.
- Support `selection` as either public booleans or a committed bitmask with in-circuit boolean-constrained decoding.

## 6) Public API (language-agnostic, rust-like)

```
type Proof = Vec<u8>;

type Label = [u8; 16];
type Commit = [u8; 32];      // Poseidon aggregate digest
type ShaDigest = [u8; 32];   // SHA256(label)

// Prover: run by Garbler at C&C "OpenCommit"
fn prove_soldering<const I: usize = 7, const L: usize = 1019>(
    commitments: &[Commit; I],   // Aggregate Poseidon per selected instance
    selection: &[bool; I],       // True for instances in K
    base_index: usize,           // i0 (must satisfy selection[base_index])
    deltas0: &[[Label; L]; I],
    deltas1: &[[Label; L]; I],
    sha0: &[ShaDigest; L],
    sha1: &[ShaDigest; L],
    labels0: &[[Label; L]; I],
    labels1: &[[Label; L]; I],
) -> Proof;

// Verifier: run by Evaluator at C&C "CheckCommit"
fn verify_soldering<const I: usize = 7, const L: usize = 1019>(
    commitments: &[Commit; I],
    selection: &[bool; I],
    base_index: usize,
    deltas0: &[[Label; L]; I],
    deltas1: &[[Label; L]; I],
    sha0: &[ShaDigest; L],
    sha1: &[ShaDigest; L],
    proof: Proof,
) -> bool;
```

Implementations may compress `selection` to a bitmask field element or custom encoding suitable for the backend, so long as boolean constraints are enforced in-circuit.

## 7) Hashing workload

- Poseidon: `|K|` aggregate hashes (default `7` when all instances are selected).
- SHA256: `2 * J` hashes for the base instance (`2 * 1019` by default). Each SHA256 input is 16 bytes (one block with padding).
- XOR constraints: `2 * |K'| * J` byte-wise XOR relations across labels.

This focuses computational effort on SHA256, consistent with common SNARK/STARK benchmarking, and avoids RIPEMD160 gadgets in-circuit.

## 8) Bitcoin integration notes

- Script in the ChallengeAssert input checks `RIPEMD160(SHA256(L_b[i0][j])) = RIPEMD160(H_b[j])` for revealed labels. Thus, revealing `L_b[i0][j]` does not leak other labels unless a collision is found in SHA256 or RIPEMD160.
- The ZK proof guarantees the evaluator can compute `L_b[i][j]` for `i != i0` via the provided deltas and verified constraints.

## 9) Notes on Poseidon aggregation style

- The exact aggregation strategy may depend on the zk-backend. If absorbing large messages is cheap, a single long Poseidon absorb is fine. Otherwise, use a Poseidon tree over per-wire chunks `(label0 || label1)` to reduce constraints.
- Maintain a canonical ordering of inputs across implementations to keep commitments interoperable.

