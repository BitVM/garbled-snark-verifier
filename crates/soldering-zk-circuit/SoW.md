# SoW: C&C SNARK for XOR-Delta Correctness with Per-Label Poseidon Commitments

## 1) Scope and goals

Build a zero-knowledge SNARK or STARK for Cut-and-Choose (C&C) that proves:

1. Each published per-label commitment equals the Poseidon hash of the corresponding label across the seven independent input-label sets.
2. For each selected instance (except the first one) and each input wire, the published XOR-delta equals the XOR of the base instance's label and that instance's label, done separately for label0 and label1.

The SNARK must not compute deltas; it must **check** the supplied deltas against the witness labels and the individual label commitments. The labels exist only in the prover's witness and must remain zero-knowledge hidden.

## 2) Fixed sizes and notation

* Label size: 128 bits = **16 bytes**.
* Input wires per instance: J = 1019. (but should be configurable at the circuit level)
* Instance Count: N = 7, (but should be configurable at the circuit level)

## 3) Data model (shapes only)

All arrays are aligned to the order of `selected`.

* **Witness (private):**
    * `labels0[m][J]`, `labels1[m][J]` where each element is 16 bytes.

* **Public inputs (known to verifier before verify call):**
    * `commits[m][J][2]` (individual 32-byte Poseidon digests for each label).
    * `deltas0[m][J]`, `deltas1[m][J]` (16-byte entries). These are pairwise XOR values of labels, where we count the deltas for 0 and 1 labels{0,1}, 0 and 2, 0 and 3, and so on up to 7th

* Hash function: For all label commitments we use Poseidon or Poseidon2, depending on the representation within zk-backend.

* **Commit construction (semantic rule):** Each label has its own individual Poseidon commit. The verifier will have individual Poseidon hashes of labels on hand.

## 4) SNARK statement (what is proven)

Public inputs: `commits[0..m-1][0..J-1][0..1]`, `deltas0[0..m-1][0..J-1]`, `deltas1[0..m-1][0..J-1]`.

Witness: `labels0[0..m-1][0..J-1]`, `labels1[0..m-1][0..J-1]`.

Constraints to enforce:

1. **Per-label commitment correctness:**
   Inside the circuit, compute per-label digests and verify:
```

For all r, j:
  commits[r][j][0] == Poseidon( labels0[r][j] )   // 16-byte input
  commits[r][j][1] == Poseidon( labels1[r][j] )

```

2. **Delta correctness (two polarities):**
For every row `r != 0` and wire `j`:
```

deltas0[r][j] == labels0[0][j] XOR labels0[r][j]
deltas1[r][j] == labels1[0][j] XOR labels1[r][j]

```
Equality and XOR operate on 16-byte values.

## 5) Backend requirements (agnostic, but explicit)

Each implementation must:

* Implement **Poseidon** or **Poseidon2** inside the circuit to compute per-label digests over 16-byte inputs.
* Implement XOR checks efficiently for 16-byte labels (e.g., byte/nibble lookup in prime-field systems; native bitwise in binary-tower systems).
* Preserve byte order within each 16-byte label exactly as provided.

## 6) Public API (language-agnostic, rust-like)

```rust
type Proof = Vec<u8>;

type Label = [u8; 16];

// Poseidon commit
type Hash = [u8; 32];

// Prover: run by Garbler at C&C "OpenCommit"
fn prove_soldering<const I: usize = 7, const L: usize = 1019>(
    commits: &[[[Hash; 2]; L]; I],  // Individual Poseidon hashes for each label
    deltas0: &[[Label; L]; I],
    deltas1: &[[Label; L]; I],
    labels0: &[[Label; L]; I],
    labels1: &[[Label; L]; I],
) -> Proof;

// Verifier: run by Evaluator at C&C "CheckCommit"
fn verify_soldering<const I: usize = 7, const L: usize = 1019>(
    commits: &[[[Hash; 2]; L]; I],  // Individual Poseidon hashes for each label
    deltas0: &[[Label; L]; I],
    deltas1: &[[Label; L]; I],
    proof: Proof,
) -> bool;

```

## 7) Potential Optimization: Commitment Aggregation

If compatible with the ZK backend implementation, we could potentially avoid having all individual hash commitments as public inputs by using aggregation techniques. Instead of providing `m * J * 2` individual Poseidon hashes (which could be thousands of public inputs), the circuit could aggregate these into a single global commitment using Poseidon in canonical order. This would reduce the public input size to a single 32-byte hash while maintaining the same security guarantees. The feasibility and efficiency of this optimization depends on the specific ZK backend characteristics and should be evaluated during implementation.
