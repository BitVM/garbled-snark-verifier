# Setup and Evaluation

## Setup

#### Step 1 – Committing

##### Step 1.1 – Wide Label creation

- The garbler generates random polynomials of degree `n - f`. Each polynomial will represent one wide label value. Since we assume wide labels to represent 8 bits, and we have 256 wide label value per byte, for `x` input wires we have roughly `32x` polynomials.

##### Step 1.2 – Circuit Generation

- Garbler generates `n` garbled circuits: for each `i ∈ [n]`, create garbled circuit `GC_i` from a random seed.

##### Step 1.3 – Wide Label Lookup Table Creation

- The garbler computes the wide labels from the previously generated polynomials, and uses them to generate wide label lookup tables.

##### Step 1.3 – Label and table commits

- For every instance `i`, the garbler sends:

```
Commit(i) = {
    ciphertext_hash: H_ciphertext(all_ciphertexts_i),
    input_commits: [(H_label(wire_j_label0), H_label(wire_j_label1))]_j,
    output_commit: (H_label(L_valid), H_label(L_invalid)),
    constants: (true_wire_value, false_wire_value)
    wide_label_lookup_table_commit: H_wide_label_ciphertexts(all_wide_label_lookup_tables_i),
    share_commits: for each polynomial j, share_commit(i, j),
}
```

Additionally, the garbler sends a global commit - for each polynomial, the garbler sends commits to the coefficients to the evaluator.


#### Step 2 – Checking commits (part 1)

- Evaluator checks that the share commits are consistent with the polynomial commits.


#### Step 3 – Selecting

- Evaluator randomly partitions `[n]` into a check set `C` (size `n-f`) and an evaluation set `E` (size `f`).
- Evaluator sends the indices in `E` together with ciphertext handlers to receive ciphertext streams for finalized instances.
- Evaluator sends an index `a` from `E` that is to be used for the adaptor signatures. 
- Evaluator sends the (incomplete) adaptor signatures.

#### Step 4 – Opening

- Garbler reveals seeds for every instance in `C`:
  ```
  OpenSeeds = {(index_i, seed_i) : i ∈ C}
  ```
- Garbler reveals al wide label values (= shares) for every instance in `C`.
- Evaluator checks that the wide label values are consistent with the share commits.
- Evaluator regenerates the wide label lookup tables and checks that they are consistent with corresponding `wide_label_lookup_table_commit`.
- For each closed instance `i ∈ E`, the Garbler re‑garbles `GC_i` deterministically from its private seed and streams the resulting ciphertext blocks to Evaluator‑supplied handlers; the Evaluator recomputes the AES accumulating hash and verifies it matches `Commit_1(i).ciphertext_hash`. The ciphertext stream is transient and does not need to be persisted.
- Any mismatch (open or closed) aborts the protocol.

#### Step 5 – Setting up adaptor signatures

- Evaluator chooses an index `a` from one of the remaining `f` indices to be used in asserts.
- Evaluator sets up adaptor signatures for the instance `a`, assuming a previously agreed-upon bitcoin transaction. It sends the adaptor signatures to the garbler.


### Phase II: Evaluation

#### Step 1 – Publishing

- The garbler reveals wide labels for the instance `a` by submitting the transaction including the adaptor signatures on bitcoin

#### Step 2 – Extraction and polynomial reconstruction

- Evaluator extracts the wide labels for the instance `a` from the adaptor signatures.
- Evaluator uses the labels from the `C` instances together with the newly revealed labels to interpolate the labels for all instances in `E`.

#### Step 3 – Evaluating

- For each `i ∈ E`:
  - Evaluate `GC_i` from saved ciphertexts to obtain `L_valid` or `L_invalid` for each.
- If any `L_invalid` is obtained, the evaluator can post the disprove transaction by supplying the `L_invalid`.

## Message Summary

- (Garbler → Evaluator) Vssscommits: {Commit_1(i)}_{i∈[n]} + Polynomial commits
- (Evaluator → Garbler) FinalizeChallenge: indices to finalize. Additionally, the instance index to be used for the adaptor signatures, plus the incomplete adaptor signatures for this instance.
- (Garbler → Evaluator) OpenInstances: seeds and wide labels of all items in `C`, and garbled wide label lookup table for all items in `E`
- (Evaluator → Garbler) Adaptor signatures and index of 1 of the instances in `E`
- (Garbler → Bitcoin) Assert: Selected widelabels for given 1 instance.
