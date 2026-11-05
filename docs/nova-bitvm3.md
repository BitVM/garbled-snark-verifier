# Nova for BitVM3: M1

Target: Nova 0.76.0, Pallas/Vesta, Spartan compression with IPA on both curves.
The native reference uses transparent public-parameter generation. This path
contains no Groth16 or KZG proof wrapper. Existing Groth16 code remains upstream.

## Implemented

`src/nova.rs` supplies canonical 256-bit encoding checks and Boolean predicates
for addition and multiplication over both Pasta fields. Pallas's scalar field
is Vesta's base field. Every operand and claimed result must be strictly below
the selected modulus, including rejection of bit 255. Multiplication is a fixed
255-round Horner circuit. Each modular addition uses a reusable child component;
its cache key binds the field. Arithmetic uses the existing Execute, Garble and
Evaluate backends. This is a correctness baseline, with optimization pending.

`nova-bitvm3` is an isolated harness. Its Rust tests compare with BigUint and run
both operations through garbling/evaluation, including false result labels and
noncanonical results. The tests deliberately use reproducible seeds. Production
seed generation and malicious-garbler security are outside this milestone.

`nova-reference` creates a real native Nova proof of two steps of x -> x^2+5,
compresses with Spartan/IPA, verifies, serializes and verifies the round trip.
It checks the expected final output (2 -> 9 -> 86), rejects altered initial state
and step count, and compares the kernel moduli with Nova's actual scalar fields.
It writes proof.bin, vk.bin and a receipt with SHA-256 identities. These are
reference fixtures for implementing the Boolean verifier. The native verifier
is not called from inside a garbled circuit.

The root's SP1 build dependencies are now feature-gated, so this harness can
build with default features disabled without installing Groth16 artifacts.
The original default feature selection and SP1 behavior are retained.

## Verification and resource bounds

Local Python Boolean-mirror run: 8 test groups passed. This includes 32,768
exhaustive small-width addition predicates, 6,144 small-width multiplication
predicates, full-width random/edge cases, all 256 single-bit wrong addition
outputs on both fields, and noncanonical inputs. Those results establish the
Python mirror only. Rust compilation was unavailable in the local environment;
check the new GitHub Actions logs for Rust and native-proof outcomes.

CI runs one test thread and limits build/Rayon concurrency to two. It captures
peak RSS and elapsed time with /usr/bin/time. The allocator's 32,768-wire reserve
is NOT an enforced RAM limit. The test garbler retains ciphertexts in a Vec;
production streaming and memory-cap enforcement remain work items. Gate and
ciphertext counts printed by the Rust tests measure one arithmetic predicate,
not an entire Nova verifier. Build+run RSS includes compilation.

Direct dependency nova-snark is pinned to 0.76.0. CI exports its resolved lockfile
and dependency tree. A reviewed, committed lockfile is needed for reproducible
release builds. bincode files are internal version-pinned fixtures, not a final
public proof format. The runner takes only an output directory, not untrusted
serialized proofs.

## Run

```sh
python3 nova-bitvm3/reference.py
cargo test --release --manifest-path nova-bitvm3/Cargo.toml --lib -- --nocapture --test-threads=1
cargo run --release --manifest-path nova-bitvm3/Cargo.toml --features native-reference --bin nova-reference -- results/nova-reference
```

## Next milestone

1. Import complete Pallas/Vesta point arithmetic from the audited reference
   semantics in zk-rusto-no-bitcoino PR #18 (commit 474299439e178da7b965d6c3716bdb8320e082d3),
   with canonical infinity, on-curve checks and exceptional-case coverage.
2. Match Nova 0.76's exact transcript byte encoding, domain separation and
   challenge derivation. Trace both primary and secondary verification paths;
   transcript challenges cannot enter as unverified witness values.
3. Implement Spartan sumcheck, matrix/evaluation checks and the full IPA MSM,
   using a verifier-owned circuit shape and commitment generators. Bind the
   verifier-key digest, steps, initial state AND expected final state.
4. Establish complete native/Boolean/garbled differential verification of real
   compressed proofs, with malformed-point, wrong-VK, transcript mutation,
   replay and output-substitution cases. Then measure total verifier gates and
   assertion-input costs.
5. Bind the resulting verdict to an authenticated BitVM3 protocol and transaction
   graph, then test malicious setup and actual regtest dispute spends.

The header prover already exists at integrations/nova-header-chain on
zk-rusto-no-bitcoino's feat/nova-testnet4 branch, using the same Nova version and
IPA engines. Its fold width k is a circuit/key parameter. Existing checkpoints
and k are unchanged by M1. Garbler buffer/concurrency tuning is a separate knob.
Production statement binding must include network, circuit version, k, steps,
checkpoint provenance, expected chain state and the specific settlement claim.
A proof receipt alone does not authorize spending Bitcoin.

No complete Nova proof has yet been verified by these Boolean kernels. M1
implements no cut-and-choose upgrade, bridge security claim or Bitcoin spend.
