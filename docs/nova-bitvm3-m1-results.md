# Nova BitVM3 M1: verified CI evidence

Evidence collected November 6, 2026 (Asia/Manila).

## Source and run

- Head commit: `9d44793c75557d3c093b90e433f0086f96d35a86`.
- CI merge commit: `61f61659b59dc7044f64371bf2549af60242d5ca`.
- [Successful Nova workflow](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42109054369).
- Conformance job: `127531468555`.
- [Evidence artifact](https://github.com/patrickdugan/garbled-snark-verifier/actions/runs/42109054369/artifacts/13454080025).
- Artifact ZIP SHA-256: `1b1100ac39938fecb8531647a5dc42c33bbe2d0500a7ecf04e6b5df85f794708`.

Python: 8 test groups passed (0.538 seconds on the CI runner).
Rust: 4 test groups passed (0.76 seconds after compilation), including
BigUint comparisons and AES garble/evaluate tests for both Pasta fields.
The native Nova reference completed successfully. The separate inherited CI
run 42109054314 failed its rustfmt check on src/nova.rs and skipped downstream
jobs. The following formatting-only code patch addresses that diff; these
results refer to the commit above and do not assert a full upstream test pass.

## Arithmetic predicate cost

Both fields produced the same counts. Each predicate includes canonical input
and output checks plus equality to the claimed result. These counts come from
the Rust garbling log, not extrapolation from the Python mirror.

| Predicate | Non-free gates | Free XOR gates | Total gates | Ciphertext bytes |
| --- | ---: | ---: | ---: | ---: |
| Addition | 3,075 | 6,912 | 9,987 | 49,200 |
| Multiplication | 719,875 | 1,309,952 | 2,029,827 | 11,518,000 |

Bytes count the emitted 16-byte ciphertext records only. They exclude input
labels, output commitments, cut-and-choose replication, proof transport and
Bitcoin transactions. The multiplication baseline has substantial room for
optimization. These counts do not establish a full Nova verifier cost.

## Native compressed proof

Statement: two applications of x -> x^2+5, with initial state 2 and expected
final state 86. Nova 0.76.0 uses Pallas/Vesta and Spartan/IPA on both curves.
The native program verified both recursive and compressed proofs, checked
serialization round-trip verification, rejected changed step count and initial
state, and checked the expected final state. It also matched the Boolean
kernel field moduli against the actual Nova dependency.

- Serialized compressed proof: **10,592 bytes**.
- Native program elapsed time: **5.90016912 seconds**. This includes parameter
  setup, recursive proving, compression and several verification calls; it
  excludes compilation and is not a proof-only or Bitcoin-header benchmark.
- Primary/secondary augmented circuit constraints: **9,820 / 10,349**.
- Proof SHA-256: `4ef3f1a889bbcf60e3b680846b4dfe8da9ad7f0cca00541178316b7407f0af9a`.
- Verifier-key SHA-256: `1fbcf1bb4982f9d95ed588871300160d6e826319218da030101ac9badbfacfc0`.

The native reference uses no Groth16/KZG wrapper. Its proof and verifier key
are included in the workflow artifact, along with the resolved dependency
lockfile, dependency tree, logs and resource records. Proof digests identify
this particular run; a freshly generated proof may differ.

## Scope

The garbled checks currently cover field arithmetic. The complete Nova/Spartan
verifier still requires curve operations, exact transcript reproduction and
both IPA verification paths. This run created no Bitcoin transactions and
establishes no end-to-end bridge security result. The 10,592-byte fixture is
native bincode proof serialization, not an assertion transaction size.

The test harness buffers ciphertexts in memory. Its live-wire reservation is
not a hard memory limit. Resource files measure compilation plus execution;
no runtime-only RAM claim is made here. Tests are evidence for the exercised
cases, not a formal proof or independent security audit.
