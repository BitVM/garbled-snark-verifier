# Garbled SNARK Verifier Circuit

## Gate Count Metrics

Gate counts are automatically measured for k=6 (64 constraints) on every push to `main` and published as dynamic badges.

![Total Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/total.json)
![Non-Free Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/nonfree.json)
![Free Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/free.json)

---

## Code Explanation

### Core Folder

**s.rs**: contains **S** struct which is a basic wrapper around the type [u8; 32].

**utils.rs**: contains a few utility functions.

**wire.rs**: contains **Wire** struct.

**gate.rs**: contains **Gate** struct which has three wires, and a gate type. It also has **GateCount** which keeps track of number of gates in circuits.

**circuit.rs**: contains **Circuit** struct which has the garbled gates and circuit wires.

### Circuits Folder

this folder contains all the circuits needed for Groth16 verifier circuit.

**basic.rs**: contains basic circuits like half adder etc.

**bigint**: contains u254 circuits.

**bn254**: contains circuits related to bn254 curve such as field arithmetic circuits and pairing etc.

**groth16.rs**: contains the Groth16 verifier circuit.
