# Garbled SNARK Verifier Circuit

## Gate Count Metrics

Gate counts are automatically measured for k=6 (64 constraints) on every push to `main` and published as dynamic badges.

![Total Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/total.json)
![Non-Free Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/nonfree.json)
![Free Gates](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/BitVM/garbled-snark-verifier/gh-badges/badge_data/free.json)

---

A: operator, B: verifier

0. A and B agree on the circuit.

1. A creates labels for circuit wires, calculates hashes, and calculates garbles for the gates. And sends wire hashes and gate garbled rows to B.

2. A and B can both create the Assert, Reveal, and Disprove txes and they presign them.

3. A produces the groth16 proof.

4. A reveals the actual groth16 proof by opening their Winternitz signatures in **Assert**.

5. B checks the proofs, if it is OK, the procedure ends here.

6. If it is not OK, B challenges.

7. A reveals the preimages for only the input wires. A can do this using existing hash opcodes like OP_SHA256 instead of constructed hash functions.

8. If the revealed preimages do not match the committed groth16 proof, B can execute **Equivocation** by providing for example the signature of 0 and preimage of 1 for any wrong wire.

9. If they match, B off-chain calculates all wire values. If there is something wrong with the garbles or the gates (for example, A provided garbage garbled rows, or tries to evaluate OR gate instead of AND etc.), B is able to execute the disprove gate script for that gate.

10. Also, if garbles are correct and all wire values are calculated, but the final wire indicating the result of the verification is 0 instead of 1, B can execute **FinalWireEquivocation** by simply providing the preimage of 0.

## Code Explanation

### Core Folder

**s.rs**: contains **S** struct which is a basic wrapper around the type [u8; 32] that the all labels and hashes have.

**utils.rs**: contains a few utility functions

**wire.rs**: contains **Wire** struct which has randomly generated labels for value 0 and value 1, and their hashes. It also has useful getter and setter functions. Importantly, wires have *commitment_script*s which appears in every gate script for every wire of that gate.

**gate.rs**: contains **Gate** struct which has three wires, and a gate type ("and", "or", "xor", "nand", "not"). We can get the garbled rows for any gate and check if a given garble is correct or not. Importantly, gates have *gate_script*s which will then be used for disproving the operator and can be executed if the input bit commitments are correct, but the garble or the gate function is incorrect. We can understand it by the status of the output bit commitment script with the output wire label and value that come from garble check and gate check scripts.

**circuit.rs**: contains **Circuit** struct which has the garbled gates and circuit wires.

**bristol.rs**: contains the parser for parsing the bristol circuit files, several examples (adder64, subtracter64, multiplier64) are provided.

### Circuits Folder

this folder contains all the circuit functions. At the end, it will contain the circuit for groth16 proof verification.

**basic.rs**: contains basic circuits like half adder etc.

**bigint**: contains u254 circuits

**bn254**: contains circuits related to bn254 curve such as field arithmetic circuits etc.
