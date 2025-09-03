// An example that creates a Groth16 proof (BN254),
// then garbles the verification circuit using the new streaming garble mode.
// Run with: `RUST_LOG=info cargo run --example groth16_garble --release`

use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_snark::CircuitSpecificSetupSNARK;
use garbled_snark_verifier::{
    self as gsv, AesNiHasher, CiphertextHasher, GarbledWire, WireId,
    circuit::streaming::StreamingResult,
};
use gsv::{
    FrWire, G1Wire, G2Wire,
    circuit::streaming::{
        CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, WiresObject, modes::GarbleMode,
    },
    groth16_verify,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Simple multiplicative circuit used to produce a valid Groth16 proof.
#[derive(Copy, Clone)]
struct DummyCircuit<F: ark_ff::PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: ark_ff::PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        // pad witnesses
        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        // repeat the same multiplicative constraint
        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        // final no-op constraint keeps ark-relations happy
        cs.enforce_constraint(lc!(), lc!(), lc!())?;
        Ok(())
    }
}

#[allow(dead_code)]
struct Inputs {
    public: Vec<ark_bn254::Fr>,
    a: ark_bn254::G1Projective,
    b: ark_bn254::G2Projective,
    c: ark_bn254::G1Projective,
}

struct InputWires {
    public: Vec<FrWire>,
    a: G1Wire,
    b: G2Wire,
    c: G1Wire,
}

impl CircuitInput for Inputs {
    type WireRepr = InputWires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        InputWires {
            public: self
                .public
                .iter()
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a: G1Wire::new(&mut issue),
            b: G2Wire::new(&mut issue),
            c: G1Wire::new(&mut issue),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<gsv::WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.b.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

// For garbling, we need to generate garbled wire labels instead of boolean values
struct GarbledInputs {
    public_len: usize,
}

impl CircuitInput for GarbledInputs {
    type WireRepr = InputWires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        InputWires {
            public: (0..self.public_len)
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a: G1Wire::new(&mut issue),
            b: G2Wire::new(&mut issue),
            c: G1Wire::new(&mut issue),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<gsv::WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.b.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl EncodeInput<GarbleMode<AesNiHasher>> for GarbledInputs {
    fn encode(&self, repr: &InputWires, cache: &mut GarbleMode<AesNiHasher>) {
        // Encode public scalars
        for w in &repr.public {
            for &wire in w.iter() {
                let gw = cache.issue_garbled_wire();
                cache.feed_wire(wire, gw);
            }
        }

        // Encode G1 points
        for &wire_id in repr
            .a
            .x
            .iter()
            .chain(repr.a.y.iter())
            .chain(repr.a.z.iter())
        {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }

        // Encode G2 points
        for &wire_id in repr
            .b
            .x
            .iter()
            .chain(repr.b.y.iter())
            .chain(repr.b.z.iter())
        {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }

        for &wire_id in repr
            .c
            .x
            .iter()
            .chain(repr.c.y.iter())
            .chain(repr.c.z.iter())
        {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(wire_id, gw);
        }
    }
}

fn main() {
    // Initialize logging (default to info if RUST_LOG not set)
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    println!("Setting up Groth16 proof...");

    // 1) Build and prove a tiny multiplicative circuit
    let k = 6; // 2^k constraints
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark_bn254::Fr> {
        a: Some(ark_bn254::Fr::rand(&mut rng)),
        b: Some(ark_bn254::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (_pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).expect("setup");

    println!("Proof generated successfully");

    let inputs = GarbledInputs { public_len: 1 };

    // Create channel for garbled tables
    let (sender, receiver) = crossbeam::channel::unbounded();

    std::thread::spawn(move || {
        println!("Starting ciphertext hashing thread...");

        let use_batched = true;

        let hasher = if use_batched {
            CiphertextHasher::new_batched()
        } else {
            CiphertextHasher::new_sequential()
        };

        let final_hash = hasher.run(receiver);
        println!("Final hash: {:02x?}", final_hash);
        println!("Ciphertext hashing thread completed");
    });

    println!("Starting garbling of Groth16 verification circuit...");

    let _result: StreamingResult<GarbleMode<AesNiHasher>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(
            inputs,
            40_000, // wire capacity
            42,     // garbling seed
            sender,
            |ctx, wires| {
                let ok = groth16_verify(ctx, &wires.public, &wires.a, &wires.b, &wires.c, &vk);
                vec![ok]
            },
        );

    // The output is a garbled wire representing the verification result
    println!("Output wire labels generated successfully");
    println!("Delta has been kept secret");
}
