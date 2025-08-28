// An example that creates a Groth16 proof (BN254),
// then garbles the verification circuit using the new streaming garble mode.
// Run with: `RUST_LOG=info cargo run --example groth16_garble --release`

use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use garbled_snark_verifier::{
    self as gsv, AesNiHasher, Delta, GarbledWire, WireId, circuit::streaming::StreamingResult,
};
use gsv::{
    FrWire, G1Wire,
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
    c: ark_bn254::G1Projective,
}

struct InputWires {
    public: Vec<FrWire>,
    a: G1Wire,
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
            c: G1Wire::new(&mut issue),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<gsv::WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

// For garbling, we need to generate garbled wire labels instead of boolean values
struct GarbledInputs {
    public: Vec<ark_bn254::Fr>,
    #[allow(dead_code)]
    a: ark_bn254::G1Projective,
    #[allow(dead_code)]
    c: ark_bn254::G1Projective,
    garbled_wires: Vec<GarbledWire>,
}

impl CircuitInput for GarbledInputs {
    type WireRepr = InputWires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        InputWires {
            public: self
                .public
                .iter()
                .map(|_| FrWire::new(&mut issue))
                .collect(),
            a: G1Wire::new(&mut issue),
            c: G1Wire::new(&mut issue),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<gsv::WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl EncodeInput<GarbledWire> for GarbledInputs {
    fn encode<M: CircuitMode<WireValue = GarbledWire>>(&self, repr: &InputWires, cache: &mut M) {
        // For garbling, we use pre-generated garbled wire labels
        // In a real implementation, these would be generated based on the actual input bits
        let mut wire_index = 0;

        // Encode public scalars
        for w in &repr.public {
            for &wire in w.iter() {
                if wire_index < self.garbled_wires.len() {
                    cache.feed_wire(wire, self.garbled_wires[wire_index].clone());
                    wire_index += 1;
                }
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
            if wire_index < self.garbled_wires.len() {
                cache.feed_wire(wire_id, self.garbled_wires[wire_index].clone());
                wire_index += 1;
            }
        }

        for &wire_id in repr
            .c
            .x
            .iter()
            .chain(repr.c.y.iter())
            .chain(repr.c.z.iter())
        {
            if wire_index < self.garbled_wires.len() {
                cache.feed_wire(wire_id, self.garbled_wires[wire_index].clone());
                wire_index += 1;
            }
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
    let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).expect("setup");
    let c_val = circuit.a.unwrap() * circuit.b.unwrap();
    let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");

    println!("Proof generated successfully");

    // 2) Generate garbled wire labels for all input wires
    // In a real implementation, the garbler would generate these based on actual input bits
    let delta = Delta::generate(&mut rng);
    let num_input_wires = 254 + 254 * 3 + 254 * 3; // Fr scalar + 2 G1 points
    let garbled_wires: Vec<GarbledWire> = (0..num_input_wires)
        .map(|_| GarbledWire::random(&mut rng, &delta))
        .collect();

    // 3) Prepare inputs for the streaming garbling
    let inputs = GarbledInputs {
        public: vec![c_val],
        a: proof.a.into_group(),
        c: proof.c.into_group(),
        garbled_wires,
    };

    // Create channel for garbled tables
    let (sender, receiver) = std::sync::mpsc::channel();

    std::thread::spawn(move || while receiver.recv().is_ok() {});

    println!("Starting garbling of Groth16 verification circuit...");

    // 4) Run the streaming garbling of the Groth16 verifier gadget
    let _result: StreamingResult<GarbleMode<AesNiHasher>, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling(
            inputs,
            40_000, // wire capacity
            42,     // garbling seed
            sender,
            |ctx, wires| {
                let ok = groth16_verify(ctx, &wires.public, &wires.a, &proof.b, &wires.c, &vk);
                vec![ok]
            },
        );

    // The output is a garbled wire representing the verification result
    println!("Output wire labels generated successfully");
    println!("Delta has been kept secret");
}
