// An isolated example that creates a Groth16 proof (BN254),
// then verifies it via the streaming MPC-style executor with logs enabled.
// Run with: `RUST_LOG=info cargo run --example groth16_mpc --release`

use ark_ec::AffineRepr;
use ark_ff::UniformRand;
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use garbled_snark_verifier::{self as gsv, WireId, circuit::streaming::StreamingResult};
use gsv::{
    FrWire, G1Wire, G2Wire,
    circuit::streaming::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, WiresObject},
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

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Inputs {
    fn encode(&self, repr: &InputWires, cache: &mut M) {
        // Encode public scalars
        for (w, v) in repr.public.iter().zip(self.public.iter()) {
            let fr_fn = FrWire::get_wire_bits_fn(w, v).expect("fr encoding fn");
            for &wire in w.iter() {
                if let Some(bit) = fr_fn(wire) {
                    cache.feed_wire(wire, bit);
                }
            }
        }

        // Encode G1 points (Montgomery coordinates)
        let a_m = G1Wire::as_montgomery(self.a);
        let b_m = G2Wire::as_montgomery(self.b);
        let c_m = G1Wire::as_montgomery(self.c);

        let a_fn = G1Wire::get_wire_bits_fn(&repr.a, &a_m).expect("g1 a encoding fn");
        for &wire_id in repr
            .a
            .x
            .iter()
            .chain(repr.a.y.iter())
            .chain(repr.a.z.iter())
        {
            if let Some(bit) = a_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }

        let b_fn = G2Wire::get_wire_bits_fn(&repr.b, &b_m).expect("g1 a encoding fn");
        for &wire_id in repr
            .b
            .x
            .iter()
            .chain(repr.b.y.iter())
            .chain(repr.b.z.iter())
        {
            if let Some(bit) = b_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }

        let c_fn = G1Wire::get_wire_bits_fn(&repr.c, &c_m).expect("g1 c encoding fn");
        for &wire_id in repr
            .c
            .x
            .iter()
            .chain(repr.c.y.iter())
            .chain(repr.c.z.iter())
        {
            if let Some(bit) = c_fn(wire_id) {
                cache.feed_wire(wire_id, bit);
            }
        }
    }
}

fn main() {
    if !garbled_snark_verifier::hardware_aes_available() {
        eprintln!(
            "Warning: AES hardware acceleration not detected; using software AES (not constant-time)."
        );
    }
    // Initialize logging (default to info if RUST_LOG not set)
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

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

    // 2) Prepare inputs for the streaming gadget execution
    let inputs = Inputs {
        public: vec![c_val],
        a: proof.a.into_group(),
        b: proof.b.into_group(),
        c: proof.c.into_group(),
    };

    let result: StreamingResult<_, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(inputs, 40_000, |ctx, wires| {
            let ok = groth16_verify(ctx, &wires.public, &wires.a, &wires.b, &wires.c, &vk);
            vec![ok]
        });

    println!("verification_result={}", result.output_wires[0]);
    println!("gate count is {}", result.gate_count);
}
