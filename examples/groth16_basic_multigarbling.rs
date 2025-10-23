// Basic multigarbling example for a single Groth16 verification.
// This example:
// - demonstrates running multiple garbling lanes in parallel (N lanes)
// - measures wall-clock time for the multigarbling phase

use std::time::Instant;

use garbled_snark_verifier::{
    AESAccumulatingHashBatch,
    ark::{self, CircuitSpecificSetupSNARK, UniformRand},
    circuit::CircuitBuilder,
    garbled_groth16,
    hashers::AesNiHasher,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const LANES: usize = 8;

#[derive(Copy, Clone)]
struct DummyCircuit<F: ark::PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: ark::PrimeField> ark::ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(
        self,
        cs: ark::ConstraintSystemRef<F>,
    ) -> Result<(), ark::SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(ark::SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(ark::SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(ark::SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ =
                cs.new_witness_variable(|| self.a.ok_or(ark::SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(ark::lc!() + a, ark::lc!() + b, ark::lc!() + c)?;
        }

        cs.enforce_constraint(ark::lc!(), ark::lc!(), ark::lc!())?;
        Ok(())
    }
}

fn main() {
    garbled_snark_verifier::init_tracing();
    let cap = 150_000;
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark::Fr> {
        a: Some(ark::Fr::rand(&mut rng)),
        b: Some(ark::Fr::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << 10,
    };
    let (_pk, vk) = ark::Groth16::<ark::Bn254>::setup(circuit, &mut rng).expect("setup");

    let inputs = garbled_groth16::GarblerInput {
        public_params_len: 1,
        vk: vk.clone(),
    };

    let garbling_seed: u64 = rand::random::<u64>();
    let seeds: [u64; LANES] = std::array::from_fn(|i| garbling_seed.wrapping_add(i as u64));
    let t_multi = Instant::now();
    let _multi = CircuitBuilder::run_streaming::<_, _, Vec<_>>(
        inputs.clone(),
        garbled_snark_verifier::circuit::modes::MultigarblingMode::<
            AesNiHasher,
            AESAccumulatingHashBatch<LANES>,
            LANES,
        >::new(cap, seeds, AESAccumulatingHashBatch::<LANES>::default()),
        |root, input| vec![garbled_groth16::verify(root, input)],
    );
    let multi_ms = t_multi.elapsed().as_secs_f64() * 1000.0;

    println!("\nGroth16 (N={}) multigarble: {:.2} ms", LANES, multi_ms);
}
