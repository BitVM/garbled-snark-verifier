// Equivalence test: MultigarblingMode (batched) vs sequential GarbleMode.
// Verifies that for identical seeds, the accumulated ciphertext hashes match lane-by-lane.

use garbled_snark_verifier::{
    AESAccumulatingHash, AESAccumulatingHashBatch,
    ark::{self, CircuitSpecificSetupSNARK, UniformRand},
    circuit::{CircuitBuilder, StreamingResult},
    garbled_groth16,
    hashers::AesNiHasher,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

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

#[test]
#[ignore]
fn multigarble_vs_sequential_equivalence() {
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

    const N: usize = 8;

    // Root seed for deterministic per-lane seeds
    let garbling_seed: u64 = 42_4242;
    let seeds: [u64; N] = std::array::from_fn(|i| garbling_seed.wrapping_add(i as u64));

    let multi = CircuitBuilder::run_streaming::<_, _, Vec<_>>(
        inputs.clone(),
        garbled_snark_verifier::circuit::modes::MultigarblingMode::<
            AesNiHasher,
            AESAccumulatingHashBatch<N>,
            N,
        >::new(cap, seeds, AESAccumulatingHashBatch::<N>::default()),
        |root, input| vec![garbled_groth16::verify(root, input)],
    );

    let multi_hashes: Vec<[u8; 16]> = multi.ciphertext_handler_result.into_iter().collect();

    let mut seq_hashes: Vec<[u8; 16]> = Vec::with_capacity(N);
    for &seed in seeds.iter() {
        let seq: StreamingResult<
            garbled_snark_verifier::circuit::modes::GarbleMode<AesNiHasher, AESAccumulatingHash>,
            _,
            garbled_snark_verifier::GarbledWire,
        > = CircuitBuilder::<
            garbled_snark_verifier::circuit::modes::GarbleMode<AesNiHasher, AESAccumulatingHash>,
        >::streaming_garbling(
            inputs.clone(),
            cap,
            seed,
            AESAccumulatingHash::default(),
            garbled_groth16::verify,
        );
        seq_hashes.push(seq.ciphertext_handler_result);
    }

    assert_eq!(multi_hashes.len(), seq_hashes.len());
    assert_eq!(multi_hashes, seq_hashes);
}
