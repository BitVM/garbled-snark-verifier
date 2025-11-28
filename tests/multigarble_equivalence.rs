// Equivalence test: MultigarblingMode (batched) vs sequential GarbleMode.
// Verifies that for identical seeds, the accumulated ciphertext hashes match lane-by-lane.

use garbled_snark_verifier::{
    AESAccumulatingHash, AESAccumulatingHashBatch,
    ark::{self, CircuitSpecificSetupSNARK, UniformRand},
    circuit::{CircuitBuilder, StreamingResult},
    garbled_groth16,
    hashers::AesNiHasher,
    test_utils::DummyCircuit,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

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
