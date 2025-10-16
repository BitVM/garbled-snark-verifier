// An example demonstrating batch garbled circuit verification using MultigarblingMode.
// Creates a Groth16 proof (BN254), then verifies it 181 times in parallel using
// the new multigarbling mode with AES accumulating hash batching.
//
// This example showcases:
// - Batch processing of multiple garbled circuit instances
// - Parallel verification using optimized thread pools with CPU core affinity
// - AES-based ciphertext accumulation across multiple garbling lanes

use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
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

/// Run a batch of N garbled circuit verifications in parallel.
///
/// This function creates N garbling lanes, each with its own seed,
/// and runs them simultaneously using MultigarblingMode. The AES accumulating
/// hash batch collects ciphertexts from all lanes.
///
fn run_batch<const N: usize>(
    inputs: &garbled_groth16::GarblerInput,
    cap: usize,
    seeds: &[u64],
) -> Vec<[u8; 16]> {
    let mut seeds_array: [u64; N] = [0; N];
    let len = seeds.len();
    for (j, &s) in seeds.iter().enumerate() {
        seeds_array[j] = s;
    }
    let last_seed = seeds[len - 1];
    for item in seeds_array.iter_mut().skip(len) {
        *item = last_seed;
    }

    CircuitBuilder::run_streaming::<_, _, Vec<_>>(
        inputs.clone(),
        garbled_snark_verifier::circuit::modes::MultigarblingMode::<
            AesNiHasher,
            AESAccumulatingHashBatch<N>,
            N,
        >::new(cap, seeds_array, AESAccumulatingHashBatch::<N>::default()),
        |root, input| vec![garbled_groth16::verify(root, input)],
    )
    .ciphertext_handler_result
    .into_iter()
    .take(len)
    .collect::<Vec<[u8; 16]>>()
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

    const N: usize = 8;

    let all_seeds: Vec<u64> = (0..181usize)
        .map(|i| rand::random::<u64>().wrapping_add(i as u64))
        .collect();

    let t = Instant::now();

    let n_threads = num_cpus::get_physical().max(1);
    let chosen_cores = match core_affinity::get_core_ids() {
        Some(cores) if cores.len() >= 2 * n_threads => {
            cores.into_iter().take(n_threads).collect::<Vec<_>>()
        }
        Some(cores) => cores.into_iter().take(n_threads).collect::<Vec<_>>(),
        None => Vec::new(),
    };

    let pool = ThreadPoolBuilder::new()
        .num_threads(n_threads)
        .start_handler(move |thread_idx| {
            if let Some(core_id) = chosen_cores.get(thread_idx).cloned() {
                let _ = core_affinity::set_for_current(core_id);
            }
        })
        .build()
        .unwrap_or_else(|_| {
            ThreadPoolBuilder::new()
                .num_threads(n_threads)
                .build()
                .expect("failed to create fallback thread pool")
        });

    let results: Vec<[u8; 16]> = pool.install(|| {
        all_seeds
            .par_chunks(N)
            .flat_map(|chunk| run_batch::<N>(&inputs, cap, chunk))
            .collect::<Vec<[u8; 16]>>()
    });

    println!("{} instances total", results.len());

    let ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("181 instances: {:.2} ms", ms);
}
