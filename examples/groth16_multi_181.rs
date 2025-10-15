use rayon::ThreadPoolBuilder;
use rayon::prelude::*;
use std::time::Instant;

use garbled_snark_verifier::{
    AESAccumulatingHash, GarbledWire,
    ark::{self, CircuitSpecificSetupSNARK, UniformRand},
    circuit::{CircuitBuilder, StreamingMode, StreamingResult},
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
            .flat_map(|chunk| {
                if chunk.len() == N {
                    let seeds_array: [u64; N] = chunk.try_into().unwrap();

                    CircuitBuilder::run_streaming::<_, _, Vec<_>>(
                        inputs.clone(),
                        garbled_snark_verifier::circuit::modes::MultigarblingMode::<
                            AesNiHasher,
                            AESAccumulatingHash,
                            N,
                        >::new(
                            cap,
                            seeds_array,
                            std::array::from_fn(|_| AESAccumulatingHash::default()),
                        ),
                        |root, input| {
                            if let StreamingMode::ExecutionPass(ctx) = root {
                                ctx.mode.set_queue_enabled(false);
                            }
                            vec![garbled_groth16::verify(root, input)]
                        },
                    )
                    .ciphertext_handler_result
                } else {
                    {
                        let mut seeds_array: [u64; N] = [0; N];
                        for (j, &s) in chunk.iter().enumerate() {
                            seeds_array[j] = s;
                        }
                        let last_seed = chunk[chunk.len() - 1];
                        for j in chunk.len()..N {
                            seeds_array[j] = last_seed;
                        }

                        CircuitBuilder::run_streaming::<_, _, Vec<_>>(
                            inputs.clone(),
                            garbled_snark_verifier::circuit::modes::MultigarblingMode::<
                                AesNiHasher,
                                AESAccumulatingHash,
                                N,
                            >::new(
                                cap,
                                seeds_array,
                                std::array::from_fn(|_| AESAccumulatingHash::default()),
                            ),
                            |root, input| {
                                if let StreamingMode::ExecutionPass(ctx) = root {
                                    ctx.mode.set_queue_enabled(false);
                                }
                                vec![garbled_groth16::verify(root, input)]
                            },
                        )
                        .ciphertext_handler_result
                        .into_iter()
                        .take(chunk.len())
                        .collect::<Vec<[u8; 16]>>()
                    }
                }
            })
            .collect::<Vec<[u8; 16]>>()
    });

    println!("{} instances total", results.len());

    let ms = t.elapsed().as_secs_f64() * 1000.0;
    println!("181 instances: {:.2} ms", ms);
}
