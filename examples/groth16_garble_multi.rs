use std::time::Instant;

use garbled_snark_verifier::{
    AESAccumulatingHash, GarbledWire,
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

    const N: usize = 16;
    let garbling_seed: u64 = rand::random::<u64>();

    let seeds: [u64; N] = std::array::from_fn(|i| garbling_seed.wrapping_add(i as u64));
    let t_multi = Instant::now();
    let _multi = CircuitBuilder::run_streaming::<_, _, Vec<_>>(
        inputs.clone(),
        garbled_snark_verifier::circuit::modes::MultigarblingMode::<
            AesNiHasher,
            AESAccumulatingHash,
            N,
        >::new(cap, seeds, AESAccumulatingHash::default()),
        |root, input| {
            if let garbled_snark_verifier::circuit::StreamingMode::ExecutionPass(ctx) = root {
                ctx.mode.set_queue_target_blocks(4096);
            }
            vec![garbled_groth16::verify(root, input)]
        },
    );
    let multi_ms = t_multi.elapsed().as_secs_f64() * 1000.0;

    let t_seq = Instant::now();
    for i in 0..N {
        let _seq: StreamingResult<
            garbled_snark_verifier::circuit::modes::GarbleMode<AesNiHasher, AESAccumulatingHash>,
            _,
            GarbledWire,
        > = CircuitBuilder::<
            garbled_snark_verifier::circuit::modes::GarbleMode<AesNiHasher, AESAccumulatingHash>,
        >::streaming_garbling(
            inputs.clone(),
            cap,
            garbling_seed.wrapping_add(i as u64),
            AESAccumulatingHash::default(),
            garbled_groth16::verify,
        );
    }
    let seq_ms = t_seq.elapsed().as_secs_f64() * 1000.0;

    println!("\nGroth16 multigarbling timing (Multi first):");
    println!("  1 multigarble: {:.2} ms", multi_ms);
    println!("  N sequential:  {:.2} ms", seq_ms);
    println!("  Speedup:       {:.2}x", seq_ms / multi_ms);
}
