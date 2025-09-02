// groth16_g2e.rs - Parallel Groth16 Garble-to-Evaluate Pipeline
//
// This example demonstrates streaming synchronization between a garbler and evaluator
// processing the same Groth16 verification circuit. The garbler generates input wires
// and streams 300+ GB of ciphertexts to the evaluator, which processes them synchronously
// to produce identical output wires.
//
// Run with: `RUST_LOG=info cargo run --example groth16_g2e --release`

use std::{iter, thread, time::Instant};

use ark_ec::AffineRepr;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use crossbeam::channel;
use garbled_snark_verifier::{
    self as gsv, AesNiHasher, EvaluatedWire, Fp254Impl, FqWire, GarbledWire, GateHasher, WireId,
    bits_from_biguint_with_len,
    circuit::streaming::{
        CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, StreamingResult, WiresObject,
        modes::{EvaluateMode, GarbleMode},
    },
    groth16_verify,
};
use gsv::{FrWire, G1Wire};
use itertools::Itertools;
use log::{error, info, trace};
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// Simple multiplicative circuit used to produce a valid Groth16 proof
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

// Wire representation for Groth16 circuit inputs
struct Groth16InputWires {
    public: Vec<FrWire>,
    a: G1Wire,
    c: G1Wire,
}

// Garbler's input encoding using pre-generated garbled wires
#[derive(Debug)]
struct GarblerInputs {
    public: Vec<ark_bn254::Fr>,
    a: ark_bn254::G1Projective,
    c: ark_bn254::G1Projective,
}

impl CircuitInput for GarblerInputs {
    type WireRepr = Groth16InputWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Groth16InputWires {
            public: iter::repeat_with(|| FrWire::new(&mut issue))
                .take(self.public.len())
                .collect(),
            a: G1Wire::new(&mut issue),
            c: G1Wire::new(&mut issue),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl<H: GateHasher> EncodeInput<GarbleMode<H>> for GarblerInputs {
    fn encode(&self, repr: &Groth16InputWires, cache: &mut GarbleMode<H>) {
        repr.public
            .iter()
            .flat_map(|f| f.iter())
            .chain(repr.a.iter_wires())
            .chain(repr.c.iter_wires())
            .for_each(|wire| {
                let gw = cache.issue_garbled_wire();
                cache.feed_wire(*wire, gw);
            });
    }
}

impl GarblerInputs {
    // Return true wire, false wire values and inputs, correctly intepret wires`
    pub fn to_evaluated_inputs(
        &self,
        wires: Vec<GarbledWire>,
    ) -> ((EvaluatedWire, EvaluatedWire), EvaluatorInputs) {
        assert_eq!(
            wires.len(),
            2 + (self.public.len() * FrWire::N_BITS) + (FqWire::N_BITS * 6)
        );
        let mut wires = wires.iter();
        let false_wire = EvaluatedWire::new_from_garbled(wires.next().unwrap(), false);
        let true_wire = EvaluatedWire::new_from_garbled(wires.next().unwrap(), true);

        let public: Vec<EvaluatedFrWires> = self
            .public
            .iter()
            .map(|f| {
                let wires = wires.by_ref().take(FrWire::N_BITS).collect::<Box<[_]>>();
                assert_eq!(wires.len(), FrWire::N_BITS);

                let bits =
                    bits_from_biguint_with_len(&BigUint::from(f.into_bigint()), FrWire::N_BITS)
                        .unwrap();

                assert_eq!(bits.len(), FrWire::N_BITS);

                bits.into_iter()
                    .zip_eq(wires)
                    .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                    .collect()
            })
            .collect();

        let to_bits = |f: &ark_bn254::Fq| {
            bits_from_biguint_with_len(&BigUint::from(f.into_bigint()), FqWire::N_BITS)
                .unwrap()
                .into_iter()
        };

        let a = EvaluatedG1Wires {
            x: to_bits(&self.a.x)
                .zip_eq(wires.by_ref().take(FqWire::N_BITS))
                .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                .collect(),
            y: to_bits(&self.a.y)
                .zip_eq(wires.by_ref().take(FqWire::N_BITS))
                .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                .collect(),
            z: to_bits(&self.a.z)
                .zip_eq(wires.by_ref().take(FqWire::N_BITS))
                .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                .collect(),
        };

        let c = EvaluatedG1Wires {
            x: to_bits(&self.c.x)
                .zip_eq(wires.by_ref().take(FqWire::N_BITS))
                .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                .collect(),
            y: to_bits(&self.c.y)
                .zip_eq(wires.by_ref().take(FqWire::N_BITS))
                .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                .collect(),
            z: to_bits(&self.c.z)
                .zip_eq(wires.by_ref().take(FqWire::N_BITS))
                .map(|(bit, gw)| EvaluatedWire::new_from_garbled(gw, bit))
                .collect(),
        };

        ((true_wire, false_wire), EvaluatorInputs { public, a, c })
    }
}

type EvaluatedFrWires = Vec<EvaluatedWire>;

#[derive(Debug)]
struct EvaluatedG1Wires {
    x: Vec<EvaluatedWire>,
    y: Vec<EvaluatedWire>,
    z: Vec<EvaluatedWire>,
}

impl EvaluatedG1Wires {
    fn iter(&self) -> impl Iterator<Item = &EvaluatedWire> {
        let Self { x, y, z } = self;

        x.iter().chain(y.iter()).chain(z.iter())
    }
}

#[derive(Debug)]
struct EvaluatorInputs {
    public: Vec<EvaluatedFrWires>,
    a: EvaluatedG1Wires,
    c: EvaluatedG1Wires,
}

impl CircuitInput for EvaluatorInputs {
    type WireRepr = Groth16InputWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Groth16InputWires {
            public: iter::repeat_with(|| FrWire::new(&mut issue))
                .take(self.public.len())
                .collect(),
            a: G1Wire::new(&mut issue),
            c: G1Wire::new(&mut issue),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = Vec::new();
        for s in &repr.public {
            ids.extend(s.to_wires_vec());
        }
        ids.extend(repr.a.to_wires_vec());
        ids.extend(repr.c.to_wires_vec());
        ids
    }
}

impl<M: CircuitMode<WireValue = EvaluatedWire>> EncodeInput<M> for EvaluatorInputs {
    fn encode(&self, repr: &Groth16InputWires, cache: &mut M) {
        repr.public
            .iter()
            .zip_eq(self.public.iter())
            .for_each(|(wires, vars)| {
                wires
                    .iter()
                    .zip_eq(vars.iter())
                    .for_each(|(wire_id, evaluated_wire)| {
                        cache.feed_wire(*wire_id, evaluated_wire.clone());
                    });
            });

        repr.a
            .iter_wires()
            .zip_eq(self.a.iter())
            .for_each(|(wire_id, evaluated_wire)| {
                cache.feed_wire(*wire_id, evaluated_wire.clone());
            });

        repr.c
            .iter_wires()
            .zip_eq(self.c.iter())
            .for_each(|(wire_id, evaluated_wire)| {
                cache.feed_wire(*wire_id, evaluated_wire.clone());
            });
    }
}

fn main() {
    // Initialize logging
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .try_init();

    info!("🚀 Starting Groth16 Garble-to-Evaluate Pipeline Example");

    // 1) Generate Groth16 proof
    info!("📊 Generating Groth16 proof...");

    let k = 8; // 2^k constraints - increase for larger circuits
    let mut rng = ChaCha20Rng::seed_from_u64(12345);
    let circuit = DummyCircuit::<ark_bn254::Fr> {
        a: Some(ark_bn254::Fr::rand(&mut rng)),
        b: Some(ark_bn254::Fr::rand(&mut rng)),
        num_variables: 100,
        num_constraints: 1 << k,
    };
    let (pk, vk) = Groth16::<ark_bn254::Bn254>::setup(circuit, &mut rng).expect("setup");
    let proof = Groth16::<ark_bn254::Bn254>::prove(&pk, circuit, &mut rng).expect("prove");

    info!("✅ Groth16 proof generated successfully");

    // 2) Generate input wires using deterministic seed
    info!("🔧 Generating deterministic input wires...");

    let garbler_seed = 42;

    // 3) Create channels for parallel communication
    let (ciphertext_tx, ciphertext_rx) = channel::bounded::<(usize, gsv::S)>(1000); // Bounded for backpressure
    let (input_wire_tx, input_wire_rx) = channel::unbounded::<EvaluatorInputs>(); // Small transfer

    // 4) Prepare garbler inputs
    let garbler_inputs = GarblerInputs {
        public: vec![circuit.a.unwrap() * circuit.b.unwrap()],
        a: proof.a.into_group(),
        c: proof.c.into_group(),
    };

    // Convert garbled wires to evaluated wires for evaluator
    // In real system, this would be determined by actual input bit values
    let ((true_wire, false_wire), evaluated_input_wires) = garbler_inputs.to_evaluated_inputs(
        GarbleMode::<AesNiHasher>::preallocate_input(garbler_seed, &garbler_inputs),
    );

    info!("🔧 Input wire encoding synchronized between garbler and evaluator");

    // Send input wires to evaluator
    if let Err(e) = input_wire_tx.send(evaluated_input_wires) {
        error!("Failed to send input wires to evaluator: {}", e);
        return;
    }

    info!("🧵 Launching parallel garbler and evaluator threads...");

    // 5) Launch Garbler Thread
    let garbler_vk = vk.clone();
    let garbler_proof_b = proof.b;
    let garbler_handle = thread::spawn(move || {
        info!("🔐 [GARBLER] Starting garbling process...");
        let start_time = Instant::now();

        let result: StreamingResult<GarbleMode<AesNiHasher>, _, Vec<GarbledWire>> =
            CircuitBuilder::streaming_garbling(
                garbler_inputs,
                40_000,
                garbler_seed,
                ciphertext_tx,
                |ctx, wires| {
                    let ok = groth16_verify(
                        ctx,
                        &wires.public,
                        &wires.a,
                        &garbler_proof_b,
                        &wires.c,
                        &garbler_vk,
                    );
                    vec![ok]
                },
            );

        let elapsed = start_time.elapsed();
        info!("🔐 [GARBLER] Completed in {:.2}s", elapsed.as_secs_f64());
        info!("🔐 [GARBLER] Output wires: {}", result.output_wires.len());

        result.output_wires
    });

    // 6) Launch Evaluator Thread
    let evaluator_vk = vk.clone();
    let evaluator_proof_b = proof.b;
    let evaluator_handle = thread::spawn(move || {
        info!("🔍 [EVALUATOR] Waiting for input wires...");

        let received_input = match input_wire_rx.recv() {
            Ok(wires) => wires,
            Err(e) => {
                error!("🔍 [EVALUATOR] Failed to receive input wires: {}", e);
                return Vec::new();
            }
        };

        let start_time = Instant::now();

        // Evaluate with AES-NI hasher to match garbler
        let result: StreamingResult<EvaluateMode<AesNiHasher>, _, Vec<EvaluatedWire>> =
            CircuitBuilder::streaming_evaluation(
                received_input,
                40_000, // wire capacity
                true_wire.active_label,
                false_wire.active_label,
                ciphertext_rx,
                |ctx, wires| {
                    let ok = groth16_verify(
                        ctx,
                        &wires.public,
                        &wires.a,
                        &evaluator_proof_b,
                        &wires.c,
                        &evaluator_vk,
                    );
                    vec![ok]
                },
            );

        let elapsed = start_time.elapsed();
        info!("🔍 [EVALUATOR] Completed in {:.2}s", elapsed.as_secs_f64());
        info!("🔍 [EVALUATOR] Output wires: {}", result.output_wires.len());
        if let Some(out) = result.output_wires.first() {
            trace!(
                "[EVALUATOR][output] value={} active_label={}",
                out.value,
                out.active_label.to_hex()
            );
        }
        result.output_wires
    });

    // 7) Wait for both processes and verify results
    info!("⏳ Waiting for garbler and evaluator to complete...");

    let garbler_result = match garbler_handle.join() {
        Ok(result) => result,
        Err(e) => {
            error!("🔐 [GARBLER] Thread panicked: {:?}", e);
            return;
        }
    };

    let evaluator_result = match evaluator_handle.join() {
        Ok(result) => result,
        Err(e) => {
            error!("🔍 [EVALUATOR] Thread panicked: {:?}", e);
            return;
        }
    };

    // 8) Verify synchronization
    info!("🔍 Verifying results...");

    if garbler_result.len() != evaluator_result.len() {
        error!(
            "❌ Output wire count mismatch: garbler={}, evaluator={}",
            garbler_result.len(),
            evaluator_result.len()
        );
        return;
    }

    if garbler_result.is_empty() || evaluator_result.is_empty() {
        error!("❌ No output wires produced");
        return;
    }

    // Compare the active labels of the output wires
    let garbler_output = &garbler_result[0];
    let evaluator_output = &evaluator_result[0];

    // For comparison, we need to check if the evaluator got the right label
    // The evaluator should have either label0 or label1 from the garbled wire
    let labels_match = evaluator_output.active_label == garbler_output.label0
        || evaluator_output.active_label == garbler_output.label1;

    if labels_match {
        info!("✅ SUCCESS: Garbler and Evaluator produced consistent results!");
        info!("🔐 Garbler output wire: label0={:?}", garbler_output.label0);
        info!("🔐 Garbler output wire: label1={:?}", garbler_output.label1);
        info!(
            "🔍 Evaluator active label: {:?}",
            evaluator_output.active_label
        );
        info!("🔍 Evaluator plaintext value: {}", evaluator_output.value);

        // Verify the Groth16 verification result
        let groth16_result = evaluator_output.value;
        info!("📊 Groth16 verification result: {}", groth16_result);

        if groth16_result {
            info!("🎉 Groth16 proof verification PASSED!");
        } else {
            info!("⚠️ Groth16 proof verification FAILED (but synchronization worked)");
        }
    } else {
        error!("❌ FAILURE: Output wire labels do not match!");
        error!("🔐 Garbler label0: {:?}", garbler_output.label0);
        error!("🔐 Garbler label1: {:?}", garbler_output.label1);
        error!("🔍 Evaluator active: {:?}", evaluator_output.active_label);
    }

    info!("🏁 Groth16 Garble-to-Evaluate Pipeline completed!");
}
