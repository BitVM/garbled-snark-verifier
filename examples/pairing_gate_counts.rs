// examples/pairing_gate_counts.rs
// Stream and print gate counts per operation as each completes (CSV rows).
// This avoids buffering results and prints ASAP for long runs.

use std::{io::Write, thread};

use ark::{CurveGroup, Field, PrimeGroup, SWCurveConfig};
use garbled_snark_verifier as gsv;
use garbled_snark_verifier::{
    WireId, ark,
    circuit::streaming::{
        CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, StreamingResult, WiresObject,
        modes::Execute,
    },
};
use gsv::gadgets::bn254::{
    fq::Fq, fq2::Fq2, fq12::Fq12, g1::G1Projective, g2::G2Projective, pairing,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

fn fq12_one_const() -> Fq12 {
    Fq12::new_constant(ark::Fq12::ONE)
}

#[derive(Clone)]
struct Inputs {
    g1: ark::G1Projective,
    g2: ark::G2Projective,
    g2_aff: ark::G2Affine,
}

#[derive(Clone)]
struct Wires {
    g1: G1Projective,
    g2: G2Projective,
}

impl CircuitInput for Inputs {
    type WireRepr = Wires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Wires {
            g1: G1Projective::new(&mut issue),
            g2: G2Projective::new(&mut issue),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.g1
            .to_wires_vec()
            .into_iter()
            .chain(repr.g2.to_wires_vec())
            .collect()
    }
}

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Inputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        let g1_m = G1Projective::as_montgomery(self.g1);
        let g2_m = G2Projective::as_montgomery(self.g2);
        let f1 = G1Projective::get_wire_bits_fn(&repr.g1, &g1_m).unwrap();
        let f2 = G2Projective::get_wire_bits_fn(&repr.g2, &g2_m).unwrap();
        for &w in repr.g1.to_wires_vec().iter() {
            if let Some(bit) = f1(w) {
                cache.feed_wire(w, bit);
            }
        }
        for &w in repr.g2.to_wires_vec().iter() {
            if let Some(bit) = f2(w) {
                cache.feed_wire(w, bit);
            }
        }
    }
}

fn run_and_print<F>(name: &str, inputs: Inputs, build: F)
where
    F: Fn(&mut Execute, &Wires) -> Vec<WireId> + Send + 'static,
{
    let result: StreamingResult<_, _, Vec<bool>> =
        CircuitBuilder::streaming_execute(inputs, 20_000, |ctx, w| {
            let wires: Vec<WireId> = build(ctx, w);
            wires
        });
    println!("{},{}", name, result.gate_count.total_gate_count());
    let _ = std::io::stdout().flush();
}

fn main() {
    if !garbled_snark_verifier::hardware_aes_available() {
        eprintln!(
            "Warning: AES hardware acceleration not detected; using software AES (not constant-time)."
        );
    }
    // Configuration: enable/disable specific tests
    const ENABLE_FQ_MUL_MONTGOMERY: bool = true;
    const ENABLE_FQ2_MUL_CONSTANT_BY_FQ_MONTGOMERY: bool = true;
    const ENABLE_FQ_MUL_CONSTANT_MONTGOMERY: bool = true;
    const ENABLE_DOUBLE_IN_PLACE_MONTGOMERY: bool = true;
    const ENABLE_ADD_IN_PLACE_MONTGOMERY: bool = true;
    const ENABLE_MUL_BY_CHAR_MONTGOMERY: bool = true;
    const ENABLE_ELL_MONTGOMERY: bool = true;
    const ENABLE_ELL_BY_CONSTANT_MONTGOMERY: bool = true;
    const ENABLE_ELL_COEFFS_EVALUATE_MONTGOMERY_FAST: bool = true;
    const ENABLE_MILLER_LOOP_EVALUATE_MONTGOMERY_FAST: bool = true;
    const ENABLE_MILLER_LOOP: bool = true;
    const ENABLE_DESERIALIZED_COMPRESSED_G1: bool = true;
    const ENABLE_DESERIALIZED_COMPRESSED_G2: bool = true;
    const ENABLE_MULTI_MILLER_LOOP: bool = true;
    const ENABLE_MULTI_MILLER_LOOP_EVALUATE_MONTGOMERY_FAST: bool = true;

    // Deterministic inputs - use affine points with z=1 for fair comparison
    let _rng = ChaCha20Rng::seed_from_u64(42);
    let g1_proj = ark::G1Projective::generator() * ark::Fr::from(5u64);
    let g2_proj = ark::G2Projective::generator() * ark::Fr::from(7u64);
    // Convert to affine then back to projective with z=1
    let g1_aff = g1_proj.into_affine();
    let g2_aff = g2_proj.into_affine();
    let g1 = ark::G1Projective::from(g1_aff);
    let g2 = ark::G2Projective::from(g2_aff);
    let inputs = Inputs { g1, g2, g2_aff };

    // Print CSV header once
    println!("test_name,total_gates");
    let _ = std::io::stdout().flush();

    // Only compute Fq::mul_montgomery gate count if enabled
    if ENABLE_FQ_MUL_MONTGOMERY {
        run_and_print("fq_mul_montgomery", inputs.clone(), move |ctx, _w| {
            let a = Fq::new_constant(&Fq::as_montgomery(ark::Fq::from(u32::MAX))).unwrap();
            let b = Fq::new_constant(&Fq::as_montgomery(ark::Fq::from(u64::MAX))).unwrap();
            let c = Fq::mul_montgomery(ctx, &a, &b);
            c.to_wires_vec()
        });
    }

    // Spawn each calculation in its own thread for parallelism
    let mut handles = Vec::new();

    // 1) double_in_place_montgomery
    // 0) fq2::mul_constant_by_fq_montgomery (only enabled target)
    if ENABLE_FQ2_MUL_CONSTANT_BY_FQ_MONTGOMERY {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print("mul_constant_by_fq_montgomery", inputs, move |ctx, w| {
                    // Constant Fq2 (canonical form, converted internally to Montgomery)
                    let a_const = ark_bn254::Fq2::new(
                        ark_bn254::Fq::from(123u64),
                        ark_bn254::Fq::from(456u64),
                    );
                    // Use an Fq wire from G1.x as the multiplier input
                    let _out = Fq2::mul_constant_by_fq_montgomery(ctx, &a_const, &w.g1.x);
                    vec![]
                });
            }
        }));
    }

    if ENABLE_FQ_MUL_CONSTANT_MONTGOMERY {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print("fq_mul_by_constant_montgomery", inputs, move |ctx, w| {
                    let c_m = Fq::as_montgomery(ark::Fq::from(123u64));
                    let _out = Fq::mul_by_constant_montgomery(ctx, &w.g1.x, &c_m);
                    vec![]
                });
            }
        }));
    }

    // 1) double_in_place_montgomery
    if ENABLE_DOUBLE_IN_PLACE_MONTGOMERY {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print("test_double_in_place_montgomery", inputs, move |ctx, w| {
                    let (_r_next, _coeffs) =
                        pairing::double_in_place_circuit_montgomery(ctx, &w.g2);
                    vec![]
                });
            }
        }));
    }

    // 2) add_in_place_montgomery
    if ENABLE_ADD_IN_PLACE_MONTGOMERY {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print("test_add_in_place_montgomery", inputs, move |ctx, w| {
                    let (_r_next, _coeffs) = pairing::add_in_place_montgomery(ctx, &w.g2, &w.g2);
                    vec![]
                });
            }
        }));
    }

    // 3) mul_by_char_montgomery
    if ENABLE_MUL_BY_CHAR_MONTGOMERY {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print("test_mul_by_char_montgomery", inputs, move |ctx, w| {
                    let _q1 = pairing::mul_by_char_montgomery(ctx, &w.g2);
                    vec![]
                });
            }
        }));
    }

    // 4) ell_montgomery: variable coeffs + eval at P
    if ENABLE_ELL_MONTGOMERY {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print("test_ell_montgomery", inputs, move |ctx, w| {
                    let f0 = fq12_one_const();
                    let coeffs = pairing::ell_coeffs_montgomery(ctx, &w.g2);
                    // Take first coeff triple and evaluate once
                    let c = coeffs.into_iter().next().unwrap();
                    let _f1 = pairing::ell_montgomery(ctx, &f0, &c, &w.g1);
                    vec![]
                });
            }
        }));
    }

    // 5) ell_by_constant_montgomery (const Q coeffs)
    if ENABLE_ELL_BY_CONSTANT_MONTGOMERY {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print(
                    "test_ell_by_constant_montgomery",
                    inputs.clone(),
                    move |ctx, w| {
                        let f0 = fq12_one_const();
                        let coeffs = pairing::ell_coeffs(inputs.g2_aff);
                        let c = coeffs.into_iter().next().unwrap();
                        let _f1 = pairing::ell_eval_const(ctx, &f0, &c, &w.g1);
                        vec![]
                    },
                );
            }
        }));
    }

    // 6) ell_coeffs_evaluate_montgomery_fast equivalent: build coeffs for variable Q
    if ENABLE_ELL_COEFFS_EVALUATE_MONTGOMERY_FAST {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print(
                    "test_ell_coeffs_evaluate_montgomery_fast",
                    inputs,
                    move |ctx, w| {
                        let _coeffs = pairing::ell_coeffs_montgomery(ctx, &w.g2);
                        vec![]
                    },
                );
            }
        }));
    }

    // 6b) miller loops
    if ENABLE_MILLER_LOOP_EVALUATE_MONTGOMERY_FAST {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print(
                    "test_miller_loop_evaluate_montgomery_fast",
                    inputs,
                    move |ctx, w| {
                        let _f = pairing::miller_loop_montgomery_fast(ctx, &w.g1, &w.g2);
                        vec![]
                    },
                );
            }
        }));
    }

    if ENABLE_MILLER_LOOP {
        handles.push(thread::spawn({
            let inputs_for_arg = inputs.clone();
            let inputs_for_capture = inputs.clone();
            move || {
                run_and_print("test_miller_loop", inputs_for_arg, move |ctx, w| {
                    let _f = pairing::miller_loop_const_q(ctx, &w.g1, &inputs_for_capture.g2_aff);
                    vec![]
                });
            }
        }));
    }

    // 7) deserialize_compressed_g1: y = sqrt(x^3 + b); sign by flag (TRUE)
    if ENABLE_DESERIALIZED_COMPRESSED_G1 {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print("test_deserialized_compressed_g1", inputs, move |ctx, w| {
                    let x = &w.g1.x;
                    let x2 = Fq::square_montgomery(ctx, x);
                    let x3 = Fq::mul_montgomery(ctx, &x2, x);
                    let y2 = Fq::add(
                        ctx,
                        &x3,
                        &Fq::new_constant(&Fq::as_montgomery(ark::g1::Config::COEFF_B)).unwrap(),
                    );
                    let y = Fq::sqrt_montgomery(ctx, &y2);
                    let neg_y = Fq::neg(ctx, &y);
                    let y_sel = gsv::gadgets::bigint::select(
                        ctx,
                        &y,
                        &neg_y,
                        gsv::circuit::streaming::TRUE_WIRE,
                    );
                    let mut out = x.clone().to_wires_vec();
                    out.extend(y_sel.to_wires_vec());
                    out
                });
            }
        }));
    }

    // 8) deserialize_compressed_g2: y = sqrt(x^3 + b) over Fq2; sign by flag (TRUE)
    if ENABLE_DESERIALIZED_COMPRESSED_G2 {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print("test_deserialized_compressed_g2", inputs, move |ctx, w| {
                    let x = &w.g2.x;
                    let x2 = Fq2::square_montgomery(ctx, x);
                    let x3 = Fq2::mul_montgomery(ctx, &x2, x);
                    let b = Fq2::as_montgomery(ark::g2::Config::COEFF_B);
                    let y2 = Fq2::add_constant(ctx, &x3, &b);
                    let y = Fq2::sqrt_general_montgomery(ctx, &y2);
                    let neg_y = Fq2::neg(ctx, y.clone());
                    let y0 = gsv::gadgets::bigint::select(
                        ctx,
                        y.c0(),
                        neg_y.c0(),
                        gsv::circuit::streaming::TRUE_WIRE,
                    );
                    let y1 = gsv::gadgets::bigint::select(
                        ctx,
                        y.c1(),
                        neg_y.c1(),
                        gsv::circuit::streaming::TRUE_WIRE,
                    );
                    let mut out = x.clone().to_wires_vec();
                    out.extend(y0.to_wires_vec());
                    out.extend(y1.to_wires_vec());
                    out
                });
            }
        }));
    }

    // 9) multi_miller_loop_const_q
    if ENABLE_MULTI_MILLER_LOOP {
        handles.push(thread::spawn({
            let inputs_for_arg = inputs.clone();
            let inputs_for_capture = inputs.clone();
            move || {
                run_and_print("test_multi_miller_loop", inputs_for_arg, move |ctx, w| {
                    let ps = vec![w.g1.clone()];
                    let qs = vec![inputs_for_capture.g2_aff];
                    let _f = pairing::multi_miller_loop_const_q(ctx, &ps, &qs);
                    vec![]
                });
            }
        }));
    }

    // 10) multi_miller_loop_montgomery_fast
    if ENABLE_MULTI_MILLER_LOOP_EVALUATE_MONTGOMERY_FAST {
        handles.push(thread::spawn({
            let inputs = inputs.clone();
            move || {
                run_and_print(
                    "test_multi_miller_loop_evaluate_montgomery_fast",
                    inputs,
                    move |ctx, w| {
                        let ps = vec![w.g1.clone()];
                        let qs = vec![w.g2.clone()];
                        let _f = pairing::multi_miller_loop_montgomery_fast(ctx, &ps, &qs);
                        vec![]
                    },
                );
            }
        }));
    }

    // Wait for all threads to finish
    for h in handles {
        let _ = h.join();
    }
}
