//! BN254 pairing helpers (constant-Q)
//!
//! - Off-circuit: precompute G2 line coefficients for the ATE/Miller loop.
//! - On-circuit: evaluate lines against variable G1 inputs and compose
//!   Miller loop + final exponentiation for a full pairing result.
//!
//! Note: These helpers assume G2 inputs are constants (host-provided arkworks
//! `G2Affine`), while G1 inputs are circuit wires (`G1Projective`).

/// Line coefficient used during Miller loop line evaluations, packed as Fq6
/// with components (c0, c1, c2) where each is an Fq2.
/// Matches arkworks' BN254 representation/order.
pub type EllCoeff = ark_bn254::Fq6;

use std::iter;

use ark_ec::{bn::BnConfig, short_weierstrass::SWCurveConfig};
use ark_ff::{AdditiveGroup, Field};
use circuit_component_macro::component;

use crate::{
    CircuitContext, Fp254Impl,
    circuit::{FromWires, OffCircuitParam, WiresArity, WiresObject},
    gadgets::bn254::{
        final_exponentiation::final_exponentiation_montgomery, fq::Fq, fq2::Fq2, fq6::Fq6,
        fq12::Fq12, g1::G1Projective, g2::G2Projective,
    },
};

pub fn double_in_place(r: &mut ark_bn254::G2Projective) -> ark_bn254::Fq6 {
    let half = ark_bn254::Fq::from(Fq::half_modulus());
    let mut a = r.x * r.y;
    a.mul_assign_by_fp(&half);
    let b = r.y.square();
    let c = r.z.square();
    let e = ark_bn254::g2::Config::COEFF_B * (c.double() + c);
    let f = e.double() + e;
    let mut g = b + f;
    g.mul_assign_by_fp(&half);
    let h = (r.y + r.z).square() - (b + c);
    let i = e - b;
    let j = r.x.square();
    let e_square = e.square();

    let new_r = ark_bn254::G2Projective {
        x: a * (b - f),
        y: g.square() - (e_square.double() + e_square),
        z: b * h,
    };
    *r = new_r;
    ark_bn254::Fq6::new(-h, j.double() + j, i)
}

pub fn add_in_place(r: &mut ark_bn254::G2Projective, q: &ark_bn254::G2Affine) -> ark_bn254::Fq6 {
    let theta = r.y - (q.y * r.z);
    let lambda = r.x - (q.x * r.z);
    let c = theta.square();
    let d = lambda.square();
    let e = lambda * d;
    let f = r.z * c;
    let g = r.x * d;
    let h = e + f - g.double();
    let j = theta * q.x - (lambda * q.y);

    let new_r = ark_bn254::G2Projective {
        x: lambda * h,
        y: theta * (g - h) - (e * r.y),
        z: r.z * e,
    };
    *r = new_r;

    ark_bn254::Fq6::new(lambda, -theta, j)
}

pub fn mul_by_char(r: ark_bn254::G2Affine) -> ark_bn254::G2Affine {
    let mut s = r;
    s.x = s.x.frobenius_map(1);
    s.x *= &ark_bn254::Config::TWIST_MUL_BY_Q_X;
    s.y = s.y.frobenius_map(1);
    s.y *= &ark_bn254::Config::TWIST_MUL_BY_Q_Y;
    s
}

/// Compute BN254 G2 line coefficients for the ATE loop given a constant `Q`.
///
/// This is an off-circuit helper intended to be used alongside circuit
/// gadgets that evaluate the lines against variable G1 points.
pub fn ell_coeffs(q: ark_bn254::G2Affine) -> Vec<EllCoeff> {
    let mut ellc = Vec::new();
    let mut r = ark_bn254::G2Projective {
        x: q.x,
        y: q.y,
        z: ark_bn254::Fq2::ONE,
    };
    let neg_q = -q;
    for bit in ark_bn254::Config::ATE_LOOP_COUNT.iter().rev().skip(1) {
        {
            let c = double_in_place(&mut r);
            ellc.push(c);
        }

        match bit {
            1 => {
                let c = add_in_place(&mut r, &q);
                ellc.push(c);
            }
            -1 => {
                let c = add_in_place(&mut r, &neg_q);
                ellc.push(c);
            }
            _ => {}
        }
    }
    let q1 = mul_by_char(q);
    let mut q2 = mul_by_char(q1);
    q2.y = -q2.y;
    {
        let c = add_in_place(&mut r, &q1);
        ellc.push(c);
    }
    {
        let c = add_in_place(&mut r, &q2);
        ellc.push(c);
    }
    ellc
}

/// Evaluate a BN254 line (with constant G2 coefficients) at a variable G1 point and
/// multiply into `f` in Montgomery form.
///
/// Given coefficients `(c0, c1, c2)` for a single Miller step and a G1 point `p`,
/// this computes `f * (c0 * p.y + c1 * p.x * w^3 + c2 * w^4)` using the specialized
/// sparse Fq12 multiplication path with indices 0,3,4.
pub fn ell_eval_const<C: CircuitContext>(
    circuit: &mut C,
    f: &Fq12,
    coeffs: &EllCoeff,
    p: &G1Projective,
) -> Fq12 {
    // c0' = coeffs.0 * p.y (in Fq2) as wires
    let c0_fq2 = Fq2::mul_constant_by_fq_montgomery(circuit, &coeffs.c0, &p.y);
    // c1' = coeffs.1 * p.x (in Fq2) as wires
    let c3_fq2 = Fq2::mul_constant_by_fq_montgomery(circuit, &coeffs.c1, &p.x);
    // c2 is a constant (Fq2); for mul_by_constant_montgomery/add_constant paths
    // we pass it in Montgomery form to match other Montgomery-form wires.
    let c4_const = Fq2::as_montgomery(coeffs.c2);

    Fq12::mul_by_034_constant4_montgomery(circuit, f, &c0_fq2, &c3_fq2, &c4_const)
}

/// Evaluate a BN254 line with variable G2 coefficients at an affine G1 point and
/// multiply into `f` in Montgomery form (variable-`Q` path).
///
/// Mirrors the logic of collector-2's `ell_circuit_montgomery`/`ell_evaluate_montgomery`:
/// - c0' = c0 * P.y (in Fq2)
/// - c3' = c1 * P.x (in Fq2)
/// - return f * (c0' + c3' * w^3 + c2 * w^4) via sparse mul_by_034.
///
/// Precondition: `p` should be affine (`z = 1`); use `g1_normalize_to_affine` beforehand.
pub fn ell_montgomery<C: CircuitContext>(
    circuit: &mut C,
    f: &Fq12,
    coeffs: &Fq6,
    p: &G1Projective,
) -> Fq12 {
    // Multiply first two coeffs by P's affine coordinates (Fq) inside Fq2
    let c0_fq2 = Fq2::mul_by_fq_montgomery(circuit, coeffs.c0(), &p.y);
    let c3_fq2 = Fq2::mul_by_fq_montgomery(circuit, coeffs.c1(), &p.x);
    // Full variable sparse multiplication (034 indices)
    Fq12::mul_by_034_montgomery(circuit, f, &c0_fq2, &c3_fq2, coeffs.c2())
}

fn g1_normalize_to_affine<C: CircuitContext>(circuit: &mut C, p: &G1Projective) -> G1Projective {
    // Convert projective (x, y, z) to affine (x/z^2, y/z^3, 1)
    let inv_z = Fq::inverse_montgomery(circuit, &p.z);
    let inv_z2 = Fq::square_montgomery(circuit, &inv_z);
    let inv_z3 = Fq::mul_montgomery(circuit, &inv_z2, &inv_z);

    let x = Fq::mul_montgomery(circuit, &p.x, &inv_z2);
    let y = Fq::mul_montgomery(circuit, &p.y, &inv_z3);
    let one_m = Fq::as_montgomery(ark_bn254::Fq::ONE);
    let z = Fq::new_constant(&one_m).expect("const one mont");

    G1Projective { x, y, z }
}

/// Normalize a G2 projective point to affine (z = 1) in Montgomery domain.
fn g2_normalize_to_affine<C: CircuitContext>(circuit: &mut C, q: &G2Projective) -> G2Projective {
    // Convert projective (x, y, z) to affine (x/z^2, y/z^3, 1)
    let inv_z = Fq2::inverse_montgomery(circuit, &q.z);
    let inv_z2 = Fq2::square_montgomery(circuit, &inv_z);
    let inv_z3 = Fq2::mul_montgomery(circuit, &inv_z2, &inv_z);

    let x = Fq2::mul_montgomery(circuit, &q.x, &inv_z2);
    let y = Fq2::mul_montgomery(circuit, &q.y, &inv_z3);
    let one_c0 = Fq::new_constant(&Fq::as_montgomery(ark_bn254::Fq::ONE)).expect("const one");
    let zero_c1 = Fq::new_constant(&Fq::as_montgomery(ark_bn254::Fq::ZERO)).expect("const zero");
    let z = Fq2::from_components(one_c0, zero_c1);

    G2Projective { x, y, z }
}

/// Apply Frobenius map to an affine G2 point: x' = (x^p) * c_x[i], y' = (y^p) * c_y[i], z = 1.
/// Precondition: q.z encodes Montgomery ONE (affine form).
#[allow(dead_code)]
fn g2_frobenius_map_affine<C: CircuitContext>(
    circuit: &mut C,
    q: &G2Projective,
    i: usize,
) -> G2Projective {
    // Reduce to cases used by BN254 Miller loop: i in {0,1,2}
    let k = i % 3;

    let one_c0 = Fq::new_constant(&Fq::as_montgomery(ark_bn254::Fq::ONE)).expect("const one");
    let zero_c1 = Fq::new_constant(&Fq::as_montgomery(ark_bn254::Fq::ZERO)).expect("const zero");
    let z_one = Fq2::from_components(one_c0, zero_c1);

    match k {
        0 => G2Projective {
            x: q.x.clone(),
            y: q.y.clone(),
            z: z_one,
        },
        1 => {
            let x_f1 = Fq2::frobenius_montgomery(circuit, &q.x, 1);
            let y_f1 = Fq2::frobenius_montgomery(circuit, &q.y, 1);
            let cx = ark_bn254::Config::TWIST_MUL_BY_Q_X;
            let cy = ark_bn254::Config::TWIST_MUL_BY_Q_Y;
            // Constants must be in Montgomery form for mul_by_constant_montgomery
            let x_new = Fq2::mul_by_constant_montgomery(circuit, &x_f1, &Fq2::as_montgomery(cx));
            let y_new = Fq2::mul_by_constant_montgomery(circuit, &y_f1, &Fq2::as_montgomery(cy));
            G2Projective {
                x: x_new,
                y: y_new,
                z: z_one,
            }
        }
        _ => {
            let x_f1 = Fq2::frobenius_montgomery(circuit, &q.x, 1);
            let y_f1 = Fq2::frobenius_montgomery(circuit, &q.y, 1);
            let cx = ark_bn254::Config::TWIST_MUL_BY_Q_X;
            let cy = ark_bn254::Config::TWIST_MUL_BY_Q_Y;
            let x1 = Fq2::mul_by_constant_montgomery(circuit, &x_f1, &Fq2::as_montgomery(cx));
            let y1 = Fq2::mul_by_constant_montgomery(circuit, &y_f1, &Fq2::as_montgomery(cy));

            let x_f2 = Fq2::frobenius_montgomery(circuit, &x1, 1);
            let y_f2 = Fq2::frobenius_montgomery(circuit, &y1, 1);
            let x2 = Fq2::mul_by_constant_montgomery(circuit, &x_f2, &Fq2::as_montgomery(cx));
            let mut y2 = Fq2::mul_by_constant_montgomery(circuit, &y_f2, &Fq2::as_montgomery(cy));
            y2 = Fq2::neg(circuit, y2);
            G2Projective {
                x: x2,
                y: y2,
                z: z_one,
            }
        }
    }
}

/// Compute tangent line coefficients at R (variable-`Q` path) and advance R <- 2R.
///
/// Returns (R_next_affine, (c0, c1, c2)) where the line is represented as
/// c0 * Y + c1 * X + c2 = 0 over Fq2, matching arkworks' BN254 prepared
/// ordering (ell_0, ell_vw, ell_vv). Later evaluation multiplies c0 by P.y
/// and c1 by P.x and uses a sparse Fq12 mul-by-034.
#[allow(dead_code)]
fn g2_line_coeffs_double<C: CircuitContext>(
    circuit: &mut C,
    r: &G2Projective,
) -> (G2Projective, Fq6) {
    // Normalize R to affine for simple slope/division formulas (a = 0 curve)
    let r_aff = g2_normalize_to_affine(circuit, r);
    let x = r_aff.x.clone();
    let y = r_aff.y.clone();

    // λ = (3*x^2) / (2*y)
    let x2 = Fq2::square_montgomery(circuit, &x);
    let three_x2 = Fq2::triple(circuit, &x2);
    let two_y = Fq2::double(circuit, &y);
    let inv_two_y = Fq2::inverse_montgomery(circuit, &two_y);
    let lambda = Fq2::mul_montgomery(circuit, &three_x2, &inv_two_y);

    // Line: Y - λ X - (y - λ x) = 0 ->
    // c0 = 1, c1 = -λ, c2 = λ*x - y
    let one_c0 = Fq::new_constant(&Fq::as_montgomery(ark_bn254::Fq::ONE)).expect("const one");
    let zero_c1 = Fq::new_constant(&Fq::as_montgomery(ark_bn254::Fq::ZERO)).expect("const zero");
    let c0 = Fq2::from_components(one_c0, zero_c1);
    let c1 = Fq2::neg(circuit, lambda.clone());
    let lambda_x = Fq2::mul_montgomery(circuit, &lambda, &x);
    let c2 = Fq2::sub(circuit, &lambda_x, &y);

    // Advance R <- 2R and normalize to affine for the caller
    let r_next = crate::gadgets::bn254::g2::G2Projective::double_montgomery(circuit, r);
    let r_next_aff = g2_normalize_to_affine(circuit, &r_next);

    (r_next_aff, Fq6::from_components(c0, c1, c2))
}

/// Compute secant line coefficients through R and Q (variable-`Q` path) and advance R <- R + Q.
///
/// Returns (R_next_affine, (c0, c1, c2)) in the same representation order
/// as `g2_line_coeffs_double`.
#[allow(dead_code)]
fn g2_line_coeffs_add<C: CircuitContext>(
    circuit: &mut C,
    r: &G2Projective,
    q: &G2Projective,
) -> (G2Projective, Fq6) {
    // Normalize to affine to compute λ = (y_q - y_r) / (x_q - x_r)
    let r_aff = g2_normalize_to_affine(circuit, r);
    let q_aff = g2_normalize_to_affine(circuit, q);
    let xr = r_aff.x.clone();
    let yr = r_aff.y.clone();
    let xq = q_aff.x.clone();
    let yq = q_aff.y.clone();

    let dy = Fq2::sub(circuit, &yq, &yr);
    let dx = Fq2::sub(circuit, &xq, &xr);
    let inv_dx = Fq2::inverse_montgomery(circuit, &dx);
    let lambda = Fq2::mul_montgomery(circuit, &dy, &inv_dx);

    // Line through R and Q: Y - λ X - (y_r - λ x_r) = 0
    let one_c0 = Fq::new_constant(&Fq::as_montgomery(ark_bn254::Fq::ONE)).expect("const one");
    let zero_c1 = Fq::new_constant(&Fq::as_montgomery(ark_bn254::Fq::ZERO)).expect("const zero");
    let c0 = Fq2::from_components(one_c0, zero_c1);
    let c1 = Fq2::neg(circuit, lambda.clone());
    let lambda_xr = Fq2::mul_montgomery(circuit, &lambda, &xr);
    let c2 = Fq2::sub(circuit, &lambda_xr, &yr);

    // Advance R <- R + Q and normalize to affine for the caller
    let r_next = crate::gadgets::bn254::g2::G2Projective::add_montgomery(circuit, r, q);
    let r_next_aff = g2_normalize_to_affine(circuit, &r_next);

    (r_next_aff, Fq6::from_components(c0, c1, c2))
}

impl FromWires for (G2Projective, Fq6) {
    fn from_wires(wires: &[crate::WireId]) -> Option<Self> {
        let (g2, fq6) = wires.split_at(G2Projective::ARITY);

        Some((G2Projective::from_wires(g2)?, Fq6::from_wires(fq6)?))
    }
}

impl WiresArity for (G2Projective, Fq6) {
    const ARITY: usize = G2Projective::ARITY + Fq6::ARITY;
}

/// Mixed-add (Jacobian + affine) update R <- R + Q with line coeffs, all in Montgomery form.
///
/// Implements the same internal sequence as the collector-2 mixed-add in-place algorithm:
/// - theta = ry - qy * rz
/// - lambda = rx - qx * rz
/// - h = (lambda^3 + rz * theta^2) - 2 * rx * lambda^2
/// - R' = (lambda * h, theta * (rx * lambda^2 - h) - lambda^3 * ry, rz * lambda^3)
/// - line coeffs scaled to avoid divisions: (c0, c1, c2) = (lambda, -theta, theta*qx - lambda*qy)
///
/// Returns (R_next_projective, (c0, c1, c2)). Precondition: `q` is affine (z = 1 in Montgomery).
#[component]
pub fn double_in_place_circuit_montgomery<C: CircuitContext>(
    circuit: &mut C,
    r: &G2Projective,
) -> (G2Projective, Fq6) {
    let rx = &r.x;
    let ry = &r.y;
    let rz = &r.z;

    let mut a = Fq2::mul_montgomery(circuit, rx, ry);

    a = Fq2::half(circuit, &a);

    let b = Fq2::square_montgomery(circuit, ry);
    let c = Fq2::square_montgomery(circuit, rz);
    let c_triple = Fq2::triple(circuit, &c);
    let e = Fq2::mul_by_constant_montgomery(
        circuit,
        &c_triple,
        &Fq2::as_montgomery(ark_bn254::g2::Config::COEFF_B),
    );
    let f = Fq2::triple(circuit, &e);
    let mut g = Fq2::add(circuit, &b, &f);
    g = Fq2::half(circuit, &g);
    let ryrz = Fq2::add(circuit, ry, rz);
    let ryrzs = Fq2::square_montgomery(circuit, &ryrz);
    let bc = Fq2::add(circuit, &b, &c);
    let h = Fq2::sub(circuit, &ryrzs, &bc);
    let i = Fq2::sub(circuit, &e, &b);
    let j = Fq2::square_montgomery(circuit, rx);
    let es = Fq2::square_montgomery(circuit, &e);
    let j_triple = Fq2::triple(circuit, &j);
    let bf = Fq2::sub(circuit, &b, &f);
    let new_x = Fq2::mul_montgomery(circuit, &a, &bf);
    let es_triple = Fq2::triple(circuit, &es);
    let gs = Fq2::square_montgomery(circuit, &g);
    let new_y = Fq2::sub(circuit, &gs, &es_triple);
    let new_z = Fq2::mul_montgomery(circuit, &b, &h);
    let hn = Fq2::neg(circuit, h);

    (
        G2Projective {
            x: new_x,
            y: new_y,
            z: new_z,
        },
        Fq6::from_components(hn, j_triple, i),
    )
}

#[component]
pub fn add_in_place_montgomery(
    circuit: &mut impl CircuitContext,
    r: &G2Projective,
    q: &G2Projective,
) -> (G2Projective, Fq6) {
    let rx = &r.x;
    let ry = &r.y;
    let rz = &r.z;
    let qx = &q.x;
    let qy = &q.y;

    let wires_1 = Fq2::mul_montgomery(circuit, qy, rz);
    let theta = Fq2::sub(circuit, ry, &wires_1);

    let wires_2 = Fq2::mul_montgomery(circuit, qx, rz);
    let lambda = Fq2::sub(circuit, rx, &wires_2);

    let c = Fq2::square_montgomery(circuit, &theta);
    let d = Fq2::square_montgomery(circuit, &lambda);

    let e = Fq2::mul_montgomery(circuit, &lambda, &d);

    let f = Fq2::mul_montgomery(circuit, rz, &c);

    let g = Fq2::mul_montgomery(circuit, rx, &d);

    let wires_3 = Fq2::add(circuit, &e, &f);

    let wires_4 = Fq2::double(circuit, &g);
    let h = Fq2::sub(circuit, &wires_3, &wires_4);

    let neg_theta = Fq2::neg(circuit, theta.clone());

    let wires_5 = Fq2::mul_montgomery(circuit, &theta, qx);
    let wires_6 = Fq2::mul_montgomery(circuit, &lambda, qy);
    let j = Fq2::sub(circuit, &wires_5, &wires_6);

    let new_r_x = Fq2::mul_montgomery(circuit, &lambda, &h);

    let wires_7 = Fq2::sub(circuit, &g, &h);
    let wires_8 = Fq2::mul_montgomery(circuit, &theta, &wires_7);
    let wires_9 = Fq2::mul_montgomery(circuit, &e, ry);

    let new_r_y = Fq2::sub(circuit, &wires_8, &wires_9);
    let new_r_z = Fq2::mul_montgomery(circuit, rz, &e);

    (
        G2Projective {
            x: new_r_x,
            y: new_r_y,
            z: new_r_z,
        },
        Fq6::from_components(lambda, neg_theta, j),
    )
}

pub fn g2_affine_neg_evaluate<C: CircuitContext>(
    circuit: &mut C,
    q: &G2Projective,
) -> G2Projective {
    let mut result = q.clone();
    result.y = Fq2::neg(circuit, q.y.clone());
    result
}

#[component]
pub fn mul_by_char_montgomery(circuit: &mut impl CircuitContext, r: &G2Projective) -> G2Projective {
    let r_x = &r.x;
    let r_y = &r.y;

    let mut s_x = Fq2::frobenius_montgomery(circuit, r_x, 1);
    s_x = Fq2::mul_by_constant_montgomery(
        circuit,
        &s_x,
        &Fq2::as_montgomery(ark_bn254::Config::TWIST_MUL_BY_Q_X),
    );

    let mut s_y = Fq2::frobenius_montgomery(circuit, r_y, 1);
    s_y = Fq2::mul_by_constant_montgomery(
        circuit,
        &s_y,
        &Fq2::as_montgomery(ark_bn254::Config::TWIST_MUL_BY_Q_Y),
    );

    G2Projective {
        x: s_x,
        y: s_y,
        z: r.z.clone(),
    }
}

/// Precompute BN254 line coefficients for the ATE/Miller loop with a variable `Q` (G2 wires).
///
/// Returns the sequence of line coefficient triples (c0, c1, c2) in Montgomery form, matching
/// the order used by arkworks' BN254 prepared coefficients (ell_0, ell_vw, ell_vv). The sequence
/// contains one triple per doubling step and, conditionally, one per addition step depending on
/// the signed bits of `ATE_LOOP_COUNT`, followed by two final frobenius-based additions.
pub fn ell_coeffs_montgomery<C: CircuitContext>(circuit: &mut C, q: &G2Projective) -> Vec<Fq6> {
    let neg_q = g2_affine_neg_evaluate(circuit, q);

    let mut ellc: Vec<Fq6> = vec![];
    let mut r = q.clone();
    for bit in ark_bn254::Config::ATE_LOOP_COUNT.iter().rev().skip(1) {
        let (new_r, coeffs) = double_in_place_circuit_montgomery(circuit, &r);
        ellc.push(coeffs);
        r = new_r;

        match bit {
            1 => {
                let (new_r, coeffs) = add_in_place_montgomery(circuit, &r, q);
                ellc.push(coeffs);
                r = new_r;
            }
            -1 => {
                let (new_r, coeffs) = add_in_place_montgomery(circuit, &r, &neg_q);
                ellc.push(coeffs);
                r = new_r;
            }
            _ => {}
        }
    }

    let q1 = mul_by_char_montgomery(circuit, q);
    let mut q2 = mul_by_char_montgomery(circuit, &q1);
    let new_q2 = g2_affine_neg_evaluate(circuit, &q2);
    q2 = new_q2;

    let (new_r, coeffs) = add_in_place_montgomery(circuit, &r, &q1);
    ellc.push(coeffs);
    r = new_r;

    let (_new_r, coeffs) = add_in_place_montgomery(circuit, &r, &q2);
    ellc.push(coeffs);

    ellc
}

/// Miller loop where P is already affine (z = 1), so no normalization needed.
/// Precondition: `p.z` encodes the Montgomery ONE constant.
#[component(offcircuit_args = "q")]
pub fn miller_loop_const_q_affine<C: CircuitContext>(
    circuit: &mut C,
    p: &G1Projective,
    q: &ark_bn254::G2Affine,
) -> Fq12 {
    let coeffs = ell_coeffs(*q);
    let mut coeff_iter = coeffs.iter();

    let mut f = new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            f = Fq12::square_montgomery(circuit, &f);
        }

        let c = coeff_iter.next().expect("coeff present");
        f = ell_eval_const(circuit, &f, c, p);

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let c2 = coeff_iter.next().expect("coeff present");
            f = ell_eval_const(circuit, &f, c2, p);
        }
    }

    // Final two steps
    let c_last = coeff_iter.next().expect("coeff present");
    f = ell_eval_const(circuit, &f, c_last, p);
    let c_last2 = coeff_iter.next().expect("coeff present");
    f = ell_eval_const(circuit, &f, c_last2, p);

    f
}

/// Multi Miller loop where all P are already affine (z = 1).
#[component(offcircuit_args = "qs")]
pub fn multi_miller_loop_const_q_affine<C: CircuitContext>(
    circuit: &mut C,
    ps: &[G1Projective],
    qs: &[ark_bn254::G2Affine],
) -> Fq12 {
    assert_eq!(ps.len(), qs.len());
    let n = ps.len();
    if n == 0 {
        return new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);
    }

    let qells: Vec<Vec<EllCoeff>> = qs.iter().copied().map(ell_coeffs).collect();
    let steps = qells[0].len();
    let mut per_step: Vec<Vec<&EllCoeff>> = Vec::with_capacity(steps);
    for i in 0..steps {
        let mut v = Vec::with_capacity(n);
        for qell in &qells {
            v.push(&qell[i]);
        }
        per_step.push(v);
    }

    let mut f = new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);
    let mut per_step_iter = per_step.into_iter();

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            f = Fq12::square_montgomery(circuit, &f);
        }

        let coeffs_now = per_step_iter.next().expect("coeffs present");
        for (c, p) in coeffs_now.into_iter().zip(ps.iter()) {
            f = ell_eval_const(circuit, &f, c, p);
        }

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let coeffs_now = per_step_iter.next().expect("coeffs present");
            for (c, p) in coeffs_now.into_iter().zip(ps.iter()) {
                f = ell_eval_const(circuit, &f, c, p);
            }
        }
    }

    for _ in 0..2 {
        let coeffs_now = per_step_iter.next().expect("coeffs present");
        for (c, p) in coeffs_now.into_iter().zip(ps.iter()) {
            f = ell_eval_const(circuit, &f, c, p);
        }
    }

    f
}

pub fn multi_miller_loop_montgomery_fast<C: CircuitContext>(
    circuit: &mut C,
    ps: &[G1Projective],
    qs: &[G2Projective],
) -> Fq12 {
    // Skip normalization - assume inputs are already affine (z = 1)
    // - ell_coeffs_montgomery assumes mixed-add with affine Q (z = 1)
    // - ell_montgomery evaluates at affine P (z = 1)
    let ps_aff = ps.to_vec();
    let qs_aff = qs.to_vec();

    let mut qells = Vec::new();
    for q in &qs_aff {
        let qell = ell_coeffs_montgomery(circuit, q);
        qells.push(qell);
    }
    let mut u = Vec::new();
    for i in 0..qells[0].len() {
        let mut x = Vec::new();
        for qell in qells.iter() {
            x.push(qell[i].clone());
        }
        u.push(x);
    }
    let mut q_ells = u.iter();

    let mut f = new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            f = Fq12::square_montgomery(circuit, &f);
        }

        let qells_next = q_ells.next().unwrap().clone();
        for (qell_next, p) in iter::zip(qells_next, ps_aff.iter()) {
            f = ell_montgomery(circuit, &f, &qell_next, p);
        }

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let qells_next = q_ells.next().unwrap().clone();
            for (qell_next, p) in iter::zip(qells_next, ps_aff.iter()) {
                f = ell_montgomery(circuit, &f, &qell_next, p);
            }
        }
    }

    let qells_next = q_ells.next().unwrap().clone();
    for (qell_next, p) in iter::zip(qells_next, ps_aff.iter()) {
        f = ell_montgomery(circuit, &f, &qell_next, p);
    }

    let qells_next = q_ells.next().unwrap().clone();
    for (qell_next, p) in iter::zip(qells_next, ps_aff.iter()) {
        f = ell_montgomery(circuit, &f, &qell_next, p);
    }

    f
}

fn new_fq12_constant_montgomery(v: ark_bn254::Fq12) -> Fq12 {
    // Convert to Montgomery form before creating constants
    let v_mont = Fq12::as_montgomery(v);
    let c0 = v_mont.c0;
    let c1 = v_mont.c1;
    let c0_0 = Fq2::from_components(
        Fq::new_constant(&c0.c0.c0).unwrap(),
        Fq::new_constant(&c0.c0.c1).unwrap(),
    );
    let c0_1 = Fq2::from_components(
        Fq::new_constant(&c0.c1.c0).unwrap(),
        Fq::new_constant(&c0.c1.c1).unwrap(),
    );
    let c0_2 = Fq2::from_components(
        Fq::new_constant(&c0.c2.c0).unwrap(),
        Fq::new_constant(&c0.c2.c1).unwrap(),
    );
    let w0 = Fq6::from_components(c0_0, c0_1, c0_2);

    let c1_0 = Fq2::from_components(
        Fq::new_constant(&c1.c0.c0).unwrap(),
        Fq::new_constant(&c1.c0.c1).unwrap(),
    );
    let c1_1 = Fq2::from_components(
        Fq::new_constant(&c1.c1.c0).unwrap(),
        Fq::new_constant(&c1.c1.c1).unwrap(),
    );
    let c1_2 = Fq2::from_components(
        Fq::new_constant(&c1.c2.c0).unwrap(),
        Fq::new_constant(&c1.c2.c1).unwrap(),
    );
    let w1 = Fq6::from_components(c1_0, c1_1, c1_2);

    Fq12::from_components(w0, w1)
}

/// Miller loop over BN254 with constant Q and variable G1 wires.
#[component(offcircuit_args = "q")]
pub fn miller_loop_const_q<C: CircuitContext>(
    circuit: &mut C,
    p: &G1Projective,
    q: &ark_bn254::G2Affine,
) -> Fq12 {
    // Ensure P is in affine form for line evaluation
    let p_aff = g1_normalize_to_affine(circuit, p);
    let coeffs = ell_coeffs(*q);
    let mut coeff_iter = coeffs.iter();

    let mut f = new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            f = Fq12::square_montgomery(circuit, &f);
        }

        let c = coeff_iter.next().expect("coeff present");
        f = ell_eval_const(circuit, &f, c, &p_aff);

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let c2 = coeff_iter.next().expect("coeff present");
            f = ell_eval_const(circuit, &f, c2, &p_aff);
        }
    }

    // Final two additions outside the loop
    let c_last = coeff_iter.next().expect("coeff present");
    f = ell_eval_const(circuit, &f, c_last, &p_aff);
    let c_last2 = coeff_iter.next().expect("coeff present");
    f = ell_eval_const(circuit, &f, c_last2, &p_aff);

    f
}

/// Multi Miller loop with constant Qs and variable G1 wires.
#[component(offcircuit_args = "qs")]
pub fn multi_miller_loop_const_q<C: CircuitContext>(
    circuit: &mut C,
    ps: &[G1Projective],
    qs: &[ark_bn254::G2Affine],
) -> Fq12 {
    assert_eq!(ps.len(), qs.len());
    let n = ps.len();
    if n == 0 {
        // Keep initialization consistent: pass standard form, convert inside
        return new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);
    }

    // Precompute coeffs per Q
    let qells: Vec<Vec<EllCoeff>> = qs.iter().copied().map(ell_coeffs).collect();
    // Transpose by step index
    let steps = qells[0].len();
    let mut per_step: Vec<Vec<&EllCoeff>> = Vec::with_capacity(steps);
    for i in 0..steps {
        let mut v = Vec::with_capacity(n);
        for qell in &qells {
            v.push(&qell[i]);
        }
        per_step.push(v);
    }

    // Normalize all P_i to affine once
    let ps_aff: Vec<G1Projective> = ps
        .iter()
        .map(|p| g1_normalize_to_affine(circuit, p))
        .collect();

    let mut f = new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);
    let mut per_step_iter = per_step.into_iter();

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            f = Fq12::square_montgomery(circuit, &f);
        }

        let coeffs_now = per_step_iter.next().expect("coeffs present");
        for (c, p) in coeffs_now.into_iter().zip(ps_aff.iter()) {
            f = ell_eval_const(circuit, &f, c, p);
        }

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let coeffs_now = per_step_iter.next().expect("coeffs present");
            for (c, p) in coeffs_now.into_iter().zip(ps_aff.iter()) {
                f = ell_eval_const(circuit, &f, c, p);
            }
        }
    }

    // Final two steps
    for _ in 0..2 {
        let coeffs_now = per_step_iter.next().expect("coeffs present");
        for (c, p) in coeffs_now.into_iter().zip(ps_aff.iter()) {
            f = ell_eval_const(circuit, &f, c, p);
        }
    }

    f
}

/// Miller loop over BN254 with variable Q (G2 wires) and variable G1 wires.
///
/// Normalizes P and Q to affine once, then performs the ATE loop by computing
/// line coefficients on-the-fly (double/add) and evaluating at P via a sparse
/// Fq12 multiplication (indices 0,3,4).
pub fn miller_loop_montgomery_fast<C: CircuitContext>(
    circuit: &mut C,
    p: &G1Projective,
    q: &G2Projective,
) -> Fq12 {
    let qell = ell_coeffs_montgomery(circuit, q);
    let mut q_ell = qell.iter();

    let mut f = new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            f = Fq12::square_montgomery(circuit, &f);
        }

        let qell_next = q_ell.next().unwrap().clone();
        f = ell_montgomery(circuit, &f, &qell_next, p);

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let qell_next = q_ell.next().unwrap().clone();
            let new_f = ell_montgomery(circuit, &f, &qell_next, p);
            f = new_f;
        }
    }

    let qell_next = q_ell.next().unwrap().clone();
    f = ell_montgomery(circuit, &f, &qell_next, p);
    let qell_next = q_ell.next().unwrap().clone();

    ell_montgomery(circuit, &f, &qell_next, p)
}

// Final exponentiation logic has moved to gadgets::bn254::final_exponentiation

/// Full pairing with constant `Q`: Miller loop followed by final exponentiation.
#[component(offcircuit_args = "q")]
pub fn pairing_const_q<C: CircuitContext>(
    circuit: &mut C,
    p: &G1Projective,
    q: &ark_bn254::G2Affine,
) -> Fq12 {
    let f = miller_loop_const_q(circuit, p, q);
    final_exponentiation_montgomery(circuit, &f)
}

/// Multi-pairing aggregation with constant `Q_i` and variable `P_i`.
#[component(offcircuit_args = "qs")]
pub fn multi_pairing_const_q<C: CircuitContext>(
    circuit: &mut C,
    ps: &[G1Projective],
    qs: &[ark_bn254::G2Affine],
) -> Fq12 {
    let f = multi_miller_loop_const_q(circuit, ps, qs);
    final_exponentiation_montgomery(circuit, &f)
}

impl OffCircuitParam for &ark_bn254::Fq6 {
    fn to_key_bytes(&self) -> Vec<u8> {
        [
            self.c0.to_key_bytes(),
            self.c1.to_key_bytes(),
            self.c2.to_key_bytes(),
        ]
        .concat()
    }
}

impl WiresObject for (Fq12, G1Projective) {
    fn to_wires_vec(&self) -> Vec<crate::WireId> {
        [self.0.to_wires_vec(), self.1.to_wires_vec()].concat()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> crate::WireId) -> Self {
        (self.0.clone_from(wire_gen), self.1.clone_from(wire_gen))
    }
}

#[component(offcircuit_args = "coeffs")]
pub fn ell_by_constant_montgomery<C: CircuitContext>(
    circuit: &mut C,
    f: &Fq12,
    coeffs: &ark_bn254::Fq6,
    p: &G1Projective,
) -> Fq12 {
    let c0 = &coeffs.c0;
    let c1 = &coeffs.c1;
    let c2 = &coeffs.c2;

    let px = &p.x;
    let py = &p.y;

    let new_c0 = Fq2::mul_constant_by_fq_montgomery(circuit, c0, py);
    let new_c1 = Fq2::mul_constant_by_fq_montgomery(circuit, c1, px);
    // c2 must be provided in Montgomery form for the constant path
    let c2_m = Fq2::as_montgomery(*c2);
    Fq12::mul_by_034_constant4_montgomery(circuit, f, &new_c0, &new_c1, &c2_m)
}

#[component(offcircuit_args = "q1,q2")]
pub fn multi_miller_loop_groth16_evaluate_montgomery_fast<C: CircuitContext>(
    circuit: &mut C,
    p1: &G1Projective,
    p2: &G1Projective,
    p3: &G1Projective,
    q1: ark_bn254::G2Affine,
    q2: ark_bn254::G2Affine,
    q3: &G2Projective,
) -> Fq12 {
    let q1ell = ell_coeffs(q1);
    let q2ell = ell_coeffs(q2);
    let q3ell = ell_coeffs_montgomery(circuit, q3);
    let mut q1_ell = q1ell.iter();
    let mut q2_ell = q2ell.iter();
    let mut q3_ell = q3ell.iter();

    let mut f = new_fq12_constant_montgomery(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            f = Fq12::square_montgomery(circuit, &f);
        }

        let q1ell_next = q1_ell.next().unwrap();
        f = ell_by_constant_montgomery(circuit, &f, q1ell_next, p1);

        let q2ell_next = q2_ell.next().unwrap();
        f = ell_by_constant_montgomery(circuit, &f, q2ell_next, p2);

        let q3ell_next = q3_ell.next().unwrap().clone();
        f = ell_montgomery(circuit, &f, &q3ell_next, p3);

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let q1ell_next = q1_ell.next().unwrap();
            f = ell_by_constant_montgomery(circuit, &f, q1ell_next, p1);

            let q2ell_next = q2_ell.next().unwrap();
            f = ell_by_constant_montgomery(circuit, &f, q2ell_next, p2);

            let q3ell_next = q3_ell.next().unwrap().clone();
            f = ell_montgomery(circuit, &f, &q3ell_next, p3);
        }
    }

    let q1ell_next = q1_ell.next().unwrap();
    f = ell_by_constant_montgomery(circuit, &f, q1ell_next, p1);

    let q2ell_next = q2_ell.next().unwrap();
    f = ell_by_constant_montgomery(circuit, &f, q2ell_next, p2);

    let q3ell_next = q3_ell.next().unwrap().clone();
    f = ell_montgomery(circuit, &f, &q3ell_next, p3);

    let q1ell_next = q1_ell.next().unwrap();
    f = ell_by_constant_montgomery(circuit, &f, q1ell_next, p1);

    let q2ell_next = q2_ell.next().unwrap();
    f = ell_by_constant_montgomery(circuit, &f, q2ell_next, p2);

    let q3ell_next = q3_ell.next().unwrap().clone();
    f = ell_montgomery(circuit, &f, &q3ell_next, p3);

    f
}

#[cfg(test)]
mod tests {
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{Field, PrimeField, UniformRand};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{
        Gate, WireId,
        circuit::{
            CircuitBuilder, CircuitInput, CircuitOutput, EncodeInput, TRUE_WIRE, WiresObject,
            modes::{CircuitMode, ExecuteMode},
        },
        gadgets::{
            bigint::{BigUint as BigUintOutput, bits_from_biguint_with_len},
            bn254::{fp254impl::Fp254Impl, g2::G2Projective as G2Wires},
        },
    };

    fn rnd_fr(rng: &mut impl Rng) -> ark_bn254::Fr {
        let mut prng = ChaCha20Rng::seed_from_u64(rng.r#gen());
        ark_bn254::Fr::rand(&mut prng)
    }

    fn random_g2_affine(rng: &mut impl Rng) -> ark_bn254::G2Affine {
        (ark_bn254::G2Projective::generator() * rnd_fr(rng)).into_affine()
    }

    #[test]
    fn test_ell_eval_var_matches_ark_step() {
        // Randomized check that ell_eval_var matches host-side BN254 logic
        let mut rng = ChaCha20Rng::seed_from_u64(77);

        // Random initial accumulator f and random variable coefficients (Fq2 triple)
        let f0 = ark_bn254::Fq12::rand(&mut rng);
        let coeffs = ark_bn254::Fq6::rand(&mut rng);

        // Random G1 point, ensure affine (z=1) by converting through affine -> projective
        let p = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng))
            .into_affine()
            .into_group();

        // Expected off-circuit result
        let mut exp_f = f0;
        let mut c0 = coeffs.c0;
        let mut c1 = coeffs.c1;
        let c2 = coeffs.c2;

        let p_aff = p.into_affine();
        c0.mul_assign_by_fp(&p_aff.y);
        c1.mul_assign_by_fp(&p_aff.x);
        exp_f.mul_by_034(&c0, &c1, &c2);
        let expected_m = Fq12::as_montgomery(exp_f);

        // Wires for f, p, and wire-based coeffs
        struct In {
            f: ark_bn254::Fq12,
            p: ark_bn254::G1Projective,
            c: ark_bn254::Fq6,
        }
        struct W {
            f: Fq12,
            p: G1Projective,
            c: Fq6,
        }
        impl CircuitInput for In {
            type WireRepr = W;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                W {
                    f: Fq12::new(&mut issue),
                    p: G1Projective::new(&mut issue),
                    c: Fq6::new(&mut issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = repr.f.to_wires_vec();
                ids.extend(repr.p.to_wires_vec());
                ids.extend(repr.c.to_wires_vec());
                ids
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for In {
            fn encode(&self, repr: &W, cache: &mut M) {
                // f in Montgomery form
                let f_m = Fq12::as_montgomery(self.f);
                encode_fq6_to_wires(&f_m.c0, &repr.f.0[0], cache);
                encode_fq6_to_wires(&f_m.c1, &repr.f.0[1], cache);

                // p in Montgomery form
                let p_m = G1Projective::as_montgomery(self.p);
                let bits_x = bits_from_biguint_with_len(
                    &BigUintOutput::from(p_m.x.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let bits_y = bits_from_biguint_with_len(
                    &BigUintOutput::from(p_m.y.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let bits_z = bits_from_biguint_with_len(
                    &BigUintOutput::from(p_m.z.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                repr.p
                    .x
                    .0
                    .iter()
                    .zip(bits_x)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.p
                    .y
                    .0
                    .iter()
                    .zip(bits_y)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.p
                    .z
                    .0
                    .iter()
                    .zip(bits_z)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));

                // Encode Fq6 coeffs in Montgomery form into Fq6 wires
                let c_m = Fq6::as_montgomery(self.c);
                encode_fq6_to_wires(&c_m, &repr.c, cache);
            }
        }

        let input = In {
            f: f0,
            p,
            c: coeffs,
        };
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, w| {
                ell_montgomery(ctx, &w.f, &w.c, &w.p)
            });

        assert_eq!(result.output_value.value, expected_m);
    }

    #[test]
    fn test_g2_normalize_to_affine_matches_host() {
        // Generate random projective G2 point and expected affine (z=1) in Montgomery
        let mut rng = ChaCha20Rng::seed_from_u64(0xA11FE2);
        let r = ark_bn254::G2Projective::generator() * rnd_fr(&mut rng);
        let r_aff = r.into_affine();
        let expected = ark_bn254::G2Projective::new(r_aff.x, r_aff.y, ark_bn254::Fq2::ONE);
        // Keep expected in canonical field representation for comparison with decoded canonical
        let expected_std = expected;

        // Circuit input containing the projective point (Montgomery)
        struct InputG2norm {
            p: ark_bn254::G2Projective,
        }
        struct WiresG2norm {
            p: G2Projective,
        }
        impl CircuitInput for InputG2norm {
            type WireRepr = WiresG2norm;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                WiresG2norm {
                    p: G2Projective::new(&mut issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                repr.p.to_wires_vec()
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for InputG2norm {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
                let p_m = G2Projective::as_montgomery(self.p);
                let f = G2Projective::get_wire_bits_fn(&repr.p, &p_m).unwrap();
                for &w in repr.p.to_wires_vec().iter() {
                    if let Some(bit) = f(w) {
                        cache.feed_wire(w, bit);
                    }
                }
            }
        }

        // Output decoder for G2 projective wires -> ark type
        struct OutG2norm {
            val: ark_bn254::G2Projective,
        }
        impl CircuitOutput<ExecuteMode> for OutG2norm {
            type WireRepr = G2Projective;
            fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
                // Decode Fq2 from wires helper
                fn decode_fq2_from_wires(w: &Fq2, cache: &mut ExecuteMode) -> ark_bn254::Fq2 {
                    // Read Montgomery limbs from wires, then convert back to standard form
                    let c0_bi = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        w.c0().0.clone(),
                        cache,
                    );
                    let c1_bi = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        w.c1().0.clone(),
                        cache,
                    );
                    let c0_m = ark_bn254::Fq::from(c0_bi);
                    let c1_m = ark_bn254::Fq::from(c1_bi);
                    let fq2_m = ark_bn254::Fq2::new(c0_m, c1_m);
                    Fq2::from_montgomery(fq2_m)
                }
                let x = decode_fq2_from_wires(&wires.x, cache);
                let y = decode_fq2_from_wires(&wires.y, cache);
                let z = decode_fq2_from_wires(&wires.z, cache);
                OutG2norm {
                    val: ark_bn254::G2Projective::new(x, y, z),
                }
            }
        }

        let input = InputG2norm { p: r };
        let res =
            CircuitBuilder::streaming_execute::<_, _, OutG2norm>(input, 20_000, |ctx, wires| {
                g2_normalize_to_affine(ctx, &wires.p)
            });

        assert_eq!(res.output_value.val, expected_std);
    }

    // Local helper to decode Fq2 (Montgomery wires -> canonical field element)
    fn decode_fq2_from_wires(w: &Fq2, cache: &mut ExecuteMode) -> ark_bn254::Fq2 {
        let c0_bi = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(w.0[0].0.clone(), cache);
        let c1_bi = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(w.0[1].0.clone(), cache);
        let c0_m = ark_bn254::Fq::from(c0_bi);
        let c1_m = ark_bn254::Fq::from(c1_bi);
        let fq2_m = ark_bn254::Fq2::new(c0_m, c1_m);
        Fq2::from_montgomery(fq2_m)
    }

    // Local helper to decode G2 projective wires into canonical host value
    fn decode_g2proj_from_wires(
        wires: &G2Projective,
        cache: &mut ExecuteMode,
    ) -> ark_bn254::G2Projective {
        let x = decode_fq2_from_wires(&wires.x, cache);
        let y = decode_fq2_from_wires(&wires.y, cache);
        let z = decode_fq2_from_wires(&wires.z, cache);
        ark_bn254::G2Projective::new(x, y, z)
    }

    #[test]
    fn test_g2_line_coeffs_double_matches_host() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xD0u64);
        let r = ark_bn254::G2Projective::generator() * rnd_fr(&mut rng);

        // Host expected: coefficients from affine R and next = 2R (affine z=1)
        let r_aff = r.into_affine();
        let x = r_aff.x;
        let y = r_aff.y;
        let lambda = (x.square() + x.square() + x.square()) * (y.double()).inverse().unwrap();
        let exp_c0 = ark_bn254::Fq2::ONE;
        let exp_c1 = -lambda;
        let exp_c2 = lambda * x - y;
        let next_exp = (r.double()).into_affine();
        let next_exp_proj =
            ark_bn254::G2Projective::new(next_exp.x, next_exp.y, ark_bn254::Fq2::ONE);

        // Execute gadget
        struct Input {
            r: ark_bn254::G2Projective,
        }
        struct Wires {
            r: G2Projective,
        }
        impl CircuitInput for Input {
            type WireRepr = Wires;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                Wires {
                    r: G2Projective::new(&mut issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                repr.r.to_wires_vec()
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Input {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
                let r_m = G2Projective::as_montgomery(self.r);
                let f = G2Projective::get_wire_bits_fn(&repr.r, &r_m).unwrap();
                for &w in repr.r.to_wires_vec().iter() {
                    if let Some(b) = f(w) {
                        cache.feed_wire(w, b);
                    }
                }
            }
        }
        struct Output {
            next: ark_bn254::G2Projective,
            coeffs: ark_bn254::Fq6,
        }
        impl CircuitOutput<ExecuteMode> for Output {
            type WireRepr = (G2Projective, Fq6);
            fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
                let (next, c) = wires;
                let c0 = decode_fq2_from_wires(&c.0[0], cache);
                let c1 = decode_fq2_from_wires(&c.0[1], cache);
                let c2 = decode_fq2_from_wires(&c.0[2], cache);
                Self {
                    next: decode_g2proj_from_wires(&next, cache),
                    coeffs: ark_bn254::Fq6::new(c0, c1, c2),
                }
            }
        }

        let res = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Output>(
            Input { r },
            50_000,
            |ctx, w| {
                let (next, c) = g2_line_coeffs_double(ctx, &w.r);
                (next, c)
            },
        );

        assert_eq!(res.output_value.next, next_exp_proj);
        assert_eq!(res.output_value.coeffs.c0, exp_c0);
        assert_eq!(res.output_value.coeffs.c1, exp_c1);
        assert_eq!(res.output_value.coeffs.c2, exp_c2);
    }

    #[test]
    fn test_g2_line_coeffs_add_matches_host() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xADDu64);
        let r = ark_bn254::G2Projective::generator() * rnd_fr(&mut rng);
        let q = ark_bn254::G2Projective::generator() * rnd_fr(&mut rng);

        // Host expected from affine forms
        let r_aff = r.into_affine();
        let q_aff = q.into_affine();
        // Avoid the rare vertical line; if so, tweak q by adding generator
        let (x1, y1) = (r_aff.x, r_aff.y);
        let (x2, y2) = (q_aff.x, q_aff.y);
        let mut x2a = x2;
        let mut y2a = y2;
        if x2a == x1 {
            // pathological, adjust deterministically
            let g = ark_bn254::G2Affine::generator();
            x2a = g.x;
            y2a = g.y;
        }
        let lambda = (y2a - y1) * (x2a - x1).inverse().unwrap();
        let exp_c0 = ark_bn254::Fq2::ONE;
        let exp_c1 = -lambda;
        let exp_c2 = lambda * x1 - y1;
        let next_exp = (r + q).into_affine();
        let next_exp_proj =
            ark_bn254::G2Projective::new(next_exp.x, next_exp.y, ark_bn254::Fq2::ONE);

        // Execute gadget
        struct Input {
            r: ark_bn254::G2Projective,
            q: ark_bn254::G2Projective,
        }
        struct Wires {
            r: G2Projective,
            q: G2Projective,
        }
        impl CircuitInput for Input {
            type WireRepr = Wires;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                Wires {
                    r: G2Projective::new(&mut issue),
                    q: G2Projective::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut v = repr.r.to_wires_vec();
                v.extend(repr.q.to_wires_vec());
                v
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Input {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
                let r_m = G2Projective::as_montgomery(self.r);
                let f_r = G2Projective::get_wire_bits_fn(&repr.r, &r_m).unwrap();
                for &w in repr.r.to_wires_vec().iter() {
                    if let Some(b) = f_r(w) {
                        cache.feed_wire(w, b);
                    }
                }
                let q_m = G2Projective::as_montgomery(self.q);
                let f_q = G2Projective::get_wire_bits_fn(&repr.q, &q_m).unwrap();
                for &w in repr.q.to_wires_vec().iter() {
                    if let Some(b) = f_q(w) {
                        cache.feed_wire(w, b);
                    }
                }
            }
        }
        struct Output {
            next: ark_bn254::G2Projective,
            coeffs: ark_bn254::Fq6,
        }
        impl CircuitOutput<ExecuteMode> for Output {
            type WireRepr = (G2Projective, Fq6);
            fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
                let (next, c) = wires;
                let c0 = decode_fq2_from_wires(&c.0[0], cache);
                let c1 = decode_fq2_from_wires(&c.0[1], cache);
                let c2 = decode_fq2_from_wires(&c.0[2], cache);
                Self {
                    next: decode_g2proj_from_wires(&next, cache),
                    coeffs: ark_bn254::Fq6::new(c0, c1, c2),
                }
            }
        }

        let res = crate::circuit::CircuitBuilder::streaming_execute::<_, _, Output>(
            Input { r, q },
            80_000,
            |ctx, w| {
                let (next, c) = g2_line_coeffs_add(ctx, &w.r, &w.q);
                (next, c)
            },
        );

        assert_eq!(res.output_value.next, next_exp_proj);
        assert_eq!(res.output_value.coeffs.c0, exp_c0);
        assert_eq!(res.output_value.coeffs.c1, exp_c1);
        assert_eq!(res.output_value.coeffs.c2, exp_c2);
    }

    #[test]
    fn test_g2_frobenius_map_affine_matches_host() {
        let mut rng = ChaCha20Rng::seed_from_u64(0xF10B1);
        let r_aff = (ark_bn254::G2Projective::generator() * rnd_fr(&mut rng)).into_affine();
        let r_aff_proj = ark_bn254::G2Projective::new(r_aff.x, r_aff.y, ark_bn254::Fq2::ONE);

        // Build expected host result for i in {1,2}
        for i in [1usize, 2usize] {
            let x_p = r_aff.x.frobenius_map(1);
            let y_p = r_aff.y.frobenius_map(1);
            let cx = ark_bn254::Config::TWIST_MUL_BY_Q_X;
            let cy = ark_bn254::Config::TWIST_MUL_BY_Q_Y;
            let (exp_x, exp_y) = if i == 1 {
                (x_p * cx, y_p * cy)
            } else {
                let x1 = x_p * cx;
                let y1 = y_p * cy;
                (x1.frobenius_map(1) * cx, -(y1.frobenius_map(1) * cy))
            };

            // Streaming execute: encode affine projective (z=1) and apply gadget
            struct Input {
                p: ark_bn254::G2Projective,
            }
            struct Wires {
                p: G2Projective,
            }
            impl CircuitInput for Input {
                type WireRepr = Wires;
                fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                    Wires {
                        p: G2Projective::new(&mut issue),
                    }
                }
                fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                    repr.p.to_wires_vec()
                }
            }
            impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for Input {
                fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
                    let p_m = G2Projective::as_montgomery(self.p);
                    let f = G2Projective::get_wire_bits_fn(&repr.p, &p_m).unwrap();
                    for &w in repr.p.to_wires_vec().iter() {
                        if let Some(bit) = f(w) {
                            cache.feed_wire(w, bit);
                        }
                    }
                }
            }
            struct OutXY {
                x: ark_bn254::Fq2,
                y: ark_bn254::Fq2,
                z: ark_bn254::Fq2,
            }
            impl CircuitOutput<ExecuteMode> for OutXY {
                type WireRepr = G2Projective;
                fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
                    fn decode_fq2_from_wires(w: &Fq2, cache: &mut ExecuteMode) -> ark_bn254::Fq2 {
                        let c0_bi = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                            w.c0().0.clone(),
                            cache,
                        );
                        let c1_bi = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                            w.c1().0.clone(),
                            cache,
                        );
                        Fq2::from_montgomery(ark_bn254::Fq2::new(
                            ark_bn254::Fq::from(c0_bi),
                            ark_bn254::Fq::from(c1_bi),
                        ))
                    }
                    let x = decode_fq2_from_wires(&wires.x, cache);
                    let y = decode_fq2_from_wires(&wires.y, cache);
                    let z = decode_fq2_from_wires(&wires.z, cache);
                    OutXY { x, y, z }
                }
            }

            let input = Input { p: r_aff_proj };
            let result =
                CircuitBuilder::streaming_execute::<_, _, OutXY>(input, 20_000, |ctx, wires| {
                    g2_frobenius_map_affine(ctx, &wires.p, i)
                });

            let out = result.output_value;
            assert_eq!(out.x, exp_x);
            assert_eq!(out.y, exp_y);
            assert_eq!(out.z, ark_bn254::Fq2::ONE);
        }
    }

    #[test]
    fn test_ell_coeffs_montgomery_fast_matches_host() {
        use ark_ec::pairing::Pairing;
        let mut rng = ChaCha20Rng::seed_from_u64(0xECFF);
        let q_aff = (ark_bn254::G2Projective::generator() * rnd_fr(&mut rng)).into_affine();
        let q_proj = ark_bn254::G2Projective::new(q_aff.x, q_aff.y, ark_bn254::Fq2::ONE);

        // Host expected coeffs using arkworks prepared coefficients
        let expected = {
            type G2Prep = <ark_bn254::Bn254 as Pairing>::G2Prepared;
            let prepared: G2Prep = q_aff.into();
            prepared.ell_coeffs
        };

        struct In {
            q: ark_bn254::G2Projective,
        }
        struct W {
            q: G2Wires,
        }
        impl CircuitInput for In {
            type WireRepr = W;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                W {
                    q: G2Wires::new(&mut issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                repr.q.to_wires_vec()
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for In {
            fn encode(&self, repr: &W, cache: &mut M) {
                let q_m = G2Wires::as_montgomery(self.q);
                let f = G2Wires::get_wire_bits_fn(&repr.q, &q_m).unwrap();
                for &w in repr.q.to_wires_vec().iter() {
                    if let Some(bit) = f(w) {
                        cache.feed_wire(w, bit);
                    }
                }
            }
        }

        // Closure computes coeffs and checks equality against constants, returns a single bool
        let out = CircuitBuilder::streaming_execute::<_, _, Vec<bool>>(
            In { q: q_proj },
            50_000,
            |ctx, wires| {
                let got = ell_coeffs_montgomery(ctx, &wires.q);
                // Combine all equality checks into one flag
                let mut ok = TRUE_WIRE;
                for (i, coeff) in got.into_iter().enumerate() {
                    let c0 = coeff.0[0].clone();
                    let c1 = coeff.0[1].clone();
                    let c2 = coeff.0[2].clone();
                    // Our wire computations are in Montgomery form; compare against
                    // Montgomery-encoded constants to match representation.
                    let (e0, e1, e2) = expected[i];
                    let e0_m = Fq2::as_montgomery(e0);
                    let e1_m = Fq2::as_montgomery(e1);
                    let e2_m = Fq2::as_montgomery(e2);
                    let t0 = Fq2::equal_constant(ctx, &c0, &e0_m);
                    let t1 = Fq2::equal_constant(ctx, &c1, &e1_m);
                    let t2 = Fq2::equal_constant(ctx, &c2, &e2_m);
                    let t01 = ctx.issue_wire();
                    ctx.add_gate(Gate::and(t0, t1, t01));
                    let t = ctx.issue_wire();
                    ctx.add_gate(Gate::and(t01, t2, t));
                    let new_ok = ctx.issue_wire();
                    ctx.add_gate(Gate::and(ok, t, new_ok));
                    ok = new_ok;
                }
                vec![ok]
            },
        );

        assert!(out.output_value[0]);
    }

    #[test]
    fn test_ell_coeffs_matches_arkworks() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let q = random_g2_affine(&mut rng);

        let ours = ell_coeffs(q);
        let ark = {
            use ark_ec::pairing::Pairing;
            type G2Prep = <ark_bn254::Bn254 as Pairing>::G2Prepared;
            let prepared: G2Prep = q.into();
            prepared.ell_coeffs
        };

        assert_eq!(ours.len(), ark.len(), "coeff vector length mismatch");
        for (i, (a, b)) in ours.iter().zip(ark.iter()).enumerate() {
            assert_eq!(a.c0, b.0, "c0 mismatch at idx {i}");
            assert_eq!(a.c1, b.1, "c1 mismatch at idx {i}");
            assert_eq!(a.c2, b.2, "c2 mismatch at idx {i}");
        }
    }

    // Helper to encode Fq6 into wires (Montgomery form expected)
    fn encode_fq6_to_wires(
        val: &ark_bn254::Fq6,
        wires: &crate::gadgets::bn254::fq6::Fq6,
        cache: &mut impl CircuitMode<WireValue = bool>,
    ) {
        use crate::gadgets::bn254::fq::Fq as FqWire;
        let c0_c0_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c0.c0.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        let c0_c1_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c0.c1.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        wires.0[0].0[0]
            .0
            .iter()
            .zip(c0_c0_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));
        wires.0[0].0[1]
            .0
            .iter()
            .zip(c0_c1_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));

        let c1_c0_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c1.c0.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        let c1_c1_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c1.c1.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        wires.0[1].0[0]
            .0
            .iter()
            .zip(c1_c0_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));
        wires.0[1].0[1]
            .0
            .iter()
            .zip(c1_c1_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));

        let c2_c0_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c2.c0.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        let c2_c1_bits = bits_from_biguint_with_len(
            &BigUintOutput::from(val.c2.c1.into_bigint()),
            FqWire::N_BITS,
        )
        .unwrap();
        wires.0[2].0[0]
            .0
            .iter()
            .zip(c2_c0_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));
        wires.0[2].0[1]
            .0
            .iter()
            .zip(c2_c1_bits)
            .for_each(|(w, b)| cache.feed_wire(*w, b));
    }

    #[test]
    fn test_final_exponentiation_matches_arkworks() {
        use ark_ec::pairing::Pairing;
        // Deterministic inputs
        let mut rng = ChaCha20Rng::seed_from_u64(12345);
        let p = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng)).into_affine();
        let q = random_g2_affine(&mut rng);

        // Miller loop off-circuit (arkworks)
        let f_ml = ark_bn254::Bn254::multi_miller_loop([p], [q]).0;
        let expected = ark_bn254::Bn254::pairing(p, q);
        let expected_m = Fq12::as_montgomery(expected.0);

        // Encode f_ml as input (Montgomery) and apply final exponentiation in-circuit
        struct FEInput {
            f: ark_bn254::Fq12,
        }
        struct FEWires {
            f: Fq12,
        }

        struct FinalExpOutput {
            value: ark_bn254::Fq12,
        }
        impl CircuitInput for FEInput {
            type WireRepr = FEWires;
            fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
                FEWires {
                    f: Fq12::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
                repr.f.to_wires_vec()
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for FEInput {
            fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
                let f_m = Fq12::as_montgomery(self.f);
                encode_fq6_to_wires(&f_m.c0, &repr.f.0[0], cache);
                encode_fq6_to_wires(&f_m.c1, &repr.f.0[1], cache);
            }
        }
        impl CircuitOutput<ExecuteMode> for FinalExpOutput {
            type WireRepr = Fq12;
            fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
                // Reuse local decoder helpers
                fn decode_fq6_from_wires(
                    wires: &crate::gadgets::bn254::fq6::Fq6,
                    cache: &mut ExecuteMode,
                ) -> ark_bn254::Fq6 {
                    let c0_c0 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[0].0[0].0.clone(),
                        cache,
                    );
                    let c0_c1 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[0].0[1].0.clone(),
                        cache,
                    );
                    let c1_c0 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[1].0[0].0.clone(),
                        cache,
                    );
                    let c1_c1 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[1].0[1].0.clone(),
                        cache,
                    );
                    let c2_c0 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[2].0[0].0.clone(),
                        cache,
                    );
                    let c2_c1 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[2].0[1].0.clone(),
                        cache,
                    );
                    let c0 =
                        ark_bn254::Fq2::new(ark_bn254::Fq::from(c0_c0), ark_bn254::Fq::from(c0_c1));
                    let c1 =
                        ark_bn254::Fq2::new(ark_bn254::Fq::from(c1_c0), ark_bn254::Fq::from(c1_c1));
                    let c2 =
                        ark_bn254::Fq2::new(ark_bn254::Fq::from(c2_c0), ark_bn254::Fq::from(c2_c1));
                    ark_bn254::Fq6::new(c0, c1, c2)
                }
                let c0 = decode_fq6_from_wires(&wires.0[0], cache);
                let c1 = decode_fq6_from_wires(&wires.0[1], cache);
                Self {
                    value: ark_bn254::Fq12::new(c0, c1),
                }
            }
        }

        let input = FEInput { f: f_ml };
        let result = CircuitBuilder::streaming_execute::<_, _, FinalExpOutput>(
            input,
            10_000,
            |ctx, input| final_exponentiation_montgomery(ctx, &input.f),
        );

        assert_eq!(result.output_value.value, expected_m);
    }

    #[test]
    fn test_miller_loop_var_q_matches_ark_single() {
        use ark_ec::pairing::Pairing;
        let mut rng = ChaCha20Rng::seed_from_u64(0x515AF1);
        // Random P (affine) and Q (projective)
        let p_aff = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng)).into_affine();
        let p = p_aff.into_group();
        let q_proj = ark_bn254::G2Projective::generator() * rnd_fr(&mut rng);
        let q_aff = q_proj.into_affine();
        // Create affine-encoded projective Q with z = 1 for mixed-add precondition
        let q_aff_proj = ark_bn254::G2Projective::new(q_aff.x, q_aff.y, ark_bn254::Fq2::ONE);

        // Expected: full pairing off-circuit
        let expected = ark_bn254::Bn254::pairing(p_aff, q_aff);
        let expected_m = Fq12::as_montgomery(expected.0);

        struct In {
            p: ark_bn254::G1Projective,
            q: ark_bn254::G2Projective,
        }
        struct W {
            p: G1Projective,
            q: G2Wires,
        }
        impl CircuitInput for In {
            type WireRepr = W;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                W {
                    p: G1Projective::new(&mut issue),
                    q: G2Wires::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = repr.p.to_wires_vec();
                ids.extend(repr.q.to_wires_vec());
                ids
            }
        }
        fn encode_p<M: CircuitMode<WireValue = bool>>(
            p: ark_bn254::G1Projective,
            w: &G1Projective,
            cache: &mut M,
        ) {
            let p_m = G1Projective::as_montgomery(p);
            let bits_x =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.x.into_bigint()), Fq::N_BITS)
                    .unwrap();
            let bits_y =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.y.into_bigint()), Fq::N_BITS)
                    .unwrap();
            let bits_z =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.z.into_bigint()), Fq::N_BITS)
                    .unwrap();
            w.x.0
                .iter()
                .zip(bits_x)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            w.y.0
                .iter()
                .zip(bits_y)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            w.z.0
                .iter()
                .zip(bits_z)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for In {
            fn encode(&self, repr: &W, cache: &mut M) {
                encode_p(self.p, &repr.p, cache);
                // Encode Q as Montgomery using helper mapping function
                let q_m = G2Wires::as_montgomery(self.q);
                let f = G2Wires::get_wire_bits_fn(&repr.q, &q_m).unwrap();
                for &w in repr.q.to_wires_vec().iter() {
                    if let Some(bit) = f(w) {
                        cache.feed_wire(w, bit);
                    }
                }
            }
        }

        let result = CircuitBuilder::streaming_execute::<_, _, Fq12Output>(
            In { p, q: q_aff_proj },
            10_000,
            |ctx, input| {
                let f_ml = miller_loop_montgomery_fast(ctx, &input.p, &input.q);
                final_exponentiation_montgomery(ctx, &f_ml)
            },
        );

        assert_eq!(result.output_value.value, expected_m);
    }
    // Local decoder helpers for Fq12 output
    fn decode_fq6_from_wires(
        wires: &crate::gadgets::bn254::fq6::Fq6,
        cache: &mut ExecuteMode,
    ) -> ark_bn254::Fq6 {
        let c0_c0 =
            <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(wires.0[0].0[0].0.clone(), cache);
        let c0_c1 =
            <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(wires.0[0].0[1].0.clone(), cache);
        let c1_c0 =
            <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(wires.0[1].0[0].0.clone(), cache);
        let c1_c1 =
            <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(wires.0[1].0[1].0.clone(), cache);
        let c2_c0 =
            <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(wires.0[2].0[0].0.clone(), cache);
        let c2_c1 =
            <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(wires.0[2].0[1].0.clone(), cache);

        let c0 = ark_bn254::Fq2::new(ark_bn254::Fq::from(c0_c0), ark_bn254::Fq::from(c0_c1));
        let c1 = ark_bn254::Fq2::new(ark_bn254::Fq::from(c1_c0), ark_bn254::Fq::from(c1_c1));
        let c2 = ark_bn254::Fq2::new(ark_bn254::Fq::from(c2_c0), ark_bn254::Fq::from(c2_c1));
        ark_bn254::Fq6::new(c0, c1, c2)
    }

    struct Fq12Output {
        value: ark_bn254::Fq12,
    }
    impl CircuitOutput<ExecuteMode> for Fq12Output {
        type WireRepr = Fq12;
        fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
            let c0 = decode_fq6_from_wires(&wires.0[0], cache);
            let c1 = decode_fq6_from_wires(&wires.0[1], cache);
            Self {
                value: ark_bn254::Fq12::new(c0, c1),
            }
        }
    }

    struct EllEvalInput {
        f: ark_bn254::Fq12,
        p: ark_bn254::G1Projective,
    }
    struct EllEvalWires {
        f: Fq12,
        p: G1Projective,
    }
    impl CircuitInput for EllEvalInput {
        type WireRepr = EllEvalWires;
        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            EllEvalWires {
                f: Fq12::new(&mut issue),
                p: G1Projective::new(issue),
            }
        }
        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
            let mut ids = repr.f.to_wires_vec();
            ids.extend(repr.p.to_wires_vec());
            ids
        }
    }
    impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for EllEvalInput {
        fn encode(&self, repr: &EllEvalWires, cache: &mut M) {
            // Encode f (Fq12) in Montgomery form
            let f_m = Fq12::as_montgomery(self.f);
            encode_fq6_to_wires(&f_m.c0, &repr.f.0[0], cache);
            encode_fq6_to_wires(&f_m.c1, &repr.f.0[1], cache);

            // Encode p (G1Projective) in Montgomery form
            let p_m = G1Projective::as_montgomery(self.p);
            let bits_x =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.x.into_bigint()), Fq::N_BITS)
                    .unwrap();
            let bits_y =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.y.into_bigint()), Fq::N_BITS)
                    .unwrap();
            let bits_z =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.z.into_bigint()), Fq::N_BITS)
                    .unwrap();
            repr.p
                .x
                .0
                .iter()
                .zip(bits_x)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            repr.p
                .y
                .0
                .iter()
                .zip(bits_y)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            repr.p
                .z
                .0
                .iter()
                .zip(bits_z)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
        }
    }

    #[test]
    fn test_ell_eval_const_matches_ark_step() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let q = random_g2_affine(&mut rng);
        let coeffs = ell_coeffs(q);
        // choose first step coeffs
        let coeff = coeffs[0];

        // random G1 point and initial f=1
        let p = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng))
            .into_affine()
            .into_group();

        // Expected off-circuit using arkworks API
        let mut exp_c0 = coeff.c0;
        let mut exp_c1 = coeff.c1;
        let exp_c2 = coeff.c2;
        let p_affine = p.into_affine();
        exp_c0.mul_assign_by_fp(&p_affine.y);
        exp_c1.mul_assign_by_fp(&p_affine.x);
        let mut expected = ark_bn254::Fq12::ONE;
        expected.mul_by_034(&exp_c0, &exp_c1, &exp_c2);
        let expected_m = Fq12::as_montgomery(expected);

        // Circuit computation
        let input = EllEvalInput {
            f: ark_bn254::Fq12::ONE,
            p,
        };
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                ell_eval_const(ctx, &input.f, &coeff, &input.p)
            });

        assert_eq!(result.output_value.value, expected_m);
    }

    #[test]
    fn test_miller_loop_const_q_matches_ark_single() {
        use ark_ec::pairing::Pairing;
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let p_aff = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng)).into_affine();
        let p = p_aff.into_group();
        let q = random_g2_affine(&mut rng);

        let expected_ml = ark_bn254::Bn254::multi_miller_loop([p_aff], [q]).0;
        let expected_m = Fq12::as_montgomery(expected_ml);

        struct In {
            p: ark_bn254::G1Projective,
        }
        struct W {
            p: G1Projective,
        }
        impl CircuitInput for In {
            type WireRepr = W;
            fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
                W {
                    p: G1Projective::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
                repr.p.to_wires_vec()
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for In {
            fn encode(&self, repr: &W, cache: &mut M) {
                // Encode p (G1Projective) in Montgomery form
                let p_m = G1Projective::as_montgomery(self.p);
                let bits_x = bits_from_biguint_with_len(
                    &BigUintOutput::from(p_m.x.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let bits_y = bits_from_biguint_with_len(
                    &BigUintOutput::from(p_m.y.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let bits_z = bits_from_biguint_with_len(
                    &BigUintOutput::from(p_m.z.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                repr.p
                    .x
                    .0
                    .iter()
                    .zip(bits_x)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.p
                    .y
                    .0
                    .iter()
                    .zip(bits_y)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.p
                    .z
                    .0
                    .iter()
                    .zip(bits_z)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
            }
        }

        let result = CircuitBuilder::streaming_execute::<_, _, Fq12Output>(
            In { p },
            10_000,
            |ctx, input| miller_loop_const_q(ctx, &input.p, &q),
        );

        assert_eq!(result.output_value.value, expected_m);
    }

    #[test]
    fn test_pairing_const_q_matches_ark_single() {
        use ark_ec::pairing::Pairing;
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let p_aff = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng)).into_affine();
        let p = p_aff.into_group();
        let q = random_g2_affine(&mut rng);

        let expected = ark_bn254::Bn254::pairing(p_aff, q);
        let expected_m = Fq12::as_montgomery(expected.0);

        struct In {
            p: ark_bn254::G1Projective,
        }
        struct W {
            p: G1Projective,
        }
        impl CircuitInput for In {
            type WireRepr = W;
            fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
                W {
                    p: G1Projective::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
                repr.p.to_wires_vec()
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for In {
            fn encode(&self, repr: &W, cache: &mut M) {
                // Encode p (G1Projective) in Montgomery form
                let p_m = G1Projective::as_montgomery(self.p);
                let bits_x = bits_from_biguint_with_len(
                    &BigUintOutput::from(p_m.x.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let bits_y = bits_from_biguint_with_len(
                    &BigUintOutput::from(p_m.y.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let bits_z = bits_from_biguint_with_len(
                    &BigUintOutput::from(p_m.z.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                repr.p
                    .x
                    .0
                    .iter()
                    .zip(bits_x)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.p
                    .y
                    .0
                    .iter()
                    .zip(bits_y)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.p
                    .z
                    .0
                    .iter()
                    .zip(bits_z)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
            }
        }

        let result = CircuitBuilder::streaming_execute::<_, _, Fq12Output>(
            In { p },
            10_000,
            |ctx, input| pairing_const_q(ctx, &input.p, &q),
        );

        assert_eq!(result.output_value.value, expected_m);
    }

    #[test]
    fn test_multi_pairing_const_q_matches_ark_n3() {
        use ark_ec::pairing::Pairing;
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let p0_aff = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng)).into_affine();
        let p1_aff = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng)).into_affine();
        let p2_aff = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng)).into_affine();
        let p0 = p0_aff.into_group();
        let p1 = p1_aff.into_group();
        let p2 = p2_aff.into_group();
        let q0 = random_g2_affine(&mut rng);
        let q1 = random_g2_affine(&mut rng);
        let q2 = random_g2_affine(&mut rng);

        let expected = ark_bn254::Bn254::multi_pairing([p0_aff, p1_aff, p2_aff], [q0, q1, q2]);
        let expected_m = Fq12::as_montgomery(expected.0);

        struct In {
            p0: ark_bn254::G1Projective,
            p1: ark_bn254::G1Projective,
            p2: ark_bn254::G1Projective,
        }
        struct W {
            p0: G1Projective,
            p1: G1Projective,
            p2: G1Projective,
        }
        impl CircuitInput for In {
            type WireRepr = W;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                W {
                    p0: G1Projective::new(&mut issue),
                    p1: G1Projective::new(&mut issue),
                    p2: G1Projective::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
                let mut ids = Vec::with_capacity(G1Projective::N_BITS * 3);
                ids.extend(repr.p0.to_wires_vec());
                ids.extend(repr.p1.to_wires_vec());
                ids.extend(repr.p2.to_wires_vec());
                ids
            }
        }
        fn encode_p<M: CircuitMode<WireValue = bool>>(
            p: ark_bn254::G1Projective,
            w: &G1Projective,
            cache: &mut M,
        ) {
            let p_m = G1Projective::as_montgomery(p);
            let bits_x =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.x.into_bigint()), Fq::N_BITS)
                    .unwrap();
            let bits_y =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.y.into_bigint()), Fq::N_BITS)
                    .unwrap();
            let bits_z =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.z.into_bigint()), Fq::N_BITS)
                    .unwrap();
            w.x.0
                .iter()
                .zip(bits_x)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            w.y.0
                .iter()
                .zip(bits_y)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            w.z.0
                .iter()
                .zip(bits_z)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for In {
            fn encode(&self, repr: &W, cache: &mut M) {
                encode_p(self.p0, &repr.p0, cache);
                encode_p(self.p1, &repr.p1, cache);
                encode_p(self.p2, &repr.p2, cache);
            }
        }

        let result = CircuitBuilder::streaming_execute::<_, _, Fq12Output>(
            In { p0, p1, p2 },
            10_000,
            |ctx, input| {
                let ps = [input.p0.clone(), input.p1.clone(), input.p2.clone()];
                multi_pairing_const_q(ctx, &ps, &[q0, q1, q2])
            },
        );

        assert_eq!(result.output_value.value, expected_m);
    }

    fn ell(f: &mut ark_bn254::Fq12, coeffs: ark_bn254::Fq6, p: ark_bn254::G1Affine) {
        let mut c0 = coeffs.c0;
        let mut c1 = coeffs.c1;
        let c2 = coeffs.c2;

        c0.mul_assign_by_fp(&p.y);
        c1.mul_assign_by_fp(&p.x);
        f.mul_by_034(&c0, &c1, &c2);
    }

    fn multi_miller_loop(
        ps: Vec<ark_bn254::G1Affine>,
        qs: Vec<ark_bn254::G2Affine>,
    ) -> ark_bn254::Fq12 {
        use std::iter::zip;
        let mut qells = Vec::new();
        for q in qs {
            let qell = ell_coeffs(q);
            qells.push(qell);
        }
        let mut u = Vec::new();
        for i in 0..qells[0].len() {
            let mut x = Vec::new();
            for qell in qells.iter() {
                x.push(qell[i]);
            }
            u.push(x);
        }
        let mut q_ells = u.iter();

        let mut f = ark_bn254::Fq12::ONE;
        for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
            if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
                f.square_in_place();
            }

            let qells_next = q_ells.next().unwrap().clone();
            for (qell_next, p) in zip(qells_next, ps.clone()) {
                ell(&mut f, qell_next, p);
            }

            let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
            if bit == 1 || bit == -1 {
                let qells_next = q_ells.next().unwrap().clone();
                for (qell_next, p) in zip(qells_next, ps.clone()) {
                    ell(&mut f, qell_next, p);
                }
            }
        }

        let qells_next = q_ells.next().unwrap().clone();
        for (qell_next, p) in zip(qells_next, ps.clone()) {
            ell(&mut f, qell_next, p);
        }
        let qells_next = q_ells.next().unwrap().clone();
        for (qell_next, p) in zip(qells_next, ps.clone()) {
            ell(&mut f, qell_next, p);
        }

        f
    }

    #[test]
    fn test_multi_miller_loop_montgomery_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let n = 3;
        let ps = (0..n)
            .map(|_| ark_bn254::G1Affine::rand(&mut prng))
            .collect::<Vec<_>>();
        let qs = (0..n)
            .map(|_| ark_bn254::G2Affine::rand(&mut prng))
            .collect::<Vec<_>>();

        let expected_f = multi_miller_loop(ps.clone(), qs.clone());
        // Circuit computes in Montgomery domain; compare against Montgomery-encoded host result
        let expected_m = Fq12::as_montgomery(expected_f);

        struct MultiMillerInput {
            ps: Vec<ark_bn254::G1Projective>,
            qs: Vec<ark_bn254::G2Projective>,
        }

        struct MultiMillerWires {
            ps: Vec<G1Projective>,
            qs: Vec<G2Projective>,
        }

        impl CircuitInput for MultiMillerInput {
            type WireRepr = MultiMillerWires;

            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                let ps = self
                    .ps
                    .iter()
                    .map(|_| G1Projective::new(&mut issue))
                    .collect();
                let qs = self
                    .qs
                    .iter()
                    .map(|_| G2Projective::new(&mut issue))
                    .collect();
                MultiMillerWires { ps, qs }
            }

            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = Vec::new();
                for p in &repr.ps {
                    ids.extend(p.to_wires_vec());
                }
                for q in &repr.qs {
                    ids.extend(q.to_wires_vec());
                }
                ids
            }
        }

        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for MultiMillerInput {
            fn encode(&self, repr: &MultiMillerWires, cache: &mut M) {
                // Encode ps (G1Projective) in Montgomery form
                for (p, p_wire) in self.ps.iter().zip(&repr.ps) {
                    let p_m = G1Projective::as_montgomery(*p);
                    let bits_x = bits_from_biguint_with_len(
                        &BigUintOutput::from(p_m.x.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    let bits_y = bits_from_biguint_with_len(
                        &BigUintOutput::from(p_m.y.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    let bits_z = bits_from_biguint_with_len(
                        &BigUintOutput::from(p_m.z.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    p_wire
                        .x
                        .0
                        .to_wires_vec()
                        .into_iter()
                        .zip(bits_x)
                        .for_each(|(w, b)| cache.feed_wire(w, b));
                    p_wire
                        .y
                        .0
                        .to_wires_vec()
                        .into_iter()
                        .zip(bits_y)
                        .for_each(|(w, b)| cache.feed_wire(w, b));
                    p_wire
                        .z
                        .0
                        .to_wires_vec()
                        .into_iter()
                        .zip(bits_z)
                        .for_each(|(w, b)| cache.feed_wire(w, b));
                }

                // Encode qs (G2Projective) in Montgomery form
                for (q, q_wire) in self.qs.iter().zip(&repr.qs) {
                    let q_m = G2Projective::as_montgomery(*q);
                    let bits_x_c0 = bits_from_biguint_with_len(
                        &BigUintOutput::from(q_m.x.c0.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    let bits_x_c1 = bits_from_biguint_with_len(
                        &BigUintOutput::from(q_m.x.c1.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    let bits_y_c0 = bits_from_biguint_with_len(
                        &BigUintOutput::from(q_m.y.c0.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    let bits_y_c1 = bits_from_biguint_with_len(
                        &BigUintOutput::from(q_m.y.c1.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    let bits_z_c0 = bits_from_biguint_with_len(
                        &BigUintOutput::from(q_m.z.c0.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    let bits_z_c1 = bits_from_biguint_with_len(
                        &BigUintOutput::from(q_m.z.c1.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();

                    q_wire.x.0[0]
                        .0
                        .to_wires_vec()
                        .into_iter()
                        .zip(bits_x_c0)
                        .for_each(|(w, b)| cache.feed_wire(w, b));
                    q_wire.x.0[1]
                        .0
                        .to_wires_vec()
                        .into_iter()
                        .zip(bits_x_c1)
                        .for_each(|(w, b)| cache.feed_wire(w, b));
                    q_wire.y.0[0]
                        .0
                        .to_wires_vec()
                        .into_iter()
                        .zip(bits_y_c0)
                        .for_each(|(w, b)| cache.feed_wire(w, b));
                    q_wire.y.0[1]
                        .0
                        .to_wires_vec()
                        .into_iter()
                        .zip(bits_y_c1)
                        .for_each(|(w, b)| cache.feed_wire(w, b));
                    q_wire.z.0[0]
                        .0
                        .to_wires_vec()
                        .into_iter()
                        .zip(bits_z_c0)
                        .for_each(|(w, b)| cache.feed_wire(w, b));
                    q_wire.z.0[1]
                        .0
                        .to_wires_vec()
                        .into_iter()
                        .zip(bits_z_c1)
                        .for_each(|(w, b)| cache.feed_wire(w, b));
                }
            }
        }

        let input = MultiMillerInput {
            ps: ps.iter().map(|p| p.into_group()).collect(),
            qs: qs.iter().map(|q| q.into_group()).collect(),
        };

        let result = CircuitBuilder::streaming_execute::<_, _, Fq12Output>(
            input,
            40_000,
            |circuit, wires| multi_miller_loop_montgomery_fast(circuit, &wires.ps, &wires.qs),
        );

        assert_eq!(result.output_value.value, expected_m);
    }

    // Too slow (~13 minutes) for default test runs; enable when benchmarking.
    #[ignore]
    #[test]
    fn test_multi_miller_loop_groth16_evaluate_montgomery_fast_matches_ark_many() {
        // Helper to build expected pre-final-exponentiation value using arkworks' Miller loop
        fn expected_f(
            p1: ark_bn254::G1Projective,
            p2: ark_bn254::G1Projective,
            p3: ark_bn254::G1Projective,
            q1: ark_bn254::G2Affine,
            q2: ark_bn254::G2Affine,
            q3: ark_bn254::G2Projective,
        ) -> ark_bn254::Fq12 {
            // Convert Ps and Q3 to affine for the host-side reference implementation
            let ps = vec![p1.into_affine(), p2.into_affine(), p3.into_affine()];
            let qs = vec![q1, q2, q3.into_affine()];
            multi_miller_loop(ps, qs)
        }

        // Local input/wire structs for streaming execution
        struct In {
            p1: ark_bn254::G1Projective,
            p2: ark_bn254::G1Projective,
            p3: ark_bn254::G1Projective,
            q3: ark_bn254::G2Projective,
        }
        struct W {
            p1: G1Projective,
            p2: G1Projective,
            p3: G1Projective,
            q3: G2Projective,
        }
        impl CircuitInput for In {
            type WireRepr = W;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                W {
                    p1: G1Projective::new(&mut issue),
                    p2: G1Projective::new(&mut issue),
                    p3: G1Projective::new(&mut issue),
                    q3: G2Projective::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = Vec::with_capacity(G1Projective::N_BITS * 3 + G2Projective::N_BITS);
                ids.extend(repr.p1.to_wires_vec());
                ids.extend(repr.p2.to_wires_vec());
                ids.extend(repr.p3.to_wires_vec());
                ids.extend(repr.q3.to_wires_vec());
                ids
            }
        }
        fn encode_p<M: CircuitMode<WireValue = bool>>(
            p: ark_bn254::G1Projective,
            w: &G1Projective,
            cache: &mut M,
        ) {
            let p_m = G1Projective::as_montgomery(p);
            let bits_x =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.x.into_bigint()), Fq::N_BITS)
                    .unwrap();
            let bits_y =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.y.into_bigint()), Fq::N_BITS)
                    .unwrap();
            let bits_z =
                bits_from_biguint_with_len(&BigUintOutput::from(p_m.z.into_bigint()), Fq::N_BITS)
                    .unwrap();
            w.x.0
                .iter()
                .zip(bits_x)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            w.y.0
                .iter()
                .zip(bits_y)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            w.z.0
                .iter()
                .zip(bits_z)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
        }
        fn encode_q<M: CircuitMode<WireValue = bool>>(
            q: ark_bn254::G2Projective,
            w: &G2Projective,
            cache: &mut M,
        ) {
            let q_m = G2Projective::as_montgomery(q);
            let bits_x_c0 = bits_from_biguint_with_len(
                &BigUintOutput::from(q_m.x.c0.into_bigint()),
                Fq::N_BITS,
            )
            .unwrap();
            let bits_x_c1 = bits_from_biguint_with_len(
                &BigUintOutput::from(q_m.x.c1.into_bigint()),
                Fq::N_BITS,
            )
            .unwrap();
            let bits_y_c0 = bits_from_biguint_with_len(
                &BigUintOutput::from(q_m.y.c0.into_bigint()),
                Fq::N_BITS,
            )
            .unwrap();
            let bits_y_c1 = bits_from_biguint_with_len(
                &BigUintOutput::from(q_m.y.c1.into_bigint()),
                Fq::N_BITS,
            )
            .unwrap();
            let bits_z_c0 = bits_from_biguint_with_len(
                &BigUintOutput::from(q_m.z.c0.into_bigint()),
                Fq::N_BITS,
            )
            .unwrap();
            let bits_z_c1 = bits_from_biguint_with_len(
                &BigUintOutput::from(q_m.z.c1.into_bigint()),
                Fq::N_BITS,
            )
            .unwrap();

            w.x.0[0]
                .0
                .to_wires_vec()
                .into_iter()
                .zip(bits_x_c0)
                .for_each(|(w, b)| cache.feed_wire(w, b));
            w.x.0[1]
                .0
                .to_wires_vec()
                .into_iter()
                .zip(bits_x_c1)
                .for_each(|(w, b)| cache.feed_wire(w, b));
            w.y.0[0]
                .0
                .to_wires_vec()
                .into_iter()
                .zip(bits_y_c0)
                .for_each(|(w, b)| cache.feed_wire(w, b));
            w.y.0[1]
                .0
                .to_wires_vec()
                .into_iter()
                .zip(bits_y_c1)
                .for_each(|(w, b)| cache.feed_wire(w, b));
            w.z.0[0]
                .0
                .to_wires_vec()
                .into_iter()
                .zip(bits_z_c0)
                .for_each(|(w, b)| cache.feed_wire(w, b));
            w.z.0[1]
                .0
                .to_wires_vec()
                .into_iter()
                .zip(bits_z_c1)
                .for_each(|(w, b)| cache.feed_wire(w, b));
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for In {
            fn encode(&self, repr: &W, cache: &mut M) {
                encode_p(self.p1, &repr.p1, cache);
                encode_p(self.p2, &repr.p2, cache);
                encode_p(self.p3, &repr.p3, cache);
                encode_q(self.q3, &repr.q3, cache);
            }
        }

        // Exercise several randomized and edge cases
        let mut rng = ChaCha20Rng::seed_from_u64(0xC011EC7);
        for case in 0..4u32 {
            // Select points per case
            let (p1, p2, p3, q1, q2, q3) = match case {
                // Fully random points
                0..=3 => {
                    // Normalize Ps to affine (z=1) before encoding, matching gadget expectations
                    let p1 = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng))
                        .into_affine()
                        .into_group();
                    let p2 = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng))
                        .into_affine()
                        .into_group();
                    let p3 = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng))
                        .into_affine()
                        .into_group();
                    let q1 = random_g2_affine(&mut rng);
                    let q2 = random_g2_affine(&mut rng);
                    // Ensure q3 is affine (z = 1) for mixed-add formulas
                    let q3_aff = random_g2_affine(&mut rng);
                    let q3 = ark_bn254::G2Projective::new(q3_aff.x, q3_aff.y, ark_bn254::Fq2::ONE);
                    (p1, p2, p3, q1, q2, q3)
                }
                // q3 with z = 1 (affine form encoded as projective) to exercise mixed-add friendly path
                _ => {
                    let p1 = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng))
                        .into_affine()
                        .into_group();
                    let p2 = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng))
                        .into_affine()
                        .into_group();
                    let p3 = (ark_bn254::G1Projective::generator() * rnd_fr(&mut rng))
                        .into_affine()
                        .into_group();
                    let q1 = random_g2_affine(&mut rng);
                    let q2 = random_g2_affine(&mut rng);
                    let q3_aff = random_g2_affine(&mut rng);
                    let q3 = ark_bn254::G2Projective::new(q3_aff.x, q3_aff.y, ark_bn254::Fq2::ONE);
                    (p1, p2, p3, q1, q2, q3)
                }
            };

            // Compute host-side expected (Miller loop only) and convert to Montgomery
            let exp = expected_f(p1, p2, p3, q1, q2, q3);
            let expected_m = Fq12::as_montgomery(exp);

            // Build and execute the circuit under test
            let input = In { p1, p2, p3, q3 };
            let result =
                CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 80_000, |ctx, w| {
                    multi_miller_loop_groth16_evaluate_montgomery_fast(
                        ctx, &w.p1, &w.p2, &w.p3, q1, q2, &w.q3,
                    )
                });

            assert_eq!(
                result.output_value.value, expected_m,
                "case {case} mismatch"
            );
        }
    }
}
