use crate::{
    bag::*,
    circuits::{
        bigint::U254,
        bn254::{
            fp254impl::Fp254Impl,
            fq::Fq,
            fq2::Fq2,
            fq12::Fq12,
            g1::G1Affine,
            g2::{G2Affine, G2Projective},
        },
    },
};
use ark_ec::{bn::BnConfig, short_weierstrass::SWCurveConfig};
use ark_ff::{AdditiveGroup, Field};

use std::iter::zip;

pub fn double_in_place(
    r: &mut ark_bn254::G2Projective,
) -> (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2) {
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
    (-h, j.double() + j, i)
}

pub fn double_in_place2(
    r: ark_bn254::G2Projective,
) -> (
    ark_bn254::G2Projective,
    (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2),
) {
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
    (new_r, (-h, j.double() + j, i))
}

pub fn double_in_place_circuit(r: Wires) -> Circuit {
    assert_eq!(r.len(), G2Projective::N_BITS);
    let mut circuit = Circuit::empty();

    let rx = r[0..Fq2::N_BITS].to_vec();
    let ry = r[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
    let rz = r[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

    let mut a = circuit.extend(Fq2::mul(rx.clone(), ry.clone()));
    a = circuit.extend(Fq2::half(a.clone()));
    let b = circuit.extend(Fq2::square(ry.clone()));
    let c = circuit.extend(Fq2::square(rz.clone()));
    let c_triple = circuit.extend(Fq2::triple(c.clone()));
    let e = circuit.extend(Fq2::mul_by_constant(
        c_triple,
        ark_bn254::g2::Config::COEFF_B,
    ));
    let f = circuit.extend(Fq2::triple(e.clone()));
    let mut g = circuit.extend(Fq2::add(b.clone(), f.clone()));
    g = circuit.extend(Fq2::half(g.clone()));
    let ryrz = circuit.extend(Fq2::add(ry.clone(), rz.clone()));
    let ryrzs = circuit.extend(Fq2::square(ryrz.clone()));
    let bc = circuit.extend(Fq2::add(b.clone(), c.clone()));
    let h = circuit.extend(Fq2::sub(ryrzs.clone(), bc.clone()));
    let i = circuit.extend(Fq2::sub(e.clone(), b.clone()));
    let j = circuit.extend(Fq2::square(rx.clone()));
    let es = circuit.extend(Fq2::square(e.clone()));
    let j_triple = circuit.extend(Fq2::triple(j.clone()));
    let bf = circuit.extend(Fq2::sub(b.clone(), f.clone()));
    let new_x = circuit.extend(Fq2::mul(a.clone(), bf.clone()));
    let es_triple = circuit.extend(Fq2::triple(es.clone()));
    let gs = circuit.extend(Fq2::square(g.clone()));
    let new_y = circuit.extend(Fq2::sub(gs.clone(), es_triple.clone()));
    let new_z = circuit.extend(Fq2::mul(b.clone(), h.clone()));
    let hn = circuit.extend(Fq2::neg(h.clone()));

    circuit.add_wires(hn);
    circuit.add_wires(j_triple);
    circuit.add_wires(i);
    circuit.add_wires(new_x);
    circuit.add_wires(new_y);
    circuit.add_wires(new_z);

    circuit
}

pub fn double_in_place_circuit_montgomery(r: Wires) -> Circuit {
    let mut circuit = Circuit::empty();

    let rx = r[0..Fq2::N_BITS].to_vec();
    let ry = r[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
    let rz = r[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

    let mut a = circuit.extend(Fq2::mul_montgomery(rx.clone(), ry.clone()));
    a = circuit.extend(Fq2::half(a.clone()));
    let b = circuit.extend(Fq2::square_montgomery(ry.clone()));
    let c = circuit.extend(Fq2::square_montgomery(rz.clone()));
    let c_triple = circuit.extend(Fq2::triple(c.clone()));
    let e = circuit.extend(Fq2::mul_by_constant_montgomery(
        c_triple,
        Fq2::as_montgomery(ark_bn254::g2::Config::COEFF_B),
    ));
    let f = circuit.extend(Fq2::triple(e.clone()));
    let mut g = circuit.extend(Fq2::add(b.clone(), f.clone()));
    g = circuit.extend(Fq2::half(g.clone()));
    let ryrz = circuit.extend(Fq2::add(ry.clone(), rz.clone()));
    let ryrzs = circuit.extend(Fq2::square_montgomery(ryrz.clone()));
    let bc = circuit.extend(Fq2::add(b.clone(), c.clone()));
    let h = circuit.extend(Fq2::sub(ryrzs.clone(), bc.clone()));
    let i = circuit.extend(Fq2::sub(e.clone(), b.clone()));
    let j = circuit.extend(Fq2::square_montgomery(rx.clone()));
    let es = circuit.extend(Fq2::square_montgomery(e.clone()));
    let j_triple = circuit.extend(Fq2::triple(j.clone()));
    let bf = circuit.extend(Fq2::sub(b.clone(), f.clone()));
    let new_x = circuit.extend(Fq2::mul_montgomery(a.clone(), bf.clone()));
    let es_triple = circuit.extend(Fq2::triple(es.clone()));
    let gs = circuit.extend(Fq2::square_montgomery(g.clone()));
    let new_y = circuit.extend(Fq2::sub(gs.clone(), es_triple.clone()));
    let new_z = circuit.extend(Fq2::mul_montgomery(b.clone(), h.clone()));
    let hn = circuit.extend(Fq2::neg(h.clone()));

    circuit.add_wires(hn);
    circuit.add_wires(j_triple);
    circuit.add_wires(i);
    circuit.add_wires(new_x);
    circuit.add_wires(new_y);
    circuit.add_wires(new_z);

    circuit
}

pub fn double_in_place_evaluate(r: Wires) -> ((Wires, Wires, Wires), Wires, GateCount) {
    let circuit = double_in_place_circuit(r);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    let c0 = circuit.0[0..Fq2::N_BITS].to_vec();
    let c1 = circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
    let c2 = circuit.0[Fq2::N_BITS * 2..Fq2::N_BITS * 3].to_vec();
    let r = circuit.0[Fq2::N_BITS * 3..Fq2::N_BITS * 6].to_vec();
    ((c0, c1, c2), r, n)
}

pub fn double_in_place_evaluate_montgomery(r: Wires) -> ((Wires, Wires, Wires), Wires, GateCount) {
    let circuit = double_in_place_circuit_montgomery(r);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    let c0 = circuit.0[0..Fq2::N_BITS].to_vec();
    let c1 = circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
    let c2 = circuit.0[Fq2::N_BITS * 2..Fq2::N_BITS * 3].to_vec();
    let r = circuit.0[Fq2::N_BITS * 3..Fq2::N_BITS * 6].to_vec();
    ((c0, c1, c2), r, n)
}

pub fn add_in_place(
    r: &mut ark_bn254::G2Projective,
    q: &ark_bn254::G2Affine,
) -> (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2) {
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

    (lambda, -theta, j)
}

pub fn add_in_place2(
    r: ark_bn254::G2Projective,
    q: &ark_bn254::G2Affine,
) -> (
    ark_bn254::G2Projective,
    (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2),
) {
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

    (new_r, (lambda, -theta, j))
}

pub fn add_in_place_circuit(r: Wires, q: Wires) -> Circuit {
    let mut circuit = Circuit::empty();
    assert_eq!(r.len(), G2Projective::N_BITS);
    assert_eq!(q.len(), G2Affine::N_BITS);

    let rx = r[0..Fq2::N_BITS].to_vec();
    let ry = r[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
    let rz = r[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();
    let qx = q[0..Fq2::N_BITS].to_vec();
    let qy = q[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();

    let wires_1 = circuit.extend(Fq2::mul(qy.clone(), rz.clone()));
    let theta = circuit.extend(Fq2::sub(ry.clone(), wires_1.clone()));

    let wires_2 = circuit.extend(Fq2::mul(qx.clone(), rz.clone()));
    let lambda = circuit.extend(Fq2::sub(rx.clone(), wires_2.clone()));

    let c = circuit.extend(Fq2::square(theta.clone()));
    let d = circuit.extend(Fq2::square(lambda.clone()));

    let e = circuit.extend(Fq2::mul(lambda.clone(), d.clone()));

    let f = circuit.extend(Fq2::mul(rz.clone(), c.clone()));

    let g = circuit.extend(Fq2::mul(rx.clone(), d.clone()));

    let wires_3 = circuit.extend(Fq2::add(e.clone(), f.clone()));

    let wires_4 = circuit.extend(Fq2::double(g.clone()));
    let h = circuit.extend(Fq2::sub(wires_3.clone(), wires_4.clone()));

    let neg_theta = circuit.extend(Fq2::neg(theta.clone()));

    let wires_5 = circuit.extend(Fq2::mul(theta.clone(), qx.clone()));
    let wires_6 = circuit.extend(Fq2::mul(lambda.clone(), qy.clone()));
    let j = circuit.extend(Fq2::sub(wires_5.clone(), wires_6.clone()));

    let mut new_r = circuit.extend(Fq2::mul(lambda.clone(), h.clone()));
    let wires_7 = circuit.extend(Fq2::sub(g.clone(), h.clone()));
    let wires_8 = circuit.extend(Fq2::mul(theta.clone(), wires_7.clone()));
    let wires_9 = circuit.extend(Fq2::mul(e.clone(), ry.clone()));
    let new_r_y = circuit.extend(Fq2::sub(wires_8.clone(), wires_9.clone()));
    new_r.extend(new_r_y);
    let new_r_z = circuit.extend(Fq2::mul(rz.clone(), e.clone()));
    new_r.extend(new_r_z);

    circuit.add_wires(lambda);
    circuit.add_wires(neg_theta);
    circuit.add_wires(j);
    circuit.add_wires(new_r);
    circuit
}

pub fn add_in_place_circuit_montgomery(r: Wires, q: Wires) -> Circuit {
    let mut circuit = Circuit::empty();
    assert_eq!(r.len(), G2Projective::N_BITS);
    assert_eq!(q.len(), G2Affine::N_BITS);

    let rx = r[0..Fq2::N_BITS].to_vec();
    let ry = r[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
    let rz = r[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();
    let qx = q[0..Fq2::N_BITS].to_vec();
    let qy = q[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();

    let wires_1 = circuit.extend(Fq2::mul_montgomery(qy.clone(), rz.clone()));
    let theta = circuit.extend(Fq2::sub(ry.clone(), wires_1.clone()));

    let wires_2 = circuit.extend(Fq2::mul_montgomery(qx.clone(), rz.clone()));
    let lambda = circuit.extend(Fq2::sub(rx.clone(), wires_2.clone()));

    let c = circuit.extend(Fq2::square_montgomery(theta.clone()));
    let d = circuit.extend(Fq2::square_montgomery(lambda.clone()));

    let e = circuit.extend(Fq2::mul_montgomery(lambda.clone(), d.clone()));

    let f = circuit.extend(Fq2::mul_montgomery(rz.clone(), c.clone()));

    let g = circuit.extend(Fq2::mul_montgomery(rx.clone(), d.clone()));

    let wires_3 = circuit.extend(Fq2::add(e.clone(), f.clone()));

    let wires_4 = circuit.extend(Fq2::double(g.clone()));
    let h = circuit.extend(Fq2::sub(wires_3.clone(), wires_4.clone()));

    let neg_theta = circuit.extend(Fq2::neg(theta.clone()));

    let wires_5 = circuit.extend(Fq2::mul_montgomery(theta.clone(), qx.clone()));
    let wires_6 = circuit.extend(Fq2::mul_montgomery(lambda.clone(), qy.clone()));
    let j = circuit.extend(Fq2::sub(wires_5.clone(), wires_6.clone()));

    let mut new_r = circuit.extend(Fq2::mul_montgomery(lambda.clone(), h.clone()));
    let wires_7 = circuit.extend(Fq2::sub(g.clone(), h.clone()));
    let wires_8 = circuit.extend(Fq2::mul_montgomery(theta.clone(), wires_7.clone()));
    let wires_9 = circuit.extend(Fq2::mul_montgomery(e.clone(), ry.clone()));
    let new_r_y = circuit.extend(Fq2::sub(wires_8.clone(), wires_9.clone()));
    new_r.extend(new_r_y);
    let new_r_z = circuit.extend(Fq2::mul_montgomery(rz.clone(), e.clone()));
    new_r.extend(new_r_z);

    circuit.add_wires(lambda);
    circuit.add_wires(neg_theta);
    circuit.add_wires(j);
    circuit.add_wires(new_r);
    circuit
}

pub fn add_in_place_evaluate(r: Wires, q: Wires) -> ((Wires, Wires, Wires), Wires, GateCount) {
    let circuit = add_in_place_circuit(r, q);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    let c0 = circuit.0[0..Fq2::N_BITS].to_vec();
    let c1 = circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
    let c2 = circuit.0[Fq2::N_BITS * 2..Fq2::N_BITS * 3].to_vec();
    let r = circuit.0[Fq2::N_BITS * 3..Fq2::N_BITS * 6].to_vec();
    ((c0, c1, c2), r, n)
}

pub fn add_in_place_evaluate_montgomery(
    r: Wires,
    q: Wires,
) -> ((Wires, Wires, Wires), Wires, GateCount) {
    let circuit = add_in_place_circuit_montgomery(r, q);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    let c0 = circuit.0[0..Fq2::N_BITS].to_vec();
    let c1 = circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
    let c2 = circuit.0[Fq2::N_BITS * 2..Fq2::N_BITS * 3].to_vec();
    let r = circuit.0[Fq2::N_BITS * 3..Fq2::N_BITS * 6].to_vec();
    ((c0, c1, c2), r, n)
}

pub fn mul_by_char(r: ark_bn254::G2Affine) -> ark_bn254::G2Affine {
    let mut s = r;
    s.x = s.x.frobenius_map(1);
    s.x *= &ark_bn254::Config::TWIST_MUL_BY_Q_X;
    s.y = s.y.frobenius_map(1);
    s.y *= &ark_bn254::Config::TWIST_MUL_BY_Q_Y;
    s
}

pub fn mul_by_char_circuit(r: Wires) -> Circuit {
    let mut circuit = Circuit::empty();
    let r_x = r[0..Fq2::N_BITS].to_vec();
    let r_y = r[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();

    let mut s_x = circuit.extend(Fq2::frobenius(r_x, 1));
    s_x = circuit.extend(Fq2::mul_by_constant(
        s_x,
        ark_bn254::Config::TWIST_MUL_BY_Q_X,
    ));
    let mut s_y = circuit.extend(Fq2::frobenius(r_y, 1));
    s_y = circuit.extend(Fq2::mul_by_constant(
        s_y,
        ark_bn254::Config::TWIST_MUL_BY_Q_Y,
    ));
    circuit.add_wires(s_x);
    circuit.add_wires(s_y);
    circuit
}

pub fn mul_by_char_circuit_montgomery(r: Wires) -> Circuit {
    let mut circuit = Circuit::empty();
    let r_x = r[0..Fq2::N_BITS].to_vec();
    let r_y = r[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();

    let mut s_x = circuit.extend(Fq2::frobenius_montgomery(r_x, 1));
    s_x = circuit.extend(Fq2::mul_by_constant_montgomery(
        s_x,
        Fq2::as_montgomery(ark_bn254::Config::TWIST_MUL_BY_Q_X),
    ));
    let mut s_y = circuit.extend(Fq2::frobenius_montgomery(r_y, 1));
    s_y = circuit.extend(Fq2::mul_by_constant_montgomery(
        s_y,
        Fq2::as_montgomery(ark_bn254::Config::TWIST_MUL_BY_Q_Y),
    ));
    circuit.add_wires(s_x);
    circuit.add_wires(s_y);
    circuit
}

pub fn mul_by_char_evaluate(r: Wires) -> (Wires, GateCount) {
    let circuit = mul_by_char_circuit(r);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}

pub fn mul_by_char_evaluate_montgomery(r: Wires) -> (Wires, GateCount) {
    let circuit = mul_by_char_circuit_montgomery(r);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}

pub fn g2_affine_neg_evaluate(r: Wires) -> (Wires, GateCount) {
    let mut circuit = Circuit::empty();
    let x = r[0..Fq2::N_BITS].to_vec();
    let y = r[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
    let new_y = circuit.extend(Fq2::neg(y));
    circuit.add_wires(x);
    circuit.add_wires(new_y);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}

pub fn ell_coeffs(q: ark_bn254::G2Affine) -> Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)> {
    let mut ellc = Vec::new();
    let mut r = ark_bn254::G2Projective {
        x: q.x,
        y: q.y,
        z: ark_bn254::Fq2::ONE,
    };
    let neg_q = -q;
    for bit in ark_bn254::Config::ATE_LOOP_COUNT.iter().rev().skip(1) {
        ellc.push(double_in_place(&mut r));

        match bit {
            1 => {
                ellc.push(add_in_place(&mut r, &q));
            }
            -1 => {
                ellc.push(add_in_place(&mut r, &neg_q));
            }
            _ => {}
        }
    }
    let q1 = mul_by_char(q);
    let mut q2 = mul_by_char(q1);
    q2.y = -q2.y;
    ellc.push(add_in_place(&mut r, &q1));
    ellc.push(add_in_place(&mut r, &q2));
    ellc
}

pub fn ell_coeffs_evaluate_fast(q: Wires) -> (Vec<(Wires, Wires, Wires)>, GateCount) {
    let mut gate_count = GateCount::zero();
    let mut ellc = Vec::new();
    let mut r = Vec::new();
    r.extend_from_slice(&q[0..Fq2::N_BITS]);
    r.extend_from_slice(&q[Fq2::N_BITS..2 * Fq2::N_BITS]);
    r.extend_from_slice(&Fq2::wires_set(ark_bn254::Fq2::from(1)));

    let (neg_q, gc) = g2_affine_neg_evaluate(q.clone());
    gate_count += gc;
    for bit in ark_bn254::Config::ATE_LOOP_COUNT.iter().rev().skip(1) {
        // let (coeffs, new_r, gc) = double_in_place_evaluate(r);
        // ellc.push(coeffs);
        // gate_count += gc;
        // r = new_r;
        let ((new_r, coeffs), gc) = (
            double_in_place2(G2Projective::from_wires_unchecked(r)),
            GateCount::double_in_place(),
        );
        ellc.push((
            Fq2::wires_set(coeffs.0),
            Fq2::wires_set(coeffs.1),
            Fq2::wires_set(coeffs.2),
        ));
        gate_count += gc;
        r = G2Projective::wires_set(new_r);

        match bit {
            1 => {
                // let (coeffs, new_r, gc) = add_in_place_evaluate(r, q.clone());
                // ellc.push(coeffs);
                // gate_count += gc;
                // r = new_r;
                let ((new_r, coeffs), gc) = (
                    add_in_place2(
                        G2Projective::from_wires_unchecked(r),
                        &G2Affine::from_wires(q.clone()),
                    ),
                    GateCount::add_in_place(),
                );
                ellc.push((
                    Fq2::wires_set(coeffs.0),
                    Fq2::wires_set(coeffs.1),
                    Fq2::wires_set(coeffs.2),
                ));
                gate_count += gc;
                r = G2Projective::wires_set(new_r);
            }
            -1 => {
                // let (coeffs, new_r, gc) = add_in_place_evaluate(r, neg_q.clone());
                // ellc.push(coeffs);
                // gate_count += gc;
                // r = new_r;
                let ((new_r, coeffs), gc) = (
                    add_in_place2(
                        G2Projective::from_wires_unchecked(r),
                        &G2Affine::from_wires(neg_q.clone()),
                    ),
                    GateCount::add_in_place(),
                );
                ellc.push((
                    Fq2::wires_set(coeffs.0),
                    Fq2::wires_set(coeffs.1),
                    Fq2::wires_set(coeffs.2),
                ));
                gate_count += gc;
                r = G2Projective::wires_set(new_r);
            }
            _ => {}
        }
    }
    let (q1, gc) = mul_by_char_evaluate(q.clone());
    gate_count += gc;
    let (mut q2, gc) = mul_by_char_evaluate(q1.clone());
    gate_count += gc;
    let (new_q2, gc) = g2_affine_neg_evaluate(q2);
    gate_count += gc;
    q2 = new_q2;

    // let (coeffs, new_r, gc) = add_in_place_evaluate(r, q1);
    // gate_count += gc;
    // ellc.push(coeffs);
    // r = new_r;
    let ((new_r, coeffs), gc) = (
        add_in_place2(
            G2Projective::from_wires_unchecked(r),
            &G2Affine::from_wires(q1),
        ),
        GateCount::add_in_place(),
    );
    ellc.push((
        Fq2::wires_set(coeffs.0),
        Fq2::wires_set(coeffs.1),
        Fq2::wires_set(coeffs.2),
    ));
    gate_count += gc;
    r = G2Projective::wires_set(new_r);

    // let (coeffs, _new_r, gc) = add_in_place_evaluate(r, q2);
    // gate_count += gc;
    // ellc.push(coeffs);
    // // r = new_r;
    let ((_new_r, coeffs), gc) = (
        add_in_place2(
            G2Projective::from_wires_unchecked(r),
            &G2Affine::from_wires(q2),
        ),
        GateCount::add_in_place(),
    );
    ellc.push((
        Fq2::wires_set(coeffs.0),
        Fq2::wires_set(coeffs.1),
        Fq2::wires_set(coeffs.2),
    ));
    gate_count += gc;
    // r = G2Projective::wires_set(new_r);

    (ellc, gate_count)
}

pub fn ell_coeffs_evaluate_montgomery_fast(q: Wires) -> (Vec<(Wires, Wires, Wires)>, GateCount) {
    let mut gate_count = GateCount::zero();
    let mut ellc = Vec::new();
    let mut r = Vec::new();
    r.extend_from_slice(&q[0..Fq2::N_BITS]);
    r.extend_from_slice(&q[Fq2::N_BITS..2 * Fq2::N_BITS]);
    r.extend_from_slice(&Fq2::wires_set_montgomery(ark_bn254::Fq2::from(1)));

    let (neg_q, gc) = g2_affine_neg_evaluate(q.clone());
    gate_count += gc;
    for bit in ark_bn254::Config::ATE_LOOP_COUNT.iter().rev().skip(1) {
        // let (coeffs, new_r, gc) = double_in_place_evaluate_montgomery(r);
        // ellc.push(coeffs);
        // gate_count += gc;
        // r = new_r;
        let ((new_r, coeffs), gc) = (
            double_in_place2(G2Projective::from_montgomery_wires_unchecked(r)),
            GateCount::double_in_place_montgomery(),
        );
        ellc.push((
            Fq2::wires_set_montgomery(coeffs.0),
            Fq2::wires_set_montgomery(coeffs.1),
            Fq2::wires_set_montgomery(coeffs.2),
        ));
        gate_count += gc;
        r = G2Projective::wires_set_montgomery(new_r);

        match bit {
            1 => {
                // let (coeffs, new_r, gc) = add_in_place_evaluate_montgomery(r, q.clone());
                // ellc.push(coeffs);
                // gate_count += gc;
                // r = new_r;
                let ((new_r, coeffs), gc) = (
                    add_in_place2(
                        G2Projective::from_montgomery_wires_unchecked(r),
                        &G2Affine::from_montgomery_wires_unchecked(q.clone()),
                    ),
                    GateCount::add_in_place_montgomery(),
                );
                ellc.push((
                    Fq2::wires_set_montgomery(coeffs.0),
                    Fq2::wires_set_montgomery(coeffs.1),
                    Fq2::wires_set_montgomery(coeffs.2),
                ));
                gate_count += gc;
                r = G2Projective::wires_set_montgomery(new_r);
            }
            -1 => {
                // let (coeffs, new_r, gc) = add_in_place_evaluate_montgomery(r, neg_q.clone());
                // ellc.push(coeffs);
                // gate_count += gc;
                // r = new_r;
                let ((new_r, coeffs), gc) = (
                    add_in_place2(
                        G2Projective::from_montgomery_wires_unchecked(r),
                        &G2Affine::from_montgomery_wires_unchecked(neg_q.clone()),
                    ),
                    GateCount::add_in_place_montgomery(),
                );
                ellc.push((
                    Fq2::wires_set_montgomery(coeffs.0),
                    Fq2::wires_set_montgomery(coeffs.1),
                    Fq2::wires_set_montgomery(coeffs.2),
                ));
                gate_count += gc;
                r = G2Projective::wires_set_montgomery(new_r);
            }
            _ => {}
        }
    }
    let (q1, gc) = mul_by_char_evaluate_montgomery(q.clone());
    gate_count += gc;
    let (mut q2, gc) = mul_by_char_evaluate_montgomery(q1.clone());
    gate_count += gc;
    let (new_q2, gc) = g2_affine_neg_evaluate(q2);
    gate_count += gc;
    q2 = new_q2;

    // let (coeffs, new_r, gc) = add_in_place_evaluate_montgomery(r, q1);
    // gate_count += gc;
    // ellc.push(coeffs);
    // r = new_r;
    let ((new_r, coeffs), gc) = (
        add_in_place2(
            G2Projective::from_montgomery_wires_unchecked(r),
            &G2Affine::from_montgomery_wires_unchecked(q1),
        ),
        GateCount::add_in_place_montgomery(),
    );
    ellc.push((
        Fq2::wires_set_montgomery(coeffs.0),
        Fq2::wires_set_montgomery(coeffs.1),
        Fq2::wires_set_montgomery(coeffs.2),
    ));
    gate_count += gc;
    r = G2Projective::wires_set_montgomery(new_r);

    // let (coeffs, _new_r, gc) = add_in_place_evaluate_montgomery(r, q2);
    // gate_count += gc;
    // ellc.push(coeffs);
    // // r = new_r;
    let ((_new_r, coeffs), gc) = (
        add_in_place2(
            G2Projective::from_montgomery_wires_unchecked(r),
            &G2Affine::from_montgomery_wires_unchecked(q2),
        ),
        GateCount::add_in_place_montgomery(),
    );
    ellc.push((
        Fq2::wires_set_montgomery(coeffs.0),
        Fq2::wires_set_montgomery(coeffs.1),
        Fq2::wires_set_montgomery(coeffs.2),
    ));
    gate_count += gc;
    // r = G2Projective::wires_set(new_r);

    (ellc, gate_count)
}

pub fn ell(
    f: &mut ark_bn254::Fq12,
    coeffs: (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2),
    p: ark_bn254::G1Affine,
) {
    let mut c0 = coeffs.0;
    let mut c1 = coeffs.1;
    let c2 = coeffs.2;

    c0.mul_assign_by_fp(&p.y);
    c1.mul_assign_by_fp(&p.x);
    f.mul_by_034(&c0, &c1, &c2);
}

pub fn ell2(
    f: ark_bn254::Fq12,
    coeffs: (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2),
    p: ark_bn254::G1Affine,
) -> ark_bn254::Fq12 {
    let mut new_f = f;
    let mut c0 = coeffs.0;
    let mut c1 = coeffs.1;
    let c2 = coeffs.2;

    c0.mul_assign_by_fp(&p.y);
    c1.mul_assign_by_fp(&p.x);
    new_f.mul_by_034(&c0, &c1, &c2);
    new_f
}

pub fn ell_circuit(f: Wires, coeffs: (Wires, Wires, Wires), p: Wires) -> Circuit {
    let mut circuit = Circuit::empty();
    let c0 = coeffs.0;
    let c1 = coeffs.1;
    let c2 = coeffs.2;

    let px = p[0..Fq::N_BITS].to_vec();
    let py = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

    let new_c0 = circuit.extend(Fq2::mul_by_fq(c0, py));
    let new_c1 = circuit.extend(Fq2::mul_by_fq(c1, px));
    let new_f = circuit.extend(Fq12::mul_by_034(f, new_c0, new_c1, c2));

    circuit.add_wires(new_f);
    circuit
}

pub fn ell_circuit_montgomery(f: Wires, coeffs: (Wires, Wires, Wires), p: Wires) -> Circuit {
    let mut circuit = Circuit::empty();
    let c0 = coeffs.0;
    let c1 = coeffs.1;
    let c2 = coeffs.2;

    let px = p[0..Fq::N_BITS].to_vec();
    let py = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

    let new_c0 = circuit.extend(Fq2::mul_by_fq_montgomery(c0, py));
    let new_c1 = circuit.extend(Fq2::mul_by_fq_montgomery(c1, px));
    let new_f = circuit.extend(Fq12::mul_by_034_montgomery(f, new_c0, new_c1, c2));

    circuit.add_wires(new_f);
    circuit
}

pub fn ell_evaluate(f: Wires, coeffs: (Wires, Wires, Wires), p: Wires) -> (Wires, GateCount) {
    let circuit = ell_circuit(f, coeffs, p);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}

pub fn ell_evaluate_montgomery(
    f: Wires,
    coeffs: (Wires, Wires, Wires),
    p: Wires,
) -> (Wires, GateCount) {
    let circuit = ell_circuit_montgomery(f, coeffs, p);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}

pub fn ell_by_constant_circuit(
    f: Wires,
    coeffs: (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2),
    p: Wires,
) -> Circuit {
    let mut circuit = Circuit::empty();
    let c0 = coeffs.0;
    let c1 = coeffs.1;
    let c2 = coeffs.2;

    let px = p[0..Fq::N_BITS].to_vec();
    let py = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

    let new_c0 = circuit.extend(Fq2::mul_constant_by_fq(c0, py));
    let new_c1 = circuit.extend(Fq2::mul_constant_by_fq(c1, px));
    let new_f = circuit.extend(Fq12::mul_by_034_constant4(f, new_c0, new_c1, c2));

    circuit.add_wires(new_f);
    circuit
}

pub fn ell_by_constant_circuit_montgomery(
    f: Wires,
    coeffs: (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2),
    p: Wires,
) -> Circuit {
    let mut circuit = Circuit::empty();
    let c0 = coeffs.0;
    let c1 = coeffs.1;
    let c2 = coeffs.2;

    let px = p[0..Fq::N_BITS].to_vec();
    let py = p[Fq::N_BITS..2 * Fq::N_BITS].to_vec();

    let new_c0 = circuit.extend(Fq2::mul_constant_by_fq_montgomery(c0, py));
    let new_c1 = circuit.extend(Fq2::mul_constant_by_fq_montgomery(c1, px));
    let new_f = circuit.extend(Fq12::mul_by_034_constant4_montgomery(f, new_c0, new_c1, c2));

    circuit.add_wires(new_f);
    circuit
}

pub fn ell_by_constant_evaluate(
    f: Wires,
    coeffs: (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2),
    p: Wires,
) -> (Wires, GateCount) {
    let circuit = ell_by_constant_circuit(f, coeffs, p);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}

pub fn ell_by_constant_evaluate_montgomery(
    f: Wires,
    coeffs: (ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2),
    p: Wires,
) -> (Wires, GateCount) {
    let circuit = ell_by_constant_circuit_montgomery(f, coeffs, p);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}

pub fn miller_loop(p: ark_bn254::G1Affine, q: ark_bn254::G2Affine) -> ark_bn254::Fq12 {
    let qell = ell_coeffs(q);
    let mut q_ell = qell.iter();

    let mut f = ark_bn254::Fq12::ONE;
    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            f.square_in_place();
        }

        ell(&mut f, *q_ell.next().unwrap(), p);

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            ell(&mut f, *q_ell.next().unwrap(), p)
        }
    }

    ell(&mut f, *q_ell.next().unwrap(), p);
    ell(&mut f, *q_ell.next().unwrap(), p);

    f
}

pub fn miller_loop_evaluate_fast(p: Wires, q: Wires) -> (Wires, GateCount) {
    let mut gate_count = GateCount::zero();
    let (qell, gc) = ell_coeffs_evaluate_fast(q);
    gate_count += gc;
    let mut q_ell = qell.iter();

    let mut f = Fq12::wires_set(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            let (new_f, gc) = (
                Fq12::wires_set(Fq12::from_wires(f).square()),
                GateCount::fq12_square(),
            ); // Fq12::square_evaluate(f);
            f = new_f;
            gate_count += gc;
        }

        let qell_next = q_ell.next().unwrap().clone();
        let (new_f, gc) = (
            Fq12::wires_set(ell2(
                Fq12::from_wires(f),
                (
                    Fq2::from_wires(qell_next.0),
                    Fq2::from_wires(qell_next.1),
                    Fq2::from_wires(qell_next.2),
                ),
                G1Affine::from_wires(p.clone()),
            )),
            GateCount::ell(),
        ); // ell_evaluate(f, q_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let qell_next = q_ell.next().unwrap().clone();
            let (new_f, gc) = (
                Fq12::wires_set(ell2(
                    Fq12::from_wires(f),
                    (
                        Fq2::from_wires(qell_next.0),
                        Fq2::from_wires(qell_next.1),
                        Fq2::from_wires(qell_next.2),
                    ),
                    G1Affine::from_wires(p.clone()),
                )),
                GateCount::ell(),
            ); // ell_evaluate(f, q_ell.next().unwrap().clone(), p.clone());
            f = new_f;
            gate_count += gc;
        }
    }

    let qell_next = q_ell.next().unwrap().clone();
    let (new_f, gc) = (
        Fq12::wires_set(ell2(
            Fq12::from_wires(f),
            (
                Fq2::from_wires(qell_next.0),
                Fq2::from_wires(qell_next.1),
                Fq2::from_wires(qell_next.2),
            ),
            G1Affine::from_wires(p.clone()),
        )),
        GateCount::ell(),
    ); // ell_evaluate(f, q_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;
    let qell_next = q_ell.next().unwrap().clone();
    let (new_f, gc) = (
        Fq12::wires_set(ell2(
            Fq12::from_wires(f),
            (
                Fq2::from_wires(qell_next.0),
                Fq2::from_wires(qell_next.1),
                Fq2::from_wires(qell_next.2),
            ),
            G1Affine::from_wires(p.clone()),
        )),
        GateCount::ell(),
    ); // ell_evaluate(f, q_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    (f, gate_count)
}

pub fn miller_loop_evaluate_montgomery_fast(p: Wires, q: Wires) -> (Wires, GateCount) {
    let mut gate_count = GateCount::zero();
    let (qell, gc) = ell_coeffs_evaluate_montgomery_fast(q);
    gate_count += gc;
    let mut q_ell = qell.iter();

    let mut f = Fq12::wires_set_montgomery(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            let (new_f, gc) = (
                Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(f).square()),
                GateCount::fq12_square_montgomery(),
            ); // Fq12::square_evaluate_montgomery(f);
            f = new_f;
            gate_count += gc;
        }

        let qell_next = q_ell.next().unwrap().clone();
        let (new_f, gc) = (
            Fq12::wires_set_montgomery(ell2(
                Fq12::from_montgomery_wires(f),
                (
                    Fq2::from_montgomery_wires(qell_next.0),
                    Fq2::from_montgomery_wires(qell_next.1),
                    Fq2::from_montgomery_wires(qell_next.2),
                ),
                G1Affine::from_montgomery_wires_unchecked(p.clone()),
            )),
            GateCount::ell_montgomery(),
        ); // ell_evaluate_montgomery(f, q_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let qell_next = q_ell.next().unwrap().clone();
            let (new_f, gc) = (
                Fq12::wires_set_montgomery(ell2(
                    Fq12::from_montgomery_wires(f),
                    (
                        Fq2::from_montgomery_wires(qell_next.0),
                        Fq2::from_montgomery_wires(qell_next.1),
                        Fq2::from_montgomery_wires(qell_next.2),
                    ),
                    G1Affine::from_montgomery_wires_unchecked(p.clone()),
                )),
                GateCount::ell_montgomery(),
            ); // ell_evaluate_montgomery(f, q_ell.next().unwrap().clone(), p.clone());
            f = new_f;
            gate_count += gc;
        }
    }

    let qell_next = q_ell.next().unwrap().clone();
    let (new_f, gc) = (
        Fq12::wires_set_montgomery(ell2(
            Fq12::from_montgomery_wires(f),
            (
                Fq2::from_montgomery_wires(qell_next.0),
                Fq2::from_montgomery_wires(qell_next.1),
                Fq2::from_montgomery_wires(qell_next.2),
            ),
            G1Affine::from_montgomery_wires_unchecked(p.clone()),
        )),
        GateCount::ell_montgomery(),
    ); // ell_evaluate_montgomery(f, q_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;
    let qell_next = q_ell.next().unwrap().clone();
    let (new_f, gc) = (
        Fq12::wires_set_montgomery(ell2(
            Fq12::from_montgomery_wires(f),
            (
                Fq2::from_montgomery_wires(qell_next.0),
                Fq2::from_montgomery_wires(qell_next.1),
                Fq2::from_montgomery_wires(qell_next.2),
            ),
            G1Affine::from_montgomery_wires_unchecked(p.clone()),
        )),
        GateCount::ell_montgomery(),
    ); // ell_evaluate_montgomery(f, q_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    (f, gate_count)
}

pub fn multi_miller_loop(
    ps: Vec<ark_bn254::G1Affine>,
    qs: Vec<ark_bn254::G2Affine>,
) -> ark_bn254::Fq12 {
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

pub fn multi_miller_loop_evaluate_fast(ps: Vec<Wires>, qs: Vec<Wires>) -> (Wires, GateCount) {
    let mut gate_count = GateCount::zero();
    let mut qells = Vec::new();
    for q in qs {
        let (qell, gc) = ell_coeffs_evaluate_fast(q);
        gate_count += gc;
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

    let mut f = Fq12::wires_set(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            let (new_f, gc) = (
                Fq12::wires_set(Fq12::from_wires(f).square()),
                GateCount::fq12_square(),
            ); // Fq12::square_evaluate(f);
            f = new_f;
            gate_count += gc;
        }

        let qells_next = q_ells.next().unwrap().clone();
        for (qell_next, p) in zip(qells_next, ps.clone()) {
            let (new_f, gc) = (
                Fq12::wires_set(ell2(
                    Fq12::from_wires(f),
                    (
                        Fq2::from_wires(qell_next.0),
                        Fq2::from_wires(qell_next.1),
                        Fq2::from_wires(qell_next.2),
                    ),
                    G1Affine::from_wires(p.clone()),
                )),
                GateCount::ell(),
            ); // ell_evaluate(f, q_ell.next().unwrap().clone(), p.clone());
            f = new_f;
            gate_count += gc;
        }

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let qells_next = q_ells.next().unwrap().clone();
            for (qell_next, p) in zip(qells_next, ps.clone()) {
                let (new_f, gc) = (
                    Fq12::wires_set(ell2(
                        Fq12::from_wires(f),
                        (
                            Fq2::from_wires(qell_next.0),
                            Fq2::from_wires(qell_next.1),
                            Fq2::from_wires(qell_next.2),
                        ),
                        G1Affine::from_wires(p.clone()),
                    )),
                    GateCount::ell(),
                ); // ell_evaluate(f, q_ell.next().unwrap().clone(), p.clone());
                f = new_f;
                gate_count += gc;
            }
        }
    }

    let qells_next = q_ells.next().unwrap().clone();
    for (qell_next, p) in zip(qells_next, ps.clone()) {
        let (new_f, gc) = (
            Fq12::wires_set(ell2(
                Fq12::from_wires(f),
                (
                    Fq2::from_wires(qell_next.0),
                    Fq2::from_wires(qell_next.1),
                    Fq2::from_wires(qell_next.2),
                ),
                G1Affine::from_wires(p.clone()),
            )),
            GateCount::ell(),
        ); // ell_evaluate(f, q_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;
    }
    let qells_next = q_ells.next().unwrap().clone();
    for (qell_next, p) in zip(qells_next, ps.clone()) {
        let (new_f, gc) = (
            Fq12::wires_set(ell2(
                Fq12::from_wires(f),
                (
                    Fq2::from_wires(qell_next.0),
                    Fq2::from_wires(qell_next.1),
                    Fq2::from_wires(qell_next.2),
                ),
                G1Affine::from_wires(p.clone()),
            )),
            GateCount::ell(),
        ); // ell_evaluate(f, q_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;
    }
    (f, gate_count)
}

pub fn multi_miller_loop_evaluate_montgomery_fast(
    ps: Vec<Wires>,
    qs: Vec<Wires>,
) -> (Wires, GateCount) {
    let mut gate_count = GateCount::zero();
    let mut qells = Vec::new();
    for q in qs {
        let (qell, gc) = ell_coeffs_evaluate_montgomery_fast(q);
        gate_count += gc;
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

    let mut f = Fq12::wires_set_montgomery(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            let (new_f, gc) = (
                Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(f).square()),
                GateCount::fq12_square_montgomery(),
            ); // Fq12::square_evaluate_montgomery(f);
            f = new_f;
            gate_count += gc;
        }

        let qells_next = q_ells.next().unwrap().clone();
        for (qell_next, p) in zip(qells_next, ps.clone()) {
            let (new_f, gc) = (
                Fq12::wires_set_montgomery(ell2(
                    Fq12::from_montgomery_wires(f),
                    (
                        Fq2::from_montgomery_wires(qell_next.0),
                        Fq2::from_montgomery_wires(qell_next.1),
                        Fq2::from_montgomery_wires(qell_next.2),
                    ),
                    G1Affine::from_montgomery_wires_unchecked(p.clone()),
                )),
                GateCount::ell_montgomery(),
            ); // ell_evaluate_montgomery(f, q_ell.next().unwrap().clone(), p.clone());
            f = new_f;
            gate_count += gc;
        }

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let qells_next = q_ells.next().unwrap().clone();
            for (qell_next, p) in zip(qells_next, ps.clone()) {
                let (new_f, gc) = (
                    Fq12::wires_set_montgomery(ell2(
                        Fq12::from_montgomery_wires(f),
                        (
                            Fq2::from_montgomery_wires(qell_next.0),
                            Fq2::from_montgomery_wires(qell_next.1),
                            Fq2::from_montgomery_wires(qell_next.2),
                        ),
                        G1Affine::from_montgomery_wires_unchecked(p.clone()),
                    )),
                    GateCount::ell_montgomery(),
                ); // ell_evaluate_montgomery(f, q_ell.next().unwrap().clone(), p.clone());
                f = new_f;
                gate_count += gc;
            }
        }
    }

    let qells_next = q_ells.next().unwrap().clone();
    for (qell_next, p) in zip(qells_next, ps.clone()) {
        let (new_f, gc) = (
            Fq12::wires_set_montgomery(ell2(
                Fq12::from_montgomery_wires(f),
                (
                    Fq2::from_montgomery_wires(qell_next.0),
                    Fq2::from_montgomery_wires(qell_next.1),
                    Fq2::from_montgomery_wires(qell_next.2),
                ),
                G1Affine::from_montgomery_wires_unchecked(p.clone()),
            )),
            GateCount::ell_montgomery(),
        ); // ell_evaluate_montgomery(f, q_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;
    }
    let qells_next = q_ells.next().unwrap().clone();
    for (qell_next, p) in zip(qells_next, ps.clone()) {
        let (new_f, gc) = (
            Fq12::wires_set_montgomery(ell2(
                Fq12::from_montgomery_wires(f),
                (
                    Fq2::from_montgomery_wires(qell_next.0),
                    Fq2::from_montgomery_wires(qell_next.1),
                    Fq2::from_montgomery_wires(qell_next.2),
                ),
                G1Affine::from_montgomery_wires_unchecked(p.clone()),
            )),
            GateCount::ell_montgomery(),
        ); // ell_evaluate_montgomery(f, q_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;
    }
    (f, gate_count)
}

/* 
// Deserialize a compressed G1 point in the circuit
pub fn deserialize_compressed_g1_circuit(p_c: Wires, y_flag: Wirex) -> (Wires, GateCount) {
    let mut circuit = Circuit::empty();

    let x = p_c[0..Fq::N_BITS].to_vec();

    // calculate y
    let x2 = circuit.extend(Fq::square_montgomery(x.clone()));
    let x3 = circuit.extend(Fq::mul_montgomery(x2, x.clone()));

    let y2 = circuit.extend(Fq::add(
        x3,
        Fq::wires_set_montgomery(ark_bn254::g1::Config::COEFF_B),
    ));
    let y = circuit.extend(Fq::sqrt_montgomery(y2));

    let neg_y = circuit.extend(Fq::neg(y.clone()));
    let final_y = circuit.extend(U254::select(y, neg_y, y_flag));

    circuit.add_wires(x);
    circuit.add_wires(final_y);

    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}
    */

pub fn deserialize_compressed_g1_circuit_evaluate(p_c: Wires, y_flag: Wirex) -> (Wires, GateCount) {
    //let mut circuit = Circuit::empty();

    let x = p_c[0..Fq::N_BITS].to_vec();
    let mut gc = GateCount::zero();
    // calculate y
    let (x2, add_gc)  = Fq::square_montgomery_evaluate(x.clone());
    gc += add_gc;
    let (x3, add_gc) = Fq::mul_montgomery_evaluate(x2, x.clone());
    gc += add_gc;

    let (y2, add_gc) = Fq::add_evaluate(
        x3,
        Fq::wires_set_montgomery(ark_bn254::g1::Config::COEFF_B),
    );
    gc += add_gc;

    let (y, add_gc) = Fq::sqrt_montgomery_evaluate(y2);
    gc += add_gc;

    let (neg_y, add_gc) = Fq::neg_evaluate(y.clone());
    gc += add_gc;

    let (final_y, add_gc) = U254::select_evaluate(y, neg_y, y_flag);
    gc += add_gc;

    let mut res = x;
    res.extend(final_y);
    (res, gc)
}


/* 
// deserialize compressed point to montgomery form
pub fn deserialize_compressed_g2_circuit(p_c: Wires, y_flag: Wirex) -> (Wires, GateCount) {
    let mut circuit = Circuit::empty();

    let x = p_c[0..Fq2::N_BITS].to_vec();

    // calculate y
    let x2 = circuit.extend(Fq2::square_montgomery(x.clone()));
    let x3 = circuit.extend(Fq2::mul_montgomery(x2, x.clone()));

    let b = Fq2::wires_set_montgomery(ark_bn254::g2::Config::COEFF_B);
    let y2 = circuit.extend(Fq2::add(x3, b));

    let y = circuit.extend(Fq2::sqrt_general_montgomery(y2));
    let neg_y = circuit.extend(Fq2::neg(y.clone()));

    let final_y_0 = circuit.extend(U254::select(
        y[0..Fq::N_BITS].to_vec(),
        neg_y[0..Fq::N_BITS].to_vec(),
        y_flag.clone(),
    ));
    let final_y_1 = circuit.extend(U254::select(
        y[Fq::N_BITS..].to_vec(),
        neg_y[Fq::N_BITS..].to_vec(),
        y_flag,
    ));

    circuit.add_wires(x);
    circuit.add_wires(final_y_0);
    circuit.add_wires(final_y_1);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    (circuit.0, n)
}
*/

// deserialize compressed point to montgomery form
pub fn deserialize_compressed_g2_circuit_evaluate(p_c: Wires, y_flag: Wirex) -> (Wires, GateCount) {
    //let mut circuit = Circuit::empty();
    let mut gc = GateCount::zero();

    let x = p_c[0..Fq2::N_BITS].to_vec();

    // calculate y
    let (x2, add_gc) = Fq2::square_montgomery_evaluate(x.clone());
    gc += add_gc;

    let (x3, add_gc) = Fq2::mul_montgomery_evaluate(x2, x.clone());
    gc += add_gc;

    let b = Fq2::wires_set_montgomery(ark_bn254::g2::Config::COEFF_B);
    let (y2, add_gc) = Fq2::add_evaluate(x3, b);
    gc += add_gc;

    let (y, add_gc) = Fq2::sqrt_general_montgomery_evaluate(y2);
    gc += add_gc;

    let (neg_y, add_gc) = Fq2::neg_evaluate(y.clone());
    gc += add_gc;

    let (final_y_0, add_gc) = U254::select_evaluate(
        y[0..Fq::N_BITS].to_vec(),
        neg_y[0..Fq::N_BITS].to_vec(),
        y_flag.clone(),
    );
    gc += add_gc;

    let (final_y_1, add_gc) = U254::select_evaluate(
        y[Fq::N_BITS..].to_vec(),
        neg_y[Fq::N_BITS..].to_vec(),
        y_flag,
    );
    gc += add_gc;

    /* 
    circuit.add_wires(x);
    circuit.add_wires(final_y_0);
    circuit.add_wires(final_y_1);
    let n = circuit.gate_counts();
    for mut gate in circuit.1 {
        gate.evaluate();
    }
    */
    let mut res = x;
    res.extend(final_y_0);
    res.extend(final_y_1);
    (res, gc)
}

pub fn multi_miller_loop_groth16_evaluate_fast(
    p1: Wires,
    p2: Wires,
    p3: Wires,
    q1: ark_bn254::G2Affine,
    q2: ark_bn254::G2Affine,
    q3: Wires,
) -> (Wires, GateCount) {
    let mut gate_count = GateCount::zero();
    let q1ell = ell_coeffs(q1);
    let q2ell = ell_coeffs(q2);
    let (q3ell, gc) = ell_coeffs_evaluate_fast(q3);
    gate_count += gc;
    let mut q1_ell = q1ell.iter();
    let mut q2_ell = q2ell.iter();
    let mut q3_ell = q3ell.iter();

    let mut f = Fq12::wires_set(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            let (new_f, gc) = (
                Fq12::wires_set(Fq12::from_wires(f).square()),
                GateCount::fq12_square(),
            ); // Fq12::square_evaluate(f);
            f = new_f;
            gate_count += gc;
        }

        let q1ell_next = q1_ell.next().unwrap();
        let (new_f, gc) = (
            Fq12::wires_set(ell2(
                Fq12::from_wires(f),
                *q1ell_next,
                G1Affine::from_wires(p1.clone()),
            )),
            GateCount::ell_by_constant(),
        ); // ell_by_constant_evaluate(f, q1_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;

        let q2ell_next = q2_ell.next().unwrap();
        let (new_f, gc) = (
            Fq12::wires_set(ell2(
                Fq12::from_wires(f),
                *q2ell_next,
                G1Affine::from_wires(p2.clone()),
            )),
            GateCount::ell_by_constant(),
        ); // ell_by_constant_evaluate(f, q2_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;

        let q3ell_next = q3_ell.next().unwrap().clone();
        let (new_f, gc) = (
            Fq12::wires_set(ell2(
                Fq12::from_wires(f),
                (
                    Fq2::from_wires(q3ell_next.0),
                    Fq2::from_wires(q3ell_next.1),
                    Fq2::from_wires(q3ell_next.2),
                ),
                G1Affine::from_wires(p3.clone()),
            )),
            GateCount::ell(),
        ); // ell_evaluate(f, q3_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let q1ell_next = q1_ell.next().unwrap();
            let (new_f, gc) = (
                Fq12::wires_set(ell2(
                    Fq12::from_wires(f),
                    *q1ell_next,
                    G1Affine::from_wires(p1.clone()),
                )),
                GateCount::ell_by_constant(),
            ); // ell_by_constant_evaluate(f, q1_ell.next().unwrap().clone(), p.clone());
            f = new_f;
            gate_count += gc;

            let q2ell_next = q2_ell.next().unwrap();
            let (new_f, gc) = (
                Fq12::wires_set(ell2(
                    Fq12::from_wires(f),
                    *q2ell_next,
                    G1Affine::from_wires(p2.clone()),
                )),
                GateCount::ell_by_constant(),
            ); // ell_by_constant_evaluate(f, q2_ell.next().unwrap().clone(), p.clone());
            f = new_f;
            gate_count += gc;

            let q3ell_next = q3_ell.next().unwrap().clone();
            let (new_f, gc) = (
                Fq12::wires_set(ell2(
                    Fq12::from_wires(f),
                    (
                        Fq2::from_wires(q3ell_next.0),
                        Fq2::from_wires(q3ell_next.1),
                        Fq2::from_wires(q3ell_next.2),
                    ),
                    G1Affine::from_wires(p3.clone()),
                )),
                GateCount::ell(),
            ); // ell_evaluate(f, q3_ell.next().unwrap().clone(), p.clone());
            f = new_f;
            gate_count += gc;
        }
    }

    let q1ell_next = q1_ell.next().unwrap();
    let (new_f, gc) = (
        Fq12::wires_set(ell2(
            Fq12::from_wires(f),
            *q1ell_next,
            G1Affine::from_wires(p1.clone()),
        )),
        GateCount::ell_by_constant(),
    ); // ell_by_constant_evaluate(f, q1_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    let q2ell_next = q2_ell.next().unwrap();
    let (new_f, gc) = (
        Fq12::wires_set(ell2(
            Fq12::from_wires(f),
            *q2ell_next,
            G1Affine::from_wires(p2.clone()),
        )),
        GateCount::ell_by_constant(),
    ); // ell_by_constant_evaluate(f, q2_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    let q3ell_next = q3_ell.next().unwrap().clone();
    let (new_f, gc) = (
        Fq12::wires_set(ell2(
            Fq12::from_wires(f),
            (
                Fq2::from_wires(q3ell_next.0),
                Fq2::from_wires(q3ell_next.1),
                Fq2::from_wires(q3ell_next.2),
            ),
            G1Affine::from_wires(p3.clone()),
        )),
        GateCount::ell(),
    ); // ell_evaluate(f, q3_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    let q1ell_next = q1_ell.next().unwrap();
    let (new_f, gc) = (
        Fq12::wires_set(ell2(
            Fq12::from_wires(f),
            *q1ell_next,
            G1Affine::from_wires(p1.clone()),
        )),
        GateCount::ell_by_constant(),
    ); // ell_by_constant_evaluate(f, q1_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    let q2ell_next = q2_ell.next().unwrap();
    let (new_f, gc) = (
        Fq12::wires_set(ell2(
            Fq12::from_wires(f),
            *q2ell_next,
            G1Affine::from_wires(p2.clone()),
        )),
        GateCount::ell_by_constant(),
    ); // ell_by_constant_evaluate(f, q2_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    let q3ell_next = q3_ell.next().unwrap().clone();
    let (new_f, gc) = (
        Fq12::wires_set(ell2(
            Fq12::from_wires(f),
            (
                Fq2::from_wires(q3ell_next.0),
                Fq2::from_wires(q3ell_next.1),
                Fq2::from_wires(q3ell_next.2),
            ),
            G1Affine::from_wires(p3.clone()),
        )),
        GateCount::ell(),
    ); // ell_evaluate(f, q3_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    (f, gate_count)
}

pub fn multi_miller_loop_groth16_evaluate_montgomery_fast(
    p1: Wires,
    p2: Wires,
    p3: Wires,
    q1: ark_bn254::G2Affine,
    q2: ark_bn254::G2Affine,
    q3: Wires,
) -> (Wires, GateCount) {
    let mut gate_count = GateCount::zero();
    let q1ell = ell_coeffs(q1);
    let q2ell = ell_coeffs(q2);
    let (q3ell, gc) = ell_coeffs_evaluate_montgomery_fast(q3);
    gate_count += gc;
    let mut q1_ell = q1ell.iter();
    let mut q2_ell = q2ell.iter();
    let mut q3_ell = q3ell.iter();

    let mut f = Fq12::wires_set_montgomery(ark_bn254::Fq12::ONE);

    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        if i != ark_bn254::Config::ATE_LOOP_COUNT.len() - 1 {
            let (new_f, gc) = (
                Fq12::wires_set_montgomery(Fq12::from_montgomery_wires(f).square()),
                GateCount::fq12_square_montgomery(),
            ); // Fq12::square_evaluate_montgomery(f);
            f = new_f;
            gate_count += gc;
        }

        let q1ell_next = q1_ell.next().unwrap();
        let (new_f, gc) = (
            Fq12::wires_set_montgomery(ell2(
                Fq12::from_montgomery_wires(f),
                *q1ell_next,
                G1Affine::from_montgomery_wires_unchecked(p1.clone()),
            )),
            GateCount::ell_by_constant_montgomery(),
        ); // ell_by_constant_evaluate_montgomery(f, q1_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;

        let q2ell_next = q2_ell.next().unwrap();
        let (new_f, gc) = (
            Fq12::wires_set_montgomery(ell2(
                Fq12::from_montgomery_wires(f),
                *q2ell_next,
                G1Affine::from_montgomery_wires_unchecked(p2.clone()),
            )),
            GateCount::ell_by_constant_montgomery(),
        ); // ell_by_constant_evaluate_montgomery(f, q2_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;

        let q3ell_next = q3_ell.next().unwrap().clone();
        let (new_f, gc) = (
            Fq12::wires_set_montgomery(ell2(
                Fq12::from_montgomery_wires(f),
                (
                    Fq2::from_montgomery_wires(q3ell_next.0),
                    Fq2::from_montgomery_wires(q3ell_next.1),
                    Fq2::from_montgomery_wires(q3ell_next.2),
                ),
                G1Affine::from_montgomery_wires_unchecked(p3.clone()),
            )),
            GateCount::ell_montgomery(),
        ); // ell_evaluate_montgomery(f, q3_ell.next().unwrap().clone(), p.clone());
        f = new_f;
        gate_count += gc;

        let bit = ark_bn254::Config::ATE_LOOP_COUNT[i - 1];
        if bit == 1 || bit == -1 {
            let q1ell_next = q1_ell.next().unwrap();
            let (new_f, gc) = (
                Fq12::wires_set_montgomery(ell2(
                    Fq12::from_montgomery_wires(f),
                    *q1ell_next,
                    G1Affine::from_montgomery_wires_unchecked(p1.clone()),
                )),
                GateCount::ell_by_constant_montgomery(),
            ); // ell_by_constant_evaluate_montgomery(f, q1_ell.next().unwrap().clone(), p.clone());
            f = new_f;
            gate_count += gc;

            let q2ell_next = q2_ell.next().unwrap();
            let (new_f, gc) = (
                Fq12::wires_set_montgomery(ell2(
                    Fq12::from_montgomery_wires(f),
                    *q2ell_next,
                    G1Affine::from_montgomery_wires_unchecked(p2.clone()),
                )),
                GateCount::ell_by_constant_montgomery(),
            ); // ell_by_constant_evaluate_montgomery(f, q2_ell.next().unwrap().clone(), p.clone());
            f = new_f;
            gate_count += gc;

            let q3ell_next = q3_ell.next().unwrap().clone();
            let (new_f, gc) = (
                Fq12::wires_set_montgomery(ell2(
                    Fq12::from_montgomery_wires(f),
                    (
                        Fq2::from_montgomery_wires(q3ell_next.0),
                        Fq2::from_montgomery_wires(q3ell_next.1),
                        Fq2::from_montgomery_wires(q3ell_next.2),
                    ),
                    G1Affine::from_montgomery_wires_unchecked(p3.clone()),
                )),
                GateCount::ell_montgomery(),
            ); // ell_evaluate_montgomery(f, q3_ell.next().unwrap().clone(), p.clone());
            f = new_f;
            gate_count += gc;
        }
    }

    let q1ell_next = q1_ell.next().unwrap();
    let (new_f, gc) = (
        Fq12::wires_set_montgomery(ell2(
            Fq12::from_montgomery_wires(f),
            *q1ell_next,
            G1Affine::from_montgomery_wires_unchecked(p1.clone()),
        )),
        GateCount::ell_by_constant_montgomery(),
    ); // ell_by_constant_evaluate_montgomery(f, q1_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    let q2ell_next = q2_ell.next().unwrap();
    let (new_f, gc) = (
        Fq12::wires_set_montgomery(ell2(
            Fq12::from_montgomery_wires(f),
            *q2ell_next,
            G1Affine::from_montgomery_wires_unchecked(p2.clone()),
        )),
        GateCount::ell_by_constant_montgomery(),
    ); // ell_by_constant_evaluate_montgomery(f, q2_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    let q3ell_next = q3_ell.next().unwrap().clone();
    let (new_f, gc) = (
        Fq12::wires_set_montgomery(ell2(
            Fq12::from_montgomery_wires(f),
            (
                Fq2::from_montgomery_wires(q3ell_next.0),
                Fq2::from_montgomery_wires(q3ell_next.1),
                Fq2::from_montgomery_wires(q3ell_next.2),
            ),
            G1Affine::from_montgomery_wires_unchecked(p3.clone()),
        )),
        GateCount::ell_montgomery(),
    ); // ell_evaluate_montgomery(f, q3_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    let q1ell_next = q1_ell.next().unwrap();
    let (new_f, gc) = (
        Fq12::wires_set_montgomery(ell2(
            Fq12::from_montgomery_wires(f),
            *q1ell_next,
            G1Affine::from_montgomery_wires_unchecked(p1.clone()),
        )),
        GateCount::ell_by_constant_montgomery(),
    ); // ell_by_constant_evaluate_montgomery(f, q1_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    let q2ell_next = q2_ell.next().unwrap();
    let (new_f, gc) = (
        Fq12::wires_set_montgomery(ell2(
            Fq12::from_montgomery_wires(f),
            *q2ell_next,
            G1Affine::from_montgomery_wires_unchecked(p2.clone()),
        )),
        GateCount::ell_by_constant_montgomery(),
    ); // ell_by_constant_evaluate_montgomery(f, q2_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    let q3ell_next = q3_ell.next().unwrap().clone();
    let (new_f, gc) = (
        Fq12::wires_set_montgomery(ell2(
            Fq12::from_montgomery_wires(f),
            (
                Fq2::from_montgomery_wires(q3ell_next.0),
                Fq2::from_montgomery_wires(q3ell_next.1),
                Fq2::from_montgomery_wires(q3ell_next.2),
            ),
            G1Affine::from_montgomery_wires_unchecked(p3.clone()),
        )),
        GateCount::ell_montgomery(),
    ); // ell_evaluate_montgomery(f, q3_ell.next().unwrap().clone(), p.clone());
    f = new_f;
    gate_count += gc;

    (f, gate_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::pairing::Pairing;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use serial_test::serial;
    use std::iter::zip;

    #[test]
    #[serial]
    fn test_deserialized_compressed_g1() {
        let p = G1Affine::random();
        println!("p: {:?}", p);
        //use ark_ec::CurveGroup;
        //let p = (p - p).into_affine();
        let y_flag = new_wirex();

        let sy = (p.y.square()).sqrt().unwrap();
        y_flag.borrow_mut().set(sy == p.y);

        let wires = Fq::wires_set_montgomery(p.x.clone());
        let circuit = deserialize_compressed_g1_circuit_evaluate(wires, y_flag.clone());
        //let x = Fq::from_montgomery_wires(circuit.0[0..Fq::N_BITS].to_vec());
        let y = Fq::from_montgomery_wires(circuit.0[Fq::N_BITS..2 * Fq::N_BITS].to_vec());
        assert_eq!(y, p.y);
    }

    #[test]
    #[serial]
    fn test_deserialized_compressed_g2() {
        let p = G2Affine::random();
        //use ark_ec::CurveGroup;
        //let p = (p - p).into_affine();
        let y_flag = new_wirex();
        let sy = (p.y.square()).sqrt().unwrap();
        y_flag.borrow_mut().set(sy == p.y);

        let wires = Fq2::wires_set_montgomery(p.x.clone());

        let (wires, n) = deserialize_compressed_g2_circuit_evaluate(wires.clone(), y_flag);
        n.print();
        //let x = Fq2::from_montgomery_wires(circuit.0[0..Fq2::N_BITS].to_vec());
        let y = Fq2::from_montgomery_wires(wires[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec());
        assert_eq!(y, p.y);
    }

    #[test]
    #[serial]
    fn test_double_in_place() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut r = ark_bn254::G2Projective::rand(&mut prng);

        let circuit = double_in_place_circuit(G2Projective::wires_set(r));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c0 = Fq2::from_wires(circuit.0[0..Fq2::N_BITS].to_vec());
        let c1 = Fq2::from_wires(circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec());
        let c2 = Fq2::from_wires(circuit.0[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec());
        let rx = Fq2::from_wires(circuit.0[3 * Fq2::N_BITS..4 * Fq2::N_BITS].to_vec());
        let ry = Fq2::from_wires(circuit.0[4 * Fq2::N_BITS..5 * Fq2::N_BITS].to_vec());
        let rz = Fq2::from_wires(circuit.0[5 * Fq2::N_BITS..6 * Fq2::N_BITS].to_vec());
        let coeffs = double_in_place(&mut r);
        assert_eq!(c0, coeffs.0);
        assert_eq!(c1, coeffs.1);
        assert_eq!(c2, coeffs.2);
        assert_eq!(r.x, rx);
        assert_eq!(r.y, ry);
        assert_eq!(r.z, rz);
    }

    #[test]
    #[serial]
    fn test_double_in_place_montgomery() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut r = ark_bn254::G2Projective::rand(&mut prng);

        let circuit = double_in_place_circuit_montgomery(G2Projective::wires_set_montgomery(r));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c0 = Fq2::from_montgomery_wires(circuit.0[0..Fq2::N_BITS].to_vec());
        let c1 = Fq2::from_montgomery_wires(circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec());
        let c2 = Fq2::from_montgomery_wires(circuit.0[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec());
        let rx = Fq2::from_montgomery_wires(circuit.0[3 * Fq2::N_BITS..4 * Fq2::N_BITS].to_vec());
        let ry = Fq2::from_montgomery_wires(circuit.0[4 * Fq2::N_BITS..5 * Fq2::N_BITS].to_vec());
        let rz = Fq2::from_montgomery_wires(circuit.0[5 * Fq2::N_BITS..6 * Fq2::N_BITS].to_vec());
        let coeffs = double_in_place(&mut r);
        assert_eq!(c0, coeffs.0);
        assert_eq!(c1, coeffs.1);
        assert_eq!(c2, coeffs.2);
        assert_eq!(r.x, rx);
        assert_eq!(r.y, ry);
        assert_eq!(r.z, rz);
    }

    #[test]
    #[serial]
    fn test_add_in_place() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut r = ark_bn254::G2Projective::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let circuit = add_in_place_circuit(G2Projective::wires_set(r), G2Affine::wires_set(q));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c0 = Fq2::from_wires(circuit.0[0..Fq2::N_BITS].to_vec());
        let c1 = Fq2::from_wires(circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec());
        let c2 = Fq2::from_wires(circuit.0[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec());
        let new_r_x =
            Fq2::from_wires(circuit.0[3 * Fq2::N_BITS..3 * Fq2::N_BITS + Fq2::N_BITS].to_vec());
        let new_r_y = Fq2::from_wires(
            circuit.0[3 * Fq2::N_BITS + Fq2::N_BITS..3 * Fq2::N_BITS + 2 * Fq2::N_BITS].to_vec(),
        );
        let new_r_z = Fq2::from_wires(
            circuit.0[3 * Fq2::N_BITS + 2 * Fq2::N_BITS..3 * Fq2::N_BITS + 3 * Fq2::N_BITS]
                .to_vec(),
        );
        let coeffs = add_in_place(&mut r, &q);
        assert_eq!(c0, coeffs.0);
        assert_eq!(c1, coeffs.1);
        assert_eq!(c2, coeffs.2);
        assert_eq!(r.x, new_r_x);
        assert_eq!(r.y, new_r_y);
        assert_eq!(r.z, new_r_z);
    }

    #[test]
    #[serial]
    fn test_add_in_place_montgomery() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut r = ark_bn254::G2Projective::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let circuit = add_in_place_circuit_montgomery(
            G2Projective::wires_set_montgomery(r),
            G2Affine::wires_set_montgomery(q),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c0 = Fq2::from_montgomery_wires(circuit.0[0..Fq2::N_BITS].to_vec());
        let c1 = Fq2::from_montgomery_wires(circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec());
        let c2 = Fq2::from_montgomery_wires(circuit.0[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec());
        let new_r_x = Fq2::from_montgomery_wires(
            circuit.0[3 * Fq2::N_BITS..3 * Fq2::N_BITS + Fq2::N_BITS].to_vec(),
        );
        let new_r_y = Fq2::from_montgomery_wires(
            circuit.0[3 * Fq2::N_BITS + Fq2::N_BITS..3 * Fq2::N_BITS + 2 * Fq2::N_BITS].to_vec(),
        );
        let new_r_z = Fq2::from_montgomery_wires(
            circuit.0[3 * Fq2::N_BITS + 2 * Fq2::N_BITS..3 * Fq2::N_BITS + 3 * Fq2::N_BITS]
                .to_vec(),
        );
        let coeffs = add_in_place(&mut r, &q);
        assert_eq!(c0, coeffs.0);
        assert_eq!(c1, coeffs.1);
        assert_eq!(c2, coeffs.2);
        assert_eq!(r.x, new_r_x);
        assert_eq!(r.y, new_r_y);
        assert_eq!(r.z, new_r_z);
    }

    #[test]
    #[serial]
    fn test_mul_by_char() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let circuit = mul_by_char_circuit(G2Affine::wires_set(q));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c0 = Fq2::from_wires(circuit.0[0..Fq2::N_BITS].to_vec());
        let c1 = Fq2::from_wires(circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec());
        let coeffs = mul_by_char(q);
        assert_eq!(c0, coeffs.x);
        assert_eq!(c1, coeffs.y);
    }

    #[test]
    #[serial]
    fn test_mul_by_char_montgomery() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let circuit = mul_by_char_circuit_montgomery(G2Affine::wires_set_montgomery(q));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c0 = Fq2::from_montgomery_wires(circuit.0[0..Fq2::N_BITS].to_vec());
        let c1 = Fq2::from_montgomery_wires(circuit.0[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec());
        let coeffs = mul_by_char(q);
        assert_eq!(c0, coeffs.x);
        assert_eq!(c1, coeffs.y);
    }

    #[test]
    fn test_ell_coeffs_evaluate_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let expected_coeffs = ell_coeffs(q);
        let (coeffs, gate_count) = ell_coeffs_evaluate_fast(G2Affine::wires_set(q));
        gate_count.print();

        for (a, b) in zip(coeffs, expected_coeffs) {
            assert_eq!(Fq2::from_wires(a.0), b.0);
            assert_eq!(Fq2::from_wires(a.1), b.1);
            assert_eq!(Fq2::from_wires(a.2), b.2);
        }
    }

    #[test]
    fn test_ell_coeffs_evaluate_montgomery_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let expected_coeffs = ell_coeffs(q);
        let (coeffs, gate_count) =
            ell_coeffs_evaluate_montgomery_fast(G2Affine::wires_set_montgomery(q));
        gate_count.print();

        for (a, b) in zip(coeffs, expected_coeffs) {
            assert_eq!(Fq2::from_montgomery_wires(a.0), b.0);
            assert_eq!(Fq2::from_montgomery_wires(a.1), b.1);
            assert_eq!(Fq2::from_montgomery_wires(a.2), b.2);
        }
    }

    #[test]
    #[serial]
    fn test_ell() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut f = ark_bn254::Fq12::rand(&mut prng);
        let coeffs = (
            ark_bn254::Fq2::rand(&mut prng),
            ark_bn254::Fq2::rand(&mut prng),
            ark_bn254::Fq2::rand(&mut prng),
        );
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let circuit = ell_circuit(
            Fq12::wires_set(f),
            (
                Fq2::wires_set(coeffs.0),
                Fq2::wires_set(coeffs.1),
                Fq2::wires_set(coeffs.2),
            ),
            G1Affine::wires_set(p),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let new_f = Fq12::from_wires(circuit.0);
        ell(&mut f, coeffs, p);
        assert_eq!(f, new_f);
    }

    #[test]
    #[serial]
    fn test_ell_montgomery() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut f = ark_bn254::Fq12::rand(&mut prng);
        let coeffs = (
            ark_bn254::Fq2::rand(&mut prng),
            ark_bn254::Fq2::rand(&mut prng),
            ark_bn254::Fq2::rand(&mut prng),
        );
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let circuit = ell_circuit_montgomery(
            Fq12::wires_set_montgomery(f),
            (
                Fq2::wires_set_montgomery(coeffs.0),
                Fq2::wires_set_montgomery(coeffs.1),
                Fq2::wires_set_montgomery(coeffs.2),
            ),
            G1Affine::wires_set_montgomery(p),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let new_f = Fq12::from_montgomery_wires(circuit.0);
        ell(&mut f, coeffs, p);
        assert_eq!(f, new_f);
    }

    #[test]
    #[serial]
    fn test_ell_by_constant() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut f = ark_bn254::Fq12::rand(&mut prng);
        let coeffs = (
            ark_bn254::Fq2::rand(&mut prng),
            ark_bn254::Fq2::rand(&mut prng),
            ark_bn254::Fq2::rand(&mut prng),
        );
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let circuit = ell_by_constant_circuit(Fq12::wires_set(f), coeffs, G1Affine::wires_set(p));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let new_f = Fq12::from_wires(circuit.0);
        ell(&mut f, coeffs, p);
        assert_eq!(f, new_f);
    }

    #[test]
    #[serial]
    fn test_ell_by_constant_montgomery() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let mut f = ark_bn254::Fq12::rand(&mut prng);
        let coeffs = (
            ark_bn254::Fq2::rand(&mut prng),
            ark_bn254::Fq2::rand(&mut prng),
            ark_bn254::Fq2::rand(&mut prng),
        );
        let p = ark_bn254::G1Affine::rand(&mut prng);

        let circuit = ell_by_constant_circuit_montgomery(
            Fq12::wires_set_montgomery(f),
            (
                Fq2::as_montgomery(coeffs.0),
                Fq2::as_montgomery(coeffs.1),
                Fq2::as_montgomery(coeffs.2),
            ),
            G1Affine::wires_set_montgomery(p),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let new_f = Fq12::from_montgomery_wires(circuit.0);
        ell(&mut f, coeffs, p);
        assert_eq!(f, new_f);
    }

    #[test]
    fn test_miller_loop() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let c = ark_bn254::Bn254::multi_miller_loop([p], [q]).0;
        let d = miller_loop(p, q);
        assert_eq!(c, d);
    }

    #[test]
    fn test_miller_loop_evaluate_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let expected_f = miller_loop(p, q);
        let (f, gate_count) =
            miller_loop_evaluate_fast(G1Affine::wires_set(p), G2Affine::wires_set(q));
        gate_count.print();

        assert_eq!(Fq12::from_wires(f), expected_f);
    }

    #[test]
    fn test_miller_loop_evaluate_montgomery_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p = ark_bn254::G1Affine::rand(&mut prng);
        let q = ark_bn254::G2Affine::rand(&mut prng);

        let expected_f = miller_loop(p, q);
        let (f, gate_count) = miller_loop_evaluate_montgomery_fast(
            G1Affine::wires_set_montgomery(p),
            G2Affine::wires_set_montgomery(q),
        );
        gate_count.print();

        assert_eq!(Fq12::from_montgomery_wires(f), expected_f);
    }

    #[test]
    fn test_multi_miller_loop() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let n = 3;
        let ps = (0..n)
            .map(|_| ark_bn254::G1Affine::rand(&mut prng))
            .collect::<Vec<_>>();
        let qs = (0..n)
            .map(|_| ark_bn254::G2Affine::rand(&mut prng))
            .collect::<Vec<_>>();

        let c = ark_bn254::Bn254::multi_miller_loop(ps.clone(), qs.clone()).0;
        let d = multi_miller_loop(ps, qs);
        assert_eq!(c, d);
    }

    #[test]
    fn test_multi_miller_loop_evaluate_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let n = 3;
        let ps = (0..n)
            .map(|_| ark_bn254::G1Affine::rand(&mut prng))
            .collect::<Vec<_>>();
        let qs = (0..n)
            .map(|_| ark_bn254::G2Affine::rand(&mut prng))
            .collect::<Vec<_>>();

        let expected_f = multi_miller_loop(ps.clone(), qs.clone());
        let (f, gate_count) = multi_miller_loop_evaluate_fast(
            ps.iter().map(|p| G1Affine::wires_set(*p)).collect(),
            qs.iter().map(|q| G2Affine::wires_set(*q)).collect(),
        );
        gate_count.print();

        assert_eq!(Fq12::from_wires(f), expected_f);
    }

    #[test]
    fn test_multi_miller_loop_evaluate_montgomery_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let n = 3;
        let ps = (0..n)
            .map(|_| ark_bn254::G1Affine::rand(&mut prng))
            .collect::<Vec<_>>();
        let qs = (0..n)
            .map(|_| ark_bn254::G2Affine::rand(&mut prng))
            .collect::<Vec<_>>();

        let expected_f = multi_miller_loop(ps.clone(), qs.clone());
        let (f, gate_count) = multi_miller_loop_evaluate_montgomery_fast(
            ps.iter()
                .map(|p| G1Affine::wires_set_montgomery(*p))
                .collect(),
            qs.iter()
                .map(|q| G2Affine::wires_set_montgomery(*q))
                .collect(),
        );
        gate_count.print();

        assert_eq!(Fq12::from_montgomery_wires(f), expected_f);
    }

    #[test]
    fn test_multi_miller_loop_groth16_evaluate_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p1 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let q1 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);

        let expected_f = multi_miller_loop(vec![p1, p2, p3], vec![q1, q2, q3]);
        let (f, gate_count) = multi_miller_loop_groth16_evaluate_fast(
            G1Affine::wires_set(p1),
            G1Affine::wires_set(p2),
            G1Affine::wires_set(p3),
            q1,
            q2,
            G2Affine::wires_set(q3),
        );
        gate_count.print();

        assert_eq!(Fq12::from_wires(f), expected_f);
    }

    #[test]
    fn test_multi_miller_loop_groth16_evaluate_montgomery_fast() {
        let mut prng = ChaCha20Rng::seed_from_u64(0);
        let p1 = ark_bn254::G1Affine::rand(&mut prng);
        let p2 = ark_bn254::G1Affine::rand(&mut prng);
        let p3 = ark_bn254::G1Affine::rand(&mut prng);
        let q1 = ark_bn254::G2Affine::rand(&mut prng);
        let q2 = ark_bn254::G2Affine::rand(&mut prng);
        let q3 = ark_bn254::G2Affine::rand(&mut prng);

        let expected_f = multi_miller_loop(vec![p1, p2, p3], vec![q1, q2, q3]);
        let (f, gate_count) = multi_miller_loop_groth16_evaluate_montgomery_fast(
            G1Affine::wires_set_montgomery(p1),
            G1Affine::wires_set_montgomery(p2),
            G1Affine::wires_set_montgomery(p3),
            q1,
            q2,
            G2Affine::wires_set_montgomery(q3),
        );
        gate_count.print();

        assert_eq!(Fq12::from_montgomery_wires(f), expected_f);
    }
}
