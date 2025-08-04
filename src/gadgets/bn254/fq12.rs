use ark_ff::{AdditiveGroup, Field, Fp6Config, Fp12Config, PrimeField, UniformRand};
use num_traits::Zero;
use rand::{Rng, rng};

use super::fq6::Fq6Components;
use crate::{
    Circuit, CircuitContext, Gate, WireId,
    gadgets::{
        bigint::{self, BigIntWires, select},
        bn254::{
            fq::Fq,
            fq2::{Fq2, Pair},
            fq6::Fq6,
        },
    },
};

pub type Fq12Element<T> = (Fq6Components<T>, Fq6Components<T>);

pub fn fq12element_mark_as_output(circuit: &mut Circuit, a: &Fq12) {
    a.mark_as_output(circuit);
}

#[derive(Clone)]
pub struct Fq12(pub [Fq6; 2]);

impl Fq12 {
    /// Access c0 component (first Fq6)
    pub fn c0(&self) -> &Fq6 {
        &self.0[0]
    }

    /// Access c1 component (second Fq6)
    pub fn c1(&self) -> &Fq6 {
        &self.0[1]
    }

    /// Create new Fq12 from components
    pub fn from_components(c0: Fq6, c1: Fq6) -> Self {
        Fq12([c0, c1])
    }

    /// Mark all components as output
    pub fn mark_as_output(&self, circuit: &mut Circuit) {
        self.c0().mark_as_output(circuit);
        self.c1().mark_as_output(circuit);
    }
}

impl Fq12 {
    pub const N_BITS: usize = 2 * Fq6::N_BITS;

    pub fn as_montgomery(a: ark_bn254::Fq12) -> ark_bn254::Fq12 {
        ark_bn254::Fq12::new(Fq6::as_montgomery(a.c0), Fq6::as_montgomery(a.c1))
    }

    pub fn from_montgomery(a: ark_bn254::Fq12) -> ark_bn254::Fq12 {
        ark_bn254::Fq12::new(Fq6::from_montgomery(a.c0), Fq6::from_montgomery(a.c1))
    }

    pub fn random(rng: &mut impl Rng) -> ark_bn254::Fq12 {
        ark_bn254::Fq12::new(Fq6::random(rng), Fq6::random(rng))
    }

    pub fn to_bits(u: ark_bn254::Fq12) -> Fq12Element<Vec<bool>> {
        (Fq6::to_bits(u.c0), Fq6::to_bits(u.c1))
    }

    pub fn from_bits(bits: Fq12Element<Vec<bool>>) -> ark_bn254::Fq12 {
        ark_bn254::Fq12::new(Fq6::from_bits(bits.0), Fq6::from_bits(bits.1))
    }

    pub fn new(circuit: &mut Circuit, is_input: bool, is_output: bool) -> Fq12 {
        Fq12([
            Fq6::new(circuit, is_input, is_output),
            Fq6::new(circuit, is_input, is_output),
        ])
    }

    pub fn get_wire_bits_fn(
        wires: &Fq12,
        value: &ark_bn254::Fq12,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, crate::gadgets::bigint::Error> {
        let c0_fn = Fq6::get_wire_bits_fn(wires.c0(), &value.c0)?;
        let c1_fn = Fq6::get_wire_bits_fn(wires.c1(), &value.c1)?;

        Ok(move |wire_id| c0_fn(wire_id).or_else(|| c1_fn(wire_id)))
    }

    pub fn to_bitmask(wires: &Fq12, get_val: impl Fn(WireId) -> bool) -> String {
        let c0_mask = Fq6::to_bitmask(wires.c0(), &get_val);
        let c1_mask = Fq6::to_bitmask(wires.c1(), &get_val);
        format!("c0: ({c0_mask}), c1: ({c1_mask})")
    }

    pub fn equal_constant(circuit: &mut Circuit, a: &Fq12, b: &ark_bn254::Fq12) -> WireId {
        let u = Fq6::equal_constant(circuit, a.c0(), &b.c0);
        let v = Fq6::equal_constant(circuit, a.c1(), &b.c1);
        let w = circuit.issue_wire();
        circuit.add_gate(Gate::and(u, v, w));
        w
    }

    pub fn add(circuit: &mut Circuit, a: &Fq12, b: &Fq12) -> Fq12 {
        let c0 = Fq6::add(circuit, a.c0(), b.c0());
        let c1 = Fq6::add(circuit, a.c1(), b.c1());

        Fq12::from_components(c0, c1)
    }

    pub fn neg(circuit: &mut Circuit, a: Fq12) -> Fq12 {
        Fq12::from_components(
            Fq6::neg(circuit, a.0[0].clone()),
            Fq6::neg(circuit, a.0[1].clone()),
        )
    }

    pub fn sub(circuit: &mut Circuit, a: &Fq12, b: &Fq12) -> Fq12 {
        let c0 = Fq6::sub(circuit, a.c0(), b.c0());
        let c1 = Fq6::sub(circuit, a.c1(), b.c1());

        Fq12::from_components(c0, c1)
    }

    pub fn double(circuit: &mut Circuit, a: &Fq12) -> Fq12 {
        let c0 = Fq6::double(circuit, a.c0());
        let c1 = Fq6::double(circuit, a.c1());

        Fq12::from_components(c0, c1)
    }

    pub fn mul_montgomery(circuit: &mut Circuit, a: &Fq12, b: &Fq12) -> Fq12 {
        // (a0 + a1) and (b0 + b1)
        let a_sum = Fq6::add(circuit, a.c0(), a.c1());
        let b_sum = Fq6::add(circuit, b.c0(), b.c1());

        // a0 * b0 and a1 * b1
        let a0_b0 = Fq6::mul_montgomery(circuit, a.c0(), b.c0());
        let a1_b1 = Fq6::mul_montgomery(circuit, a.c1(), b.c1());

        // a0b0+a1b1
        let sum_a0b0_a1b1 = Fq6::add(circuit, &a0_b0, &a1_b1);

        // (a0 + a1) * (b0 + b1)
        let sum_prod = Fq6::mul_montgomery(circuit, &a_sum, &b_sum);

        let a1_b1_nonres = Fq6::mul_by_nonresidue(circuit, &a1_b1);

        let c0 = Fq6::add(circuit, &a0_b0, &a1_b1_nonres);

        let c1 = Fq6::sub(circuit, &sum_prod, &sum_a0b0_a1b1);

        Fq12::from_components(c0, c1)
    }

    pub fn mul_by_constant_montgomery(
        circuit: &mut Circuit,
        a: &Fq12,
        b: &ark_bn254::Fq12,
    ) -> Fq12 {
        // a0 + a1
        let a_sum = Fq6::add(circuit, a.c0(), a.c1());

        // a0 * b0 and a1 * b1
        let a0_b0 = Fq6::mul_by_constant_montgomery(circuit, a.c0(), &b.c0);
        let a1_b1 = Fq6::mul_by_constant_montgomery(circuit, a.c1(), &b.c1);

        // a0b0+a1b1
        let sum_a0b0_a1b1 = Fq6::add(circuit, &a0_b0, &a1_b1);

        // (a0 + a1) * (b0 + b1)
        let sum_prod = Fq6::mul_by_constant_montgomery(circuit, &a_sum, &(b.c0 + b.c1));

        let a1_b1_nonres = Fq6::mul_by_nonresidue(circuit, &a1_b1);

        let c0 = Fq6::add(circuit, &a0_b0, &a1_b1_nonres);

        let c1 = Fq6::sub(circuit, &sum_prod, &sum_a0b0_a1b1);

        Fq12::from_components(c0, c1)
    }

    pub fn mul_by_34_montgomery(
        circuit: &mut Circuit,
        a: &Fq12,
        c3: &Pair<BigIntWires>,
        c4: &Pair<BigIntWires>,
    ) -> Fq12 {
        let c3_fq2 = Fq2([Fq(c3.0.clone()), Fq(c3.1.clone())]);
        let c4_fq2 = Fq2([Fq(c4.0.clone()), Fq(c4.1.clone())]);
        let w1 = Fq6::mul_by_01_montgomery(circuit, a.c1(), &c3_fq2, &c4_fq2);
        let w2 = Fq6::mul_by_nonresidue(circuit, &w1);
        let new_c0 = Fq6::add(circuit, &w2, a.c0());
        let w3 = Fq6::add(circuit, a.c0(), a.c1());
        let w4 = Fq2::add_constant(circuit, &c3_fq2, &Fq2::as_montgomery(ark_bn254::Fq2::ONE));
        let w5 = Fq6::mul_by_01_montgomery(circuit, &w3, &w4, &c4_fq2);
        let w6 = Fq6::add(circuit, &w1, a.c0());
        let new_c1 = Fq6::sub(circuit, &w5, &w6);
        Fq12::from_components(new_c0, new_c1)
    }

    pub fn mul_by_034_montgomery(
        circuit: &mut Circuit,
        a: &Fq12,
        c0: &Pair<BigIntWires>,
        c3: &Pair<BigIntWires>,
        c4: &Pair<BigIntWires>,
    ) -> Fq12 {
        let c0_fq2 = Fq2([Fq(c0.0.clone()), Fq(c0.1.clone())]);
        let c3_fq2 = Fq2([Fq(c3.0.clone()), Fq(c3.1.clone())]);
        let c4_fq2 = Fq2([Fq(c4.0.clone()), Fq(c4.1.clone())]);
        let w1 = Fq6::mul_by_01_montgomery(circuit, a.c1(), &c3_fq2, &c4_fq2);
        let w2 = Fq6::mul_by_nonresidue(circuit, &w1);
        let w3 = Fq6::mul_by_fq2_montgomery(circuit, a.c0(), &c0_fq2);
        let new_c0 = Fq6::add(circuit, &w2, &w3);
        let w4 = Fq6::add(circuit, a.c0(), a.c1());
        let w5 = Fq2::add(circuit, &c3_fq2, &c0_fq2);
        let w6 = Fq6::mul_by_01_montgomery(circuit, &w4, &w5, &c4_fq2);
        let w7 = Fq6::add(circuit, &w1, &w3);
        let new_c1 = Fq6::sub(circuit, &w6, &w7);
        Fq12::from_components(new_c0, new_c1)
    }

    pub fn mul_by_034_constant4_montgomery(
        circuit: &mut Circuit,
        a: &Fq12,
        c0: &Pair<BigIntWires>,
        c3: &Pair<BigIntWires>,
        c4: &ark_bn254::Fq2,
    ) -> Fq12 {
        let c0_fq2 = Fq2([Fq(c0.0.clone()), Fq(c0.1.clone())]);
        let c3_fq2 = Fq2([Fq(c3.0.clone()), Fq(c3.1.clone())]);
        let w1 = Fq6::mul_by_01_constant1_montgomery(circuit, a.c1(), &c3_fq2, c4);
        let w2 = Fq6::mul_by_nonresidue(circuit, &w1);
        let w3 = Fq6::mul_by_fq2_montgomery(circuit, a.c0(), &c0_fq2);
        let new_c0 = Fq6::add(circuit, &w2, &w3);
        let w4 = Fq6::add(circuit, a.c0(), a.c1());
        let w5 = Fq2::add(circuit, &c3_fq2, &c0_fq2);
        let w6 = Fq6::mul_by_01_constant1_montgomery(circuit, &w4, &w5, c4);
        let w7 = Fq6::add(circuit, &w1, &w3);
        let new_c1 = Fq6::sub(circuit, &w6, &w7);
        Fq12::from_components(new_c0, new_c1)
    }

    pub fn square_montgomery(circuit: &mut Circuit, a: &Fq12) -> Fq12 {
        let w1 = Fq6::add(circuit, a.c0(), a.c1());
        let w2 = Fq6::mul_by_nonresidue(circuit, a.c1());
        let w3 = Fq6::add(circuit, a.c0(), &w2);
        let w4 = Fq6::mul_montgomery(circuit, a.c0(), a.c1());
        let w5 = Fq6::mul_montgomery(circuit, &w1, &w3);
        let w6 = Fq6::mul_by_nonresidue(circuit, &w4);
        let w7 = Fq6::add(circuit, &w4, &w6);
        let c0 = Fq6::sub(circuit, &w5, &w7);
        let c1 = Fq6::double(circuit, &w4);
        Fq12::from_components(c0, c1)
    }

    pub fn cyclotomic_square_montgomery(circuit: &mut Circuit, a: &Fq12) -> Fq12 {
        // https://eprint.iacr.org/2009/565.pdf
        // based on the implementation in arkworks-rs, fq12_2over3over2.rs

        let c0 = a.c0().c0().clone();
        let c1 = a.c0().c1().clone();
        let c2 = a.c0().c2().clone();
        let c3 = a.c1().c0().clone();
        let c4 = a.c1().c1().clone();
        let c5 = a.c1().c2().clone();

        let xy = Fq2::mul_montgomery(circuit, &c0, &c4);
        let x_plus_y = Fq2::add(circuit, &c0, &c4);
        let y_beta = Fq2::mul_by_nonresidue(circuit, &c4);
        let x_plus_y_beta = Fq2::add(circuit, &c0, &y_beta);
        let xy_beta = Fq2::mul_by_nonresidue(circuit, &xy);
        let w1 = Fq2::mul_montgomery(circuit, &x_plus_y, &x_plus_y_beta);
        let w2 = Fq2::add(circuit, &xy, &xy_beta);
        let t0 = Fq2::sub(circuit, &w1, &w2);
        let t1 = Fq2::double(circuit, &xy);

        let xy = Fq2::mul_montgomery(circuit, &c2, &c3);
        let x_plus_y = Fq2::add(circuit, &c2, &c3);
        let y_beta = Fq2::mul_by_nonresidue(circuit, &c2);
        let x_plus_y_beta = Fq2::add(circuit, &c3, &y_beta);
        let xy_beta = Fq2::mul_by_nonresidue(circuit, &xy);
        let w1 = Fq2::mul_montgomery(circuit, &x_plus_y, &x_plus_y_beta);
        let w2 = Fq2::add(circuit, &xy, &xy_beta);
        let t2 = Fq2::sub(circuit, &w1, &w2);
        let t3 = Fq2::double(circuit, &xy);

        let xy = Fq2::mul_montgomery(circuit, &c1, &c5);
        let x_plus_y = Fq2::add(circuit, &c1, &c5);
        let y_beta = Fq2::mul_by_nonresidue(circuit, &c5);
        let x_plus_y_beta = Fq2::add(circuit, &c1, &y_beta);
        let xy_beta = Fq2::mul_by_nonresidue(circuit, &xy);
        let w1 = Fq2::mul_montgomery(circuit, &x_plus_y, &x_plus_y_beta);
        let w2 = Fq2::add(circuit, &xy, &xy_beta);
        let t4 = Fq2::sub(circuit, &w1, &w2);
        let t5 = Fq2::double(circuit, &xy);

        let w1 = Fq2::sub(circuit, &t0, &c0);
        let w2 = Fq2::double(circuit, &w1);
        let z0 = Fq2::add(circuit, &w2, &t0);

        let w1 = Fq2::sub(circuit, &t2, &c1);
        let w2 = Fq2::double(circuit, &w1);
        let z4 = Fq2::add(circuit, &w2, &t2);

        let w1 = Fq2::sub(circuit, &t4, &c2);
        let w2 = Fq2::double(circuit, &w1);
        let z3 = Fq2::add(circuit, &w2, &t4);

        let t5_beta = Fq2::mul_by_nonresidue(circuit, &t5);
        let w1 = Fq2::sub(circuit, &t5_beta, &c3);
        let w2 = Fq2::double(circuit, &w1);
        let z2 = Fq2::add(circuit, &w2, &t5_beta);

        let w1 = Fq2::sub(circuit, &t1, &c4);
        let w2 = Fq2::double(circuit, &w1);
        let z1 = Fq2::add(circuit, &w2, &t1);

        let w1 = Fq2::sub(circuit, &t3, &c5);
        let w2 = Fq2::double(circuit, &w1);
        let z5 = Fq2::add(circuit, &w2, &t3);
        Fq12::from_components(Fq6([z0, z4, z3]), Fq6([z2, z1, z5]))
    }

    // pub fn inverse(a: Wires) -> Circuit {
    //     assert_eq!(a.len(), Self::N_BITS);
    //     let mut circuit = Circuit::empty();
    //     let a_c0 = a[0..Fq6::N_BITS].to_vec();
    //     let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();
    //     let a_c0_square = circuit.extend(Fq6::square(a_c0.clone()));
    //     let a_c1_square = circuit.extend(Fq6::square(a_c1.clone()));
    //     let a_c1_square_beta = circuit.extend(Fq6::mul_by_nonresidue(a_c1_square.clone()));
    //     let norm = circuit.extend(Fq6::sub(a_c0_square, a_c1_square_beta));
    //     let inverse_norm = circuit.extend(Fq6::inverse(norm));
    //     let res_c0 = circuit.extend(Fq6::mul(a_c0, inverse_norm.clone()));
    //     let neg_a_c1 = circuit.extend(Fq6::neg(a_c1));
    //     let res_c1 = circuit.extend(Fq6::mul(inverse_norm, neg_a_c1));

    //     circuit.add_wires(res_c0);
    //     circuit.add_wires(res_c1);
    //     circuit
    // }

    // pub fn inverse_montgomery(a: Wires) -> Circuit {
    //     assert_eq!(a.len(), Self::N_BITS);
    //     let mut circuit = Circuit::empty();
    //     let a_c0 = a[0..Fq6::N_BITS].to_vec();
    //     let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();
    //     let a_c0_square = circuit.extend(Fq6::square_montgomery(a_c0.clone()));
    //     let a_c1_square = circuit.extend(Fq6::square_montgomery(a_c1.clone()));
    //     let a_c1_square_beta = circuit.extend(Fq6::mul_by_nonresidue(a_c1_square.clone()));
    //     let norm = circuit.extend(Fq6::sub(a_c0_square, a_c1_square_beta));
    //     let inverse_norm = circuit.extend(Fq6::inverse_montgomery(norm));
    //     let res_c0 = circuit.extend(Fq6::mul_montgomery(a_c0, inverse_norm.clone()));
    //     let neg_a_c1 = circuit.extend(Fq6::neg(a_c1));
    //     let res_c1 = circuit.extend(Fq6::mul_montgomery(inverse_norm, neg_a_c1));

    //     circuit.add_wires(res_c0);
    //     circuit.add_wires(res_c1);
    //     circuit
    // }

    pub fn frobenius_montgomery(circuit: &mut Circuit, a: &Fq12, i: usize) -> Fq12 {
        let frobenius_a_c0 = Fq6::frobenius_montgomery(circuit, a.c0(), i);
        let frobenius_a_c1 = Fq6::frobenius_montgomery(circuit, a.c1(), i);
        let x = Fq6::mul_by_constant_fq2_montgomery(
            circuit,
            &frobenius_a_c1,
            &Fq2::as_montgomery(
                ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1
                    [i % ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1.len()],
            ),
        );
        Fq12::from_components(frobenius_a_c0, x)
    }

    pub fn conjugate(circuit: &mut Circuit, a: &Fq12) -> Fq12 {
        let new_c1 = Fq6::neg(circuit, a.c1().clone());
        Fq12::from_components(a.c0().clone(), new_c1)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ark_ff::CyclotomicMultSubgroup;
    use num_bigint::BigUint;

    use crate::gadgets::bn254::Fp254Impl;

    use super::*;
    use crate::test_utils::trng;

    fn random() -> ark_bn254::Fq12 {
        Fq12::random(&mut trng())
    }

    #[test]
    fn test_fq12_random() {
        let u = random();
        println!("u: {u:?}");
        let b = Fq12::to_bits(u);
        let v = Fq12::from_bits(b);
        println!("v: {v:?}");
        assert_eq!(u, v);
    }

    #[test]
    fn test_fq12_add() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);
        let b_wires = Fq12::new(&mut circuit, true, false);
        let c_wires = Fq12::add(&mut circuit, &a_wires.clone(), &b_wires.clone());

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let a_val = random();
        let b_val = random();
        let expected = a_val + b_val;

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let b_input = Fq12::get_wire_bits_fn(&b_wires, &b_val).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq12_neg() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);
        let c_wires = Fq12::neg(&mut circuit, a_wires.clone());

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let a_val = random();
        let expected = -a_val;

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq12_sub() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);
        let b_wires = Fq12::new(&mut circuit, true, false);
        let c_wires = Fq12::sub(&mut circuit, &a_wires, &b_wires);

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let a_val = random();
        let b_val = random();
        let expected = a_val - b_val;

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let b_input = Fq12::get_wire_bits_fn(&b_wires, &b_val).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq12_mul_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);
        let b_wires = Fq12::new(&mut circuit, true, false);
        let c_wires = Fq12::mul_montgomery(&mut circuit, &a_wires, &b_wires);

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let a_val = random();
        let b_val = random();
        let expected = Fq12::as_montgomery(a_val * b_val);

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &Fq12::as_montgomery(a_val)).unwrap();
        let b_input = Fq12::get_wire_bits_fn(&b_wires, &Fq12::as_montgomery(b_val)).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq12_mul_by_constant_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);

        let a_val = random();
        let b_val = random();
        let c_wires =
            Fq12::mul_by_constant_montgomery(&mut circuit, &a_wires, &Fq12::as_montgomery(b_val));

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let expected = Fq12::as_montgomery(a_val * b_val);

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &Fq12::as_montgomery(a_val)).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq12_mul_by_34_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);
        let c3_wires = Fq2::new(&mut circuit, true, false);
        let c4_wires = Fq2::new(&mut circuit, true, false);
        let c3_pair = (c3_wires.c0().0.clone(), c3_wires.c1().0.clone());
        let c4_pair = (c4_wires.c0().0.clone(), c4_wires.c1().0.clone());
        let c_wires = Fq12::mul_by_34_montgomery(&mut circuit, &a_wires, &c3_pair, &c4_pair);

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let a_val = random();
        let c3_val = Fq2::random(&mut trng());
        let c4_val = Fq2::random(&mut trng());

        let mut b = a_val;
        b.mul_by_034(&ark_bn254::Fq2::ONE, &c3_val, &c4_val);
        let expected = Fq12::as_montgomery(b);

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &Fq12::as_montgomery(a_val)).unwrap();
        let c3_input = Fq2::get_wire_bits_fn(&c3_wires, &Fq2::as_montgomery(c3_val)).unwrap();
        let c4_input = Fq2::get_wire_bits_fn(&c4_wires, &Fq2::as_montgomery(c4_val)).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| {
                (a_input)(wire_id)
                    .or((c3_input)(wire_id))
                    .or((c4_input)(wire_id))
            })
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq12_mul_by_034_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);
        let c0_wires = Fq2::new(&mut circuit, true, false);
        let c3_wires = Fq2::new(&mut circuit, true, false);
        let c4_wires = Fq2::new(&mut circuit, true, false);
        let c0_pair = (c0_wires.c0().0.clone(), c0_wires.c1().0.clone());
        let c3_pair = (c3_wires.c0().0.clone(), c3_wires.c1().0.clone());
        let c4_pair = (c4_wires.c0().0.clone(), c4_wires.c1().0.clone());
        let c_wires =
            Fq12::mul_by_034_montgomery(&mut circuit, &a_wires, &c0_pair, &c3_pair, &c4_pair);

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let a_val = random();
        let c0_val = Fq2::random(&mut trng());
        let c3_val = Fq2::random(&mut trng());
        let c4_val = Fq2::random(&mut trng());

        let mut b = a_val;
        b.mul_by_034(&c0_val, &c3_val, &c4_val);
        let expected = Fq12::as_montgomery(b);

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &Fq12::as_montgomery(a_val)).unwrap();
        let c0_input = Fq2::get_wire_bits_fn(&c0_wires, &Fq2::as_montgomery(c0_val)).unwrap();
        let c3_input = Fq2::get_wire_bits_fn(&c3_wires, &Fq2::as_montgomery(c3_val)).unwrap();
        let c4_input = Fq2::get_wire_bits_fn(&c4_wires, &Fq2::as_montgomery(c4_val)).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| {
                (a_input)(wire_id)
                    .or((c0_input)(wire_id))
                    .or((c3_input)(wire_id))
                    .or((c4_input)(wire_id))
            })
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq12_mul_by_034_constant4_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);
        let c0_wires = Fq2::new(&mut circuit, true, false);
        let c3_wires = Fq2::new(&mut circuit, true, false);
        let c4_val = Fq2::random(&mut trng());
        let c0_pair = (c0_wires.c0().0.clone(), c0_wires.c1().0.clone());
        let c3_pair = (c3_wires.c0().0.clone(), c3_wires.c1().0.clone());
        let c_wires = Fq12::mul_by_034_constant4_montgomery(
            &mut circuit,
            &a_wires,
            &c0_pair,
            &c3_pair,
            &Fq2::as_montgomery(c4_val),
        );

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let a_val = random();
        let c0_val = Fq2::random(&mut trng());
        let c3_val = Fq2::random(&mut trng());

        let mut b = a_val;
        b.mul_by_034(&c0_val, &c3_val, &c4_val);
        let expected = Fq12::as_montgomery(b);

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &Fq12::as_montgomery(a_val)).unwrap();
        let c0_input = Fq2::get_wire_bits_fn(&c0_wires, &Fq2::as_montgomery(c0_val)).unwrap();
        let c3_input = Fq2::get_wire_bits_fn(&c3_wires, &Fq2::as_montgomery(c3_val)).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(|wire_id| {
                (a_input)(wire_id)
                    .or((c0_input)(wire_id))
                    .or((c3_input)(wire_id))
            })
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq12_square_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);
        let c_wires = Fq12::square_montgomery(&mut circuit, &a_wires);

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let a_val = random();
        let expected = Fq12::as_montgomery(a_val * a_val);

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &Fq12::as_montgomery(a_val)).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq12_cyclotomic_square_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);
        let c_wires = Fq12::square_montgomery(&mut circuit, &a_wires);

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let p = Fq::modulus_as_biguint();
        let u = (p.pow(6) - BigUint::from_str("1").unwrap())
            * (p.pow(2) + BigUint::from_str("1").unwrap());
        let a_val = Fq12::random(&mut trng()).pow(u.to_u64_digits());
        let mut b = a_val;
        b.cyclotomic_square_in_place();
        let expected = Fq12::as_montgomery(b);

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &Fq12::as_montgomery(a_val)).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }

    #[test]
    fn test_fq12_frobenius_montgomery() {
        for i in [0, 1, 2, 3] {
            let mut circuit = Circuit::default();
            let a_wires = Fq12::new(&mut circuit, true, false);
            let c_wires = Fq12::frobenius_montgomery(&mut circuit, &a_wires, i);

            fq12element_mark_as_output(&mut circuit, &c_wires);

            let a_val = random();
            let mut expected = a_val;
            expected.frobenius_map_in_place(i);

            let a_input = Fq12::get_wire_bits_fn(&a_wires, &Fq12::as_montgomery(a_val)).unwrap();
            let c_output =
                Fq12::get_wire_bits_fn(&c_wires, &Fq12::as_montgomery(expected)).unwrap();

            circuit
                .simple_evaluate(a_input)
                .unwrap()
                .for_each(|(wire_id, value)| {
                    assert_eq!((c_output)(wire_id), Some(value));
                });
        }
    }

    #[test]
    fn test_fq12_conjugate() {
        let mut circuit = Circuit::default();
        let a_wires = Fq12::new(&mut circuit, true, false);
        let c_wires = Fq12::conjugate(&mut circuit, &a_wires);

        fq12element_mark_as_output(&mut circuit, &c_wires);

        let a_val = random();
        let mut expected = a_val;
        expected.conjugate_in_place();

        let a_input = Fq12::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq12::get_wire_bits_fn(&c_wires, &expected).unwrap();

        circuit
            .simple_evaluate(a_input)
            .unwrap()
            .for_each(|(wire_id, value)| {
                assert_eq!((c_output)(wire_id), Some(value));
            });
    }
}
