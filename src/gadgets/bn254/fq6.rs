use ark_ff::{AdditiveGroup, Field, Fp6Config, PrimeField, UniformRand};
use num_traits::Zero;
use rand::{Rng, rng};

use super::fq2::Pair;
use crate::{
    Circuit, CircuitContext, Gate, WireId,
    gadgets::{
        bigint::{self, BigIntWires, select},
        bn254::{fq::Fq, fq2::Fq2},
    },
};

pub type Fq6Components<T> = [Pair<T>; 3];

#[derive(Clone)]
pub struct Fq6(pub [Fq2; 3]);

impl Fq6 {
    pub const N_BITS: usize = 3 * Fq2::N_BITS;

    /// Access c0 component
    pub fn c0(&self) -> &Fq2 {
        &self.0[0]
    }

    /// Access c1 component
    pub fn c1(&self) -> &Fq2 {
        &self.0[1]
    }

    /// Access c2 component
    pub fn c2(&self) -> &Fq2 {
        &self.0[2]
    }

    /// Create new Fq6 from components
    pub fn from_components(c0: Fq2, c1: Fq2, c2: Fq2) -> Self {
        Fq6([c0, c1, c2])
    }

    /// Mark all components as output
    pub fn mark_as_output(&self, circuit: &mut Circuit) {
        self.c0().mark_as_output(circuit);
        self.c1().mark_as_output(circuit);
        self.c2().mark_as_output(circuit);
    }

    pub fn random(rng: &mut impl Rng) -> ark_bn254::Fq6 {
        ark_bn254::Fq6::new(Fq2::random(rng), Fq2::random(rng), Fq2::random(rng))
    }

    pub fn as_montgomery(a: ark_bn254::Fq6) -> ark_bn254::Fq6 {
        ark_bn254::Fq6::new(
            Fq2::as_montgomery(a.c0),
            Fq2::as_montgomery(a.c1),
            Fq2::as_montgomery(a.c2),
        )
    }

    pub fn from_montgomery(a: ark_bn254::Fq6) -> ark_bn254::Fq6 {
        ark_bn254::Fq6::new(
            Fq2::from_montgomery(a.c0),
            Fq2::from_montgomery(a.c1),
            Fq2::from_montgomery(a.c2),
        )
    }

    pub fn to_bits(u: ark_bn254::Fq6) -> Fq6Components<Vec<bool>> {
        [Fq2::to_bits(u.c0), Fq2::to_bits(u.c1), Fq2::to_bits(u.c2)]
    }

    pub fn from_bits(bits: Fq6Components<Vec<bool>>) -> ark_bn254::Fq6 {
        ark_bn254::Fq6::new(
            Fq2::from_bits(bits[0].clone()),
            Fq2::from_bits(bits[1].clone()),
            Fq2::from_bits(bits[2].clone()),
        )
    }

    pub fn new(circuit: &mut Circuit, is_input: bool, is_output: bool) -> Fq6 {
        Fq6([
            Fq2::new(circuit, is_input, is_output),
            Fq2::new(circuit, is_input, is_output),
            Fq2::new(circuit, is_input, is_output),
        ])
    }

    pub fn get_wire_bits_fn(
        wires: &Fq6,
        value: &ark_bn254::Fq6,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, crate::gadgets::bigint::Error> {
        let values = [value.c0, value.c1, value.c2];

        let c0_fn = Fq2::get_wire_bits_fn(wires.c0(), &values[0])?;
        let c1_fn = Fq2::get_wire_bits_fn(wires.c1(), &values[1])?;
        let c2_fn = Fq2::get_wire_bits_fn(wires.c2(), &values[2])?;

        Ok(move |wire_id| {
            c0_fn(wire_id)
                .or_else(|| c1_fn(wire_id))
                .or_else(|| c2_fn(wire_id))
        })
    }

    pub fn to_bitmask(wires: &Fq6, get_val: impl Fn(WireId) -> bool) -> String {
        let c0_mask = Fq2::to_bitmask(wires.c0(), &get_val);
        let c1_mask = Fq2::to_bitmask(wires.c1(), &get_val);
        let c2_mask = Fq2::to_bitmask(wires.c2(), &get_val);
        format!("c0: ({c0_mask}), c1: ({c1_mask}), c2: ({c2_mask})")
    }

    pub fn equal_constant(circuit: &mut Circuit, a: &Fq6, b: &ark_bn254::Fq6) -> WireId {
        let u = Fq2::equal_constant(circuit, a.c0(), &b.c0);
        let v = Fq2::equal_constant(circuit, a.c1(), &b.c1);
        let w = Fq2::equal_constant(circuit, a.c2(), &b.c2);
        let x = circuit.issue_wire();
        let y = circuit.issue_wire();
        circuit.add_gate(Gate::and(u, v, x));
        circuit.add_gate(Gate::and(x, w, y));
        y
    }

    pub fn add(circuit: &mut Circuit, a: &Fq6, b: &Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::add(circuit, a.c0(), b.c0()),
            Fq2::add(circuit, a.c1(), b.c1()),
            Fq2::add(circuit, a.c2(), b.c2()),
        )
    }

    pub fn neg(circuit: &mut Circuit, a: Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::neg(circuit, a.0[0].clone()),
            Fq2::neg(circuit, a.0[1].clone()),
            Fq2::neg(circuit, a.0[2].clone()),
        )
    }

    pub fn sub(circuit: &mut Circuit, a: &Fq6, b: &Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::sub(circuit, a.c0(), b.c0()),
            Fq2::sub(circuit, a.c1(), b.c1()),
            Fq2::sub(circuit, a.c2(), b.c2()),
        )
    }

    pub fn double(circuit: &mut Circuit, a: &Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::double(circuit, a.c0()),
            Fq2::double(circuit, a.c1()),
            Fq2::double(circuit, a.c2()),
        )
    }

    pub fn div6(circuit: &mut Circuit, a: &Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::div6(circuit, a.c0()),
            Fq2::div6(circuit, a.c1()),
            Fq2::div6(circuit, a.c2()),
        )
    }

    pub fn mul_montgomery(circuit: &mut Circuit, a: &Fq6, b: &Fq6) -> Fq6 {
        let a_c0 = a.c0();
        let a_c1 = a.c1();
        let a_c2 = a.c2();
        let b_c0 = b.c0();
        let b_c1 = b.c1();
        let b_c2 = b.c2();

        let v0 = Fq2::mul_montgomery(circuit, a_c0, b_c0);

        let wires_2 = Fq2::add(circuit, a_c0, a_c2);
        let wires_3 = Fq2::add(circuit, &wires_2, a_c1);
        let wires_4 = Fq2::sub(circuit, &wires_2, a_c1);
        let wires_5 = Fq2::double(circuit, a_c1);
        let wires_6 = Fq2::double(circuit, a_c2);
        let wires_7 = Fq2::double(circuit, &wires_6);
        let wires_8 = Fq2::add(circuit, a_c0, &wires_5);
        let wires_9 = Fq2::add(circuit, &wires_8, &wires_7);

        let wires_10 = Fq2::add(circuit, b_c0, b_c2);
        let wires_11 = Fq2::add(circuit, &wires_10, b_c1);
        let wires_12 = Fq2::sub(circuit, &wires_10, b_c1);
        let wires_13 = Fq2::double(circuit, b_c1);
        let wires_14 = Fq2::double(circuit, b_c2);
        let wires_15 = Fq2::double(circuit, &wires_14);
        let wires_16 = Fq2::add(circuit, b_c0, &wires_13);
        let wires_17 = Fq2::add(circuit, &wires_16, &wires_15);

        let v1 = Fq2::mul_montgomery(circuit, &wires_3, &wires_11);
        let v2 = Fq2::mul_montgomery(circuit, &wires_4, &wires_12);
        let v3 = Fq2::mul_montgomery(circuit, &wires_9, &wires_17);
        let v4 = Fq2::mul_montgomery(circuit, a_c2, b_c2);

        let v2_2 = Fq2::double(circuit, &v2);

        let v0_3 = Fq2::triple(circuit, &v0);
        let v1_3 = Fq2::triple(circuit, &v1);
        let v2_3 = Fq2::triple(circuit, &v2);
        let v4_3 = Fq2::triple(circuit, &v4);

        let v0_6 = Fq2::double(circuit, &v0_3);
        let v1_6 = Fq2::double(circuit, &v1_3);
        let v4_6 = Fq2::double(circuit, &v4_3);

        let v4_12 = Fq2::double(circuit, &v4_6);

        let wires_18 = Fq2::sub(circuit, &v0_3, &v1_3);
        let wires_19 = Fq2::sub(circuit, &wires_18, &v2);
        let wires_20 = Fq2::add(circuit, &wires_19, &v3);
        let wires_21 = Fq2::sub(circuit, &wires_20, &v4_12);
        let wires_22 = Fq2::mul_by_nonresidue(circuit, &wires_21);
        let c0 = Fq2::add(circuit, &wires_22, &v0_6);

        let wires_23 = Fq2::sub(circuit, &v1_6, &v0_3);
        let wires_24 = Fq2::sub(circuit, &wires_23, &v2_2);
        let wires_25 = Fq2::sub(circuit, &wires_24, &v3);
        let wires_26 = Fq2::add(circuit, &wires_25, &v4_12);
        let wires_27 = Fq2::mul_by_nonresidue(circuit, &v4_6);
        let c1 = Fq2::add(circuit, &wires_26, &wires_27);

        let wires_28 = Fq2::sub(circuit, &v1_3, &v0_6);
        let wires_29 = Fq2::add(circuit, &wires_28, &v2_3);
        let c2 = Fq2::sub(circuit, &wires_29, &v4_6);

        let result = Fq6::from_components(c0, c1, c2);
        Self::div6(circuit, &result)
    }

    pub fn mul_by_constant_montgomery(circuit: &mut Circuit, a: &Fq6, b: &ark_bn254::Fq6) -> Fq6 {
        let a_c0 = a.c0();
        let a_c1 = a.c1();
        let a_c2 = a.c2();

        let v0 = Fq2::mul_by_constant_montgomery(circuit, a_c0, &b.c0);

        let wires_2 = Fq2::add(circuit, a_c0, a_c2);
        let wires_3 = Fq2::add(circuit, &wires_2, a_c1);
        let wires_4 = Fq2::sub(circuit, &wires_2, a_c1);
        let wires_5 = Fq2::double(circuit, a_c1);
        let wires_6 = Fq2::double(circuit, a_c2);
        let wires_7 = Fq2::double(circuit, &wires_6);
        let wires_8 = Fq2::add(circuit, a_c0, &wires_5);
        let wires_9 = Fq2::add(circuit, &wires_8, &wires_7);

        let v1 = Fq2::mul_by_constant_montgomery(circuit, &wires_3, &(b.c0 + b.c1 + b.c2));
        let v2 = Fq2::mul_by_constant_montgomery(circuit, &wires_4, &(b.c0 - b.c1 + b.c2));
        let v3 = Fq2::mul_by_constant_montgomery(
            circuit,
            &wires_9,
            &(b.c0 + b.c1.double() + b.c2.double().double()),
        );
        let v4 = Fq2::mul_by_constant_montgomery(circuit, a_c2, &b.c2);

        let v2_2 = Fq2::double(circuit, &v2);

        let v0_3 = Fq2::triple(circuit, &v0);
        let v1_3 = Fq2::triple(circuit, &v1);
        let v2_3 = Fq2::triple(circuit, &v2);
        let v4_3 = Fq2::triple(circuit, &v4);

        let v0_6 = Fq2::double(circuit, &v0_3);
        let v1_6 = Fq2::double(circuit, &v1_3);
        let v4_6 = Fq2::double(circuit, &v4_3);

        let v4_12 = Fq2::double(circuit, &v4_6);

        let wires_18 = Fq2::sub(circuit, &v0_3, &v1_3);
        let wires_19 = Fq2::sub(circuit, &wires_18, &v2);
        let wires_20 = Fq2::add(circuit, &wires_19, &v3);
        let wires_21 = Fq2::sub(circuit, &wires_20, &v4_12);
        let wires_22 = Fq2::mul_by_nonresidue(circuit, &wires_21);
        let c0 = Fq2::add(circuit, &wires_22, &v0_6);

        let wires_23 = Fq2::sub(circuit, &v1_6, &v0_3);
        let wires_24 = Fq2::sub(circuit, &wires_23, &v2_2);
        let wires_25 = Fq2::sub(circuit, &wires_24, &v3);
        let wires_26 = Fq2::add(circuit, &wires_25, &v4_12);
        let wires_27 = Fq2::mul_by_nonresidue(circuit, &v4_6);
        let c1 = Fq2::add(circuit, &wires_26, &wires_27);

        let wires_28 = Fq2::sub(circuit, &v1_3, &v0_6);
        let wires_29 = Fq2::add(circuit, &wires_28, &v2_3);
        let c2 = Fq2::sub(circuit, &wires_29, &v4_6);

        let result = Fq6::from_components(c0, c1, c2);
        Self::div6(circuit, &result)
    }

    pub fn mul_by_fq2_montgomery(circuit: &mut Circuit, a: &Fq6, b: &Fq2) -> Fq6 {
        Fq6::from_components(
            Fq2::mul_montgomery(circuit, a.c0(), b),
            Fq2::mul_montgomery(circuit, a.c1(), b),
            Fq2::mul_montgomery(circuit, a.c2(), b),
        )
    }

    pub fn mul_by_constant_fq2_montgomery(
        circuit: &mut Circuit,
        a: &Fq6,
        b: &ark_bn254::Fq2,
    ) -> Fq6 {
        Fq6::from_components(
            Fq2::mul_by_constant_montgomery(circuit, a.c0(), b),
            Fq2::mul_by_constant_montgomery(circuit, a.c1(), b),
            Fq2::mul_by_constant_montgomery(circuit, a.c2(), b),
        )
    }

    pub fn mul_by_nonresidue(circuit: &mut Circuit, a: &Fq6) -> Fq6 {
        let u = Fq2::mul_by_nonresidue(circuit, a.c2());
        Fq6::from_components(u, a.c0().clone(), a.c1().clone())
    }

    pub fn mul_by_01_montgomery(circuit: &mut Circuit, a: &Fq6, c0: &Fq2, c1: &Fq2) -> Fq6 {
        let a_c0 = a.c0();
        let a_c1 = a.c1();
        let a_c2 = a.c2();

        let wires_1 = Fq2::mul_montgomery(circuit, a_c0, c0);
        let wires_2 = Fq2::mul_montgomery(circuit, a_c1, c1);
        let wires_3 = Fq2::add(circuit, a_c1, a_c2);
        let wires_4 = Fq2::mul_montgomery(circuit, &wires_3, c1);
        let wires_5 = Fq2::sub(circuit, &wires_4, &wires_2);
        let wires_6 = Fq2::mul_by_nonresidue(circuit, &wires_5);
        let wires_7 = Fq2::add(circuit, &wires_6, &wires_1);
        let wires_8 = Fq2::add(circuit, a_c0, a_c1);
        let wires_9 = Fq2::add(circuit, c0, c1);
        let wires_10 = Fq2::mul_montgomery(circuit, &wires_8, &wires_9);
        let wires_11 = Fq2::sub(circuit, &wires_10, &wires_1);
        let wires_12 = Fq2::sub(circuit, &wires_11, &wires_2);
        let wires_13 = Fq2::add(circuit, a_c0, a_c2);
        let wires_14 = Fq2::mul_montgomery(circuit, &wires_13, c0);
        let wires_15 = Fq2::sub(circuit, &wires_14, &wires_1);
        let wires_16 = Fq2::add(circuit, &wires_15, &wires_2);

        Fq6::from_components(wires_7, wires_12, wires_16)
    }

    pub fn mul_by_01_constant1_montgomery(
        circuit: &mut Circuit,
        a: &Fq6,
        c0: &Fq2,
        c1: &ark_bn254::Fq2,
    ) -> Fq6 {
        let a_c0 = a.c0();
        let a_c1 = a.c1();
        let a_c2 = a.c2();

        let wires_1 = Fq2::mul_montgomery(circuit, a_c0, c0);
        let wires_2 = Fq2::mul_by_constant_montgomery(circuit, a_c1, c1);
        let wires_3 = Fq2::add(circuit, a_c1, a_c2);
        let wires_4 = Fq2::mul_by_constant_montgomery(circuit, &wires_3, c1);
        let wires_5 = Fq2::sub(circuit, &wires_4, &wires_2);
        let wires_6 = Fq2::mul_by_nonresidue(circuit, &wires_5);
        let wires_7 = Fq2::add(circuit, &wires_6, &wires_1);
        let wires_8 = Fq2::add(circuit, a_c0, a_c1);
        let wires_9 = Fq2::add_constant(circuit, c0, c1);
        let wires_10 = Fq2::mul_montgomery(circuit, &wires_8, &wires_9);
        let wires_11 = Fq2::sub(circuit, &wires_10, &wires_1);
        let wires_12 = Fq2::sub(circuit, &wires_11, &wires_2);
        let wires_13 = Fq2::add(circuit, a_c0, a_c2);
        let wires_14 = Fq2::mul_montgomery(circuit, &wires_13, c0);
        let wires_15 = Fq2::sub(circuit, &wires_14, &wires_1);
        let wires_16 = Fq2::add(circuit, &wires_15, &wires_2);

        Fq6::from_components(wires_7, wires_12, wires_16)
    }

    pub fn triple(circuit: &mut Circuit, a: &Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::triple(circuit, a.c0()),
            Fq2::triple(circuit, a.c1()),
            Fq2::triple(circuit, a.c2()),
        )
    }

    // https://eprint.iacr.org/2006/471.pdf
    pub fn square_montgomery(circuit: &mut Circuit, a: &Fq6) -> Fq6 {
        let a_c0 = a.c0();
        let a_c1 = a.c1();
        let a_c2 = a.c2();

        let s_0 = Fq2::square_montgomery(circuit, a_c0);
        let wires_1 = Fq2::add(circuit, a_c0, a_c2);
        let wires_2 = Fq2::add(circuit, &wires_1, a_c1);
        let wires_3 = Fq2::sub(circuit, &wires_1, a_c1);
        let s_1 = Fq2::square_montgomery(circuit, &wires_2);
        let s_2 = Fq2::square_montgomery(circuit, &wires_3);
        let wires_4 = Fq2::mul_montgomery(circuit, a_c1, a_c2);
        let s_3 = Fq2::double(circuit, &wires_4);
        let s_4 = Fq2::square_montgomery(circuit, a_c2);
        let wires_5 = Fq2::add(circuit, &s_1, &s_2);
        let t_1 = Fq2::half(circuit, &wires_5);

        let wires_6 = Fq2::mul_by_nonresidue(circuit, &s_3);
        let res_c0 = Fq2::add(circuit, &s_0, &wires_6);
        let wires_7 = Fq2::mul_by_nonresidue(circuit, &s_4);
        let wires_8 = Fq2::sub(circuit, &s_1, &s_3);
        let wires_9 = Fq2::sub(circuit, &wires_8, &t_1);
        let res_c1 = Fq2::add(circuit, &wires_9, &wires_7);
        let wires_10 = Fq2::sub(circuit, &t_1, &s_0);
        let res_c2 = Fq2::sub(circuit, &wires_10, &s_4);

        Fq6::from_components(res_c0, res_c1, res_c2)
    }

    pub fn inverse_montgomery(circuit: &mut Circuit, r: &Fq6) -> Fq6 {
        let a = r.c0();
        let b = r.c1();
        let c = r.c2();

        let a_square = Fq2::square_montgomery(circuit, a);
        let b_square = Fq2::square_montgomery(circuit, b);
        let c_square = Fq2::square_montgomery(circuit, c);

        let ab = Fq2::mul_montgomery(circuit, a, b);
        let ac = Fq2::mul_montgomery(circuit, a, c);
        let bc = Fq2::mul_montgomery(circuit, b, c);

        let bc_beta = Fq2::mul_by_nonresidue(circuit, &bc);

        let a_square_minus_bc_beta = Fq2::sub(circuit, &a_square, &bc_beta);

        let c_square_beta = Fq2::mul_by_nonresidue(circuit, &c_square);
        let c_square_beta_minus_ab = Fq2::sub(circuit, &c_square_beta, &ab);
        let b_square_minus_ac = Fq2::sub(circuit, &b_square, &ac);

        let wires_1 = Fq2::mul_montgomery(circuit, &c_square_beta_minus_ab, c);

        let wires_2 = Fq2::mul_montgomery(circuit, &b_square_minus_ac, b);

        let wires_1_plus_wires_2 = Fq2::add(circuit, &wires_1, &wires_2);
        let wires_3 = Fq2::mul_by_nonresidue(circuit, &wires_1_plus_wires_2);

        let wires_4 = Fq2::mul_montgomery(circuit, a, &a_square_minus_bc_beta);
        let norm = Fq2::add(circuit, &wires_4, &wires_3);

        let inverse_norm = Fq2::inverse_montgomery(circuit, &norm);
        let res_c0 = Fq2::mul_montgomery(circuit, &a_square_minus_bc_beta, &inverse_norm);
        let res_c1 = Fq2::mul_montgomery(circuit, &c_square_beta_minus_ab, &inverse_norm);
        let res_c2 = Fq2::mul_montgomery(circuit, &b_square_minus_ac, &inverse_norm);

        Fq6::from_components(res_c0, res_c1, res_c2)
    }

    pub fn frobenius_montgomery(circuit: &mut Circuit, a: &Fq6, i: usize) -> Fq6 {
        let frobenius_a_c0 = Fq2::frobenius_montgomery(circuit, a.c0(), i);
        let frobenius_a_c1 = Fq2::frobenius_montgomery(circuit, a.c1(), i);
        let frobenius_a_c2 = Fq2::frobenius_montgomery(circuit, a.c2(), i);
        let frobenius_a_c1_updated = Fq2::mul_by_constant_montgomery(
            circuit,
            &frobenius_a_c1,
            &Fq2::as_montgomery(
                ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C1
                    [i % ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C1.len()],
            ),
        );
        let frobenius_a_c2_updated = Fq2::mul_by_constant_montgomery(
            circuit,
            &frobenius_a_c2,
            &Fq2::as_montgomery(
                ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C2
                    [i % ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C2.len()],
            ),
        );

        Fq6::from_components(
            frobenius_a_c0,
            frobenius_a_c1_updated,
            frobenius_a_c2_updated,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use ark_ff::{AdditiveGroup, Field, Fp12Config};

    use super::*;
    use crate::test_utils::trng;

    fn random() -> ark_bn254::Fq6 {
        Fq6::random(&mut trng())
    }

    #[test]
    fn test_fq6_random() {
        let u = random();
        println!("u: {u:?}");
        let b = Fq6::to_bits(u);
        let v = Fq6::from_bits(b);
        println!("v: {v:?}");
        assert_eq!(u, v);
    }

    #[test]
    fn test_fq6_add() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let b_wires = Fq6::new(&mut circuit, true, false);
        let c_wires = Fq6::add(&mut circuit, &a_wires, &b_wires);

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let b_val = random();
        let expected = a_val + b_val;

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let b_input = Fq6::get_wire_bits_fn(&b_wires, &b_val).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_neg() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let c_wires = Fq6::neg(&mut circuit, a_wires.clone());

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = -a_val;

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_sub() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let b_wires = Fq6::new(&mut circuit, true, false);
        let c_wires = Fq6::sub(&mut circuit, &a_wires, &b_wires);

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let b_val = random();
        let expected = a_val - b_val;

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let b_input = Fq6::get_wire_bits_fn(&b_wires, &b_val).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_double() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let c_wires = Fq6::double(&mut circuit, &a_wires);

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = a_val + a_val;

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_div6() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let c_wires = Fq6::div6(&mut circuit, &a_wires);

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = a_val / ark_bn254::Fq6::from(6u32);

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_mul_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let b_wires = Fq6::new(&mut circuit, true, false);
        let c_wires = Fq6::mul_montgomery(&mut circuit, &a_wires, &b_wires);

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let b_val = random();
        let expected = Fq6::as_montgomery(a_val * b_val);

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &Fq6::as_montgomery(a_val)).unwrap();
        let b_input = Fq6::get_wire_bits_fn(&b_wires, &Fq6::as_montgomery(b_val)).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_mul_by_constant_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);

        let a_val = random();
        let b_val = random();
        let c_wires =
            Fq6::mul_by_constant_montgomery(&mut circuit, &a_wires, &Fq6::as_montgomery(b_val));

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let expected = Fq6::as_montgomery(a_val * b_val);

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &Fq6::as_montgomery(a_val)).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_mul_by_fq2_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let b_wires = Fq2::new(&mut circuit, true, false);
        let c_wires = Fq6::mul_by_fq2_montgomery(&mut circuit, &a_wires, &b_wires);

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let b_val = Fq2::random(&mut trng());
        let expected = Fq6::as_montgomery(
            a_val * ark_bn254::Fq6::new(b_val, ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO),
        );

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &Fq6::as_montgomery(a_val)).unwrap();
        let b_input = Fq2::get_wire_bits_fn(&b_wires, &Fq2::as_montgomery(b_val)).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_mul_by_constant_fq2_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);

        let a_val = random();
        let b_val = Fq2::random(&mut trng());
        let c_wires =
            Fq6::mul_by_constant_fq2_montgomery(&mut circuit, &a_wires, &Fq2::as_montgomery(b_val));

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let expected = Fq6::as_montgomery(
            a_val * ark_bn254::Fq6::new(b_val, ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO),
        );

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &Fq6::as_montgomery(a_val)).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_mul_by_nonresidue() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let c_wires = Fq6::mul_by_nonresidue(&mut circuit, &a_wires);

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let mut expected = a_val;
        ark_bn254::Fq12Config::mul_fp6_by_nonresidue_in_place(&mut expected);

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_square_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let c_wires = Fq6::square_montgomery(&mut circuit, &a_wires);

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = Fq6::as_montgomery(a_val * a_val);

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &Fq6::as_montgomery(a_val)).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_inverse_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let c_wires = Fq6::inverse_montgomery(&mut circuit, &a_wires);

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = Fq6::as_montgomery(a_val.inverse().unwrap());

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &Fq6::as_montgomery(a_val)).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_mul_by_01_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let c0_wires = Fq2::new(&mut circuit, true, false);
        let c1_wires = Fq2::new(&mut circuit, true, false);
        let result_wires = Fq6::mul_by_01_montgomery(&mut circuit, &a_wires, &c0_wires, &c1_wires);

        // Mark outputs
        result_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let c0_val = Fq2::random(&mut trng());
        let c1_val = Fq2::random(&mut trng());
        let mut expected = a_val;
        expected.mul_by_01(&c0_val, &c1_val);
        let expected = Fq6::as_montgomery(expected);

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &Fq6::as_montgomery(a_val)).unwrap();
        let c0_input = Fq2::get_wire_bits_fn(&c0_wires, &Fq2::as_montgomery(c0_val)).unwrap();
        let c1_input = Fq2::get_wire_bits_fn(&c1_wires, &Fq2::as_montgomery(c1_val)).unwrap();
        let result_output = Fq6::get_wire_bits_fn(&result_wires, &expected).unwrap();

        let actual_result = circuit
            .simple_evaluate(|wire_id| {
                (a_input)(wire_id)
                    .or((c0_input)(wire_id))
                    .or((c1_input)(wire_id))
            })
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&result_wires, |wire_id| result_output(wire_id).unwrap()),
            Fq6::to_bitmask(&result_wires, |wire_id| *actual_result.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_mul_by_01_constant1_montgomery() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let c0_wires = Fq2::new(&mut circuit, true, false);

        let a_val = random();
        let c0_val = Fq2::random(&mut trng());
        let c1_val = Fq2::random(&mut trng());

        let result_wires = Fq6::mul_by_01_constant1_montgomery(
            &mut circuit,
            &a_wires,
            &c0_wires,
            &Fq2::as_montgomery(c1_val),
        );

        // Mark outputs
        result_wires.mark_as_output(&mut circuit);

        let mut expected = a_val;
        expected.mul_by_01(&c0_val, &c1_val);
        let expected = Fq6::as_montgomery(expected);

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &Fq6::as_montgomery(a_val)).unwrap();
        let c0_input = Fq2::get_wire_bits_fn(&c0_wires, &Fq2::as_montgomery(c0_val)).unwrap();
        let result_output = Fq6::get_wire_bits_fn(&result_wires, &expected).unwrap();

        let actual_result = circuit
            .simple_evaluate(|wire_id| (a_input)(wire_id).or((c0_input)(wire_id)))
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&result_wires, |wire_id| result_output(wire_id).unwrap()),
            Fq6::to_bitmask(&result_wires, |wire_id| *actual_result.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_triple() {
        let mut circuit = Circuit::default();
        let a_wires = Fq6::new(&mut circuit, true, false);
        let c_wires = Fq6::triple(&mut circuit, &a_wires);

        // Mark outputs
        c_wires.mark_as_output(&mut circuit);

        let a_val = random();
        let expected = a_val + a_val + a_val;

        let a_input = Fq6::get_wire_bits_fn(&a_wires, &a_val).unwrap();
        let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

        let actual_c = circuit
            .simple_evaluate(a_input)
            .unwrap()
            .collect::<HashMap<WireId, bool>>();

        assert_eq!(
            Fq6::to_bitmask(&c_wires, |wire_id| c_output(wire_id).unwrap()),
            Fq6::to_bitmask(&c_wires, |wire_id| *actual_c.get(&wire_id).unwrap())
        );
    }

    #[test]
    fn test_fq6_frobenius_montgomery() {
        let a_val = random();

        // Test frobenius_map(0)
        {
            let mut circuit = Circuit::default();
            let a_wires = Fq6::new(&mut circuit, true, false);
            let c_wires = Fq6::frobenius_montgomery(&mut circuit, &a_wires, 0);

            // Mark outputs
            c_wires.mark_as_output(&mut circuit);

            let expected = Fq6::as_montgomery(a_val.frobenius_map(0));

            let a_input = Fq6::get_wire_bits_fn(&a_wires, &Fq6::as_montgomery(a_val)).unwrap();
            let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

            circuit
                .simple_evaluate(a_input)
                .unwrap()
                .for_each(|(wire_id, value)| {
                    assert_eq!((c_output)(wire_id), Some(value));
                });
        }

        // Test frobenius_map(1)
        {
            let mut circuit = Circuit::default();
            let a_wires = Fq6::new(&mut circuit, true, false);
            let c_wires = Fq6::frobenius_montgomery(&mut circuit, &a_wires, 1);

            // Mark outputs
            c_wires.mark_as_output(&mut circuit);

            let expected = Fq6::as_montgomery(a_val.frobenius_map(1));

            let a_input = Fq6::get_wire_bits_fn(&a_wires, &Fq6::as_montgomery(a_val)).unwrap();
            let c_output = Fq6::get_wire_bits_fn(&c_wires, &expected).unwrap();

            circuit
                .simple_evaluate(a_input)
                .unwrap()
                .for_each(|(wire_id, value)| {
                    assert_eq!((c_output)(wire_id), Some(value));
                });
        }
    }
}
