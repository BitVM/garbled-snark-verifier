use ark_ff::{AdditiveGroup, Field, Fp6Config, PrimeField, UniformRand};
use num_traits::Zero;
use rand::Rng;

use super::fq2::Pair;
use crate::{
    CircuitContext, Gate, WireId,
    circuit::streaming::IntoWireList,
    gadgets::{
        bigint::{self},
        bn254::fq2::Fq2,
    },
};

pub type Fq6Components<T> = [Pair<T>; 3];

#[derive(Clone)]
pub struct Fq6(pub [Fq2; 3]);

impl IntoWireList for Fq6 {
    fn into_wire_list(self) -> Vec<WireId> {
        self.0
            .into_iter()
            .flat_map(|fq2| fq2.into_wire_list())
            .collect()
    }
}

impl IntoWireList for &Fq6 {
    fn into_wire_list(self) -> Vec<WireId> {
        self.0.iter().flat_map(|fq2| fq2.into_wire_list()).collect()
    }
}

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

    pub fn new<C: CircuitContext>(circuit: &mut C) -> Fq6 {
        Fq6([Fq2::new(circuit), Fq2::new(circuit), Fq2::new(circuit)])
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

    pub fn equal_constant<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq6,
        b: &ark_bn254::Fq6,
    ) -> WireId {
        let u = Fq2::equal_constant(circuit, a.c0(), &b.c0);
        let v = Fq2::equal_constant(circuit, a.c1(), &b.c1);
        let w = Fq2::equal_constant(circuit, a.c2(), &b.c2);
        let x = circuit.issue_wire();
        let y = circuit.issue_wire();
        circuit.add_gate(Gate::and(u, v, x));
        circuit.add_gate(Gate::and(x, w, y));
        y
    }

    pub fn add<C: CircuitContext>(circuit: &mut C, a: &Fq6, b: &Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::add(circuit, a.c0(), b.c0()),
            Fq2::add(circuit, a.c1(), b.c1()),
            Fq2::add(circuit, a.c2(), b.c2()),
        )
    }

    pub fn neg<C: CircuitContext>(circuit: &mut C, a: Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::neg(circuit, a.0[0].clone()),
            Fq2::neg(circuit, a.0[1].clone()),
            Fq2::neg(circuit, a.0[2].clone()),
        )
    }

    pub fn sub<C: CircuitContext>(circuit: &mut C, a: &Fq6, b: &Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::sub(circuit, a.c0(), b.c0()),
            Fq2::sub(circuit, a.c1(), b.c1()),
            Fq2::sub(circuit, a.c2(), b.c2()),
        )
    }

    pub fn double<C: CircuitContext>(circuit: &mut C, a: &Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::double(circuit, a.c0()),
            Fq2::double(circuit, a.c1()),
            Fq2::double(circuit, a.c2()),
        )
    }

    pub fn div6<C: CircuitContext>(circuit: &mut C, a: &Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::div6(circuit, a.c0()),
            Fq2::div6(circuit, a.c1()),
            Fq2::div6(circuit, a.c2()),
        )
    }

    pub fn mul_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq6, b: &Fq6) -> Fq6 {
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

    pub fn mul_by_constant_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq6,
        b: &ark_bn254::Fq6,
    ) -> Fq6 {
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

    pub fn mul_by_fq2_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq6, b: &Fq2) -> Fq6 {
        Fq6::from_components(
            Fq2::mul_montgomery(circuit, a.c0(), b),
            Fq2::mul_montgomery(circuit, a.c1(), b),
            Fq2::mul_montgomery(circuit, a.c2(), b),
        )
    }

    pub fn mul_by_constant_fq2_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq6,
        b: &ark_bn254::Fq2,
    ) -> Fq6 {
        Fq6::from_components(
            Fq2::mul_by_constant_montgomery(circuit, a.c0(), b),
            Fq2::mul_by_constant_montgomery(circuit, a.c1(), b),
            Fq2::mul_by_constant_montgomery(circuit, a.c2(), b),
        )
    }

    pub fn mul_by_nonresidue<C: CircuitContext>(circuit: &mut C, a: &Fq6) -> Fq6 {
        let u = Fq2::mul_by_nonresidue(circuit, a.c2());
        Fq6::from_components(u, a.c0().clone(), a.c1().clone())
    }

    pub fn mul_by_01_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq6,
        c0: &Fq2,
        c1: &Fq2,
    ) -> Fq6 {
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

    pub fn mul_by_01_constant1_montgomery<C: CircuitContext>(
        circuit: &mut C,
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

    pub fn triple<C: CircuitContext>(circuit: &mut C, a: &Fq6) -> Fq6 {
        Fq6::from_components(
            Fq2::triple(circuit, a.c0()),
            Fq2::triple(circuit, a.c1()),
            Fq2::triple(circuit, a.c2()),
        )
    }

    // https://eprint.iacr.org/2006/471.pdf
    pub fn square_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq6) -> Fq6 {
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

    pub fn inverse_montgomery<C: CircuitContext>(circuit: &mut C, r: &Fq6) -> Fq6 {
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

    pub fn frobenius_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq6, i: usize) -> Fq6 {
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
    use ark_ff::{AdditiveGroup, Field, Fp12Config};

    use super::*;
    use crate::{
        CircuitContext,
        circuit::streaming::{
            CircuitBuilder, CircuitInput, CircuitOutput, EncodeInput, Execute, IntoWireList,
            modes::CircuitMode,
        },
        gadgets::{
            bigint::{BigUint as BigUintOutput, bits_from_biguint_with_len},
            bn254::fp254impl::Fp254Impl,
        },
        test_utils::trng,
    };

    fn random() -> ark_bn254::Fq6 {
        Fq6::random(&mut trng())
    }

    // Input struct for Fq6 tests
    struct Fq6Input<const N: usize> {
        values: [ark_bn254::Fq6; N],
    }

    impl<const N: usize> Fq6Input<N> {
        fn new(values: [ark_bn254::Fq6; N]) -> Self {
            Self { values }
        }
    }

    impl<const N: usize> CircuitInput for Fq6Input<N> {
        type WireRepr = [Fq6; N];

        fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
            std::array::from_fn(|_| Fq6::new(ctx))
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.iter().flat_map(|fq6| fq6.into_wire_list()).collect()
        }
    }

    impl<const N: usize> EncodeInput<Execute> for Fq6Input<N> {
        fn encode(self, repr: &Self::WireRepr, cache: &mut Execute) {
            self.values
                .iter()
                .zip(repr.iter())
                .for_each(|(val, wires)| {
                    let v = val;
                    // encode c0
                    let c0_c0_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(v.c0.c0.into_bigint()),
                        crate::gadgets::bn254::fq::Fq::N_BITS,
                    )
                    .unwrap();
                    let c0_c1_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(v.c0.c1.into_bigint()),
                        crate::gadgets::bn254::fq::Fq::N_BITS,
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

                    // encode c1
                    let c1_c0_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(v.c1.c0.into_bigint()),
                        crate::gadgets::bn254::fq::Fq::N_BITS,
                    )
                    .unwrap();
                    let c1_c1_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(v.c1.c1.into_bigint()),
                        crate::gadgets::bn254::fq::Fq::N_BITS,
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

                    // encode c2
                    let c2_c0_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(v.c2.c0.into_bigint()),
                        crate::gadgets::bn254::fq::Fq::N_BITS,
                    )
                    .unwrap();
                    let c2_c1_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(v.c2.c1.into_bigint()),
                        crate::gadgets::bn254::fq::Fq::N_BITS,
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
                });
        }
    }

    // Output struct for Fq6 tests
    struct Fq6Output {
        value: ark_bn254::Fq6,
    }

    impl CircuitOutput<Execute> for Fq6Output {
        type WireRepr = Fq6;

        fn decode(wires: Self::WireRepr, cache: &Execute) -> Self {
            let c0_c0 =
                <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[0].0[0].0.clone(), cache);
            let c0_c1 =
                <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[0].0[1].0.clone(), cache);
            let c1_c0 =
                <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[1].0[0].0.clone(), cache);
            let c1_c1 =
                <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[1].0[1].0.clone(), cache);
            let c2_c0 =
                <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[2].0[0].0.clone(), cache);
            let c2_c1 =
                <BigUintOutput as CircuitOutput<Execute>>::decode(wires.0[2].0[1].0.clone(), cache);

            let c0 = ark_bn254::Fq2::new(ark_bn254::Fq::from(c0_c0), ark_bn254::Fq::from(c0_c1));
            let c1 = ark_bn254::Fq2::new(ark_bn254::Fq::from(c1_c0), ark_bn254::Fq::from(c1_c1));
            let c2 = ark_bn254::Fq2::new(ark_bn254::Fq::from(c2_c0), ark_bn254::Fq::from(c2_c1));
            let value = ark_bn254::Fq6::new(c0, c1, c2);
            Self { value }
        }
    }

    #[test]
    fn test_fq6_random() {
        let u = random();
        let b = Fq6::to_bits(u);
        let v = Fq6::from_bits(b);
        assert_eq!(u, v);
    }

    #[test]
    fn test_fq6_add() {
        let a = random();
        let b = random();
        let expected = a + b;

        let input = Fq6Input::new([a, b]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a, b] = input;
                Fq6::add(ctx, a, b)
            },
        );

        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_neg() {
        let a = random();
        let expected = -a;
        let input = Fq6Input::new([a]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a] = input;
                Fq6::neg(ctx, a.clone())
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_sub() {
        let a = random();
        let b = random();
        let expected = a - b;

        let input = Fq6Input::new([a, b]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a, b] = input;
                Fq6::sub(ctx, a, b)
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_double() {
        let a = random();
        let expected = a + a;
        let input = Fq6Input::new([a]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a] = input;
                Fq6::double(ctx, a)
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_div6() {
        let a = random();
        let expected = a / ark_bn254::Fq6::from(6u32);
        let input = Fq6Input::new([a]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a] = input;
                Fq6::div6(ctx, a)
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_mul_montgomery() {
        let a = random();
        let b = random();
        let expected = Fq6::as_montgomery(a * b);
        let input = Fq6Input::new([Fq6::as_montgomery(a), Fq6::as_montgomery(b)]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a, b] = input;
                Fq6::mul_montgomery(ctx, a, b)
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_mul_by_constant_montgomery() {
        let a = random();
        let b = random();
        let expected = Fq6::as_montgomery(a * b);
        let input = Fq6Input::new([Fq6::as_montgomery(a)]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a] = input;
                Fq6::mul_by_constant_montgomery(ctx, a, &Fq6::as_montgomery(b))
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_mul_by_fq2_montgomery() {
        // Custom input type containing both Fq6 and Fq2
        struct In {
            a: ark_bn254::Fq6,
            b: ark_bn254::Fq2,
        }
        struct InWire {
            a: Fq6,
            b: Fq2,
        }
        impl CircuitInput for In {
            type WireRepr = InWire;
            fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
                InWire {
                    a: Fq6::new(ctx),
                    b: Fq2::new(ctx),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = IntoWireList::into_wire_list(&repr.a);
                ids.extend(IntoWireList::into_wire_list(&repr.b));
                ids
            }
        }
        impl EncodeInput<Execute> for In {
            fn encode(self, repr: &InWire, cache: &mut Execute) {
                // encode a (Fq6) in montgomery form
                let a_m = Fq6::as_montgomery(self.a);
                // c0
                let c0_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c0.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c0_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c0.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.a.0[0].0[0]
                    .0
                    .iter()
                    .zip(c0_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.a.0[0].0[1]
                    .0
                    .iter()
                    .zip(c0_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                // c1
                let c1_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c1.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c1_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c1.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.a.0[1].0[0]
                    .0
                    .iter()
                    .zip(c1_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.a.0[1].0[1]
                    .0
                    .iter()
                    .zip(c1_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                // c2
                let c2_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c2.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c2_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c2.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.a.0[2].0[0]
                    .0
                    .iter()
                    .zip(c2_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.a.0[2].0[1]
                    .0
                    .iter()
                    .zip(c2_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));

                // encode b (Fq2) in montgomery form
                let b_m = Fq2::as_montgomery(self.b);
                let b0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(b_m.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let b1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(b_m.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.b.0[0]
                    .0
                    .iter()
                    .zip(b0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.b.0[1]
                    .0
                    .iter()
                    .zip(b1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
            }
        }

        let a = random();
        let b = crate::gadgets::bn254::fq2::Fq2::random(&mut trng());
        let expected = Fq6::as_montgomery(
            a * ark_bn254::Fq6::new(b, ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO),
        );

        let input = In { a, b };
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| Fq6::mul_by_fq2_montgomery(ctx, &input.a, &input.b),
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_mul_by_constant_fq2_montgomery() {
        let a = random();
        let b = crate::gadgets::bn254::fq2::Fq2::random(&mut trng());
        let expected = Fq6::as_montgomery(
            a * ark_bn254::Fq6::new(b, ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO),
        );

        let input = Fq6Input::new([Fq6::as_montgomery(a)]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a] = input;
                Fq6::mul_by_constant_fq2_montgomery(ctx, a, &Fq2::as_montgomery(b))
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_mul_by_nonresidue() {
        let a = random();
        let mut expected = a;
        ark_bn254::Fq12Config::mul_fp6_by_nonresidue_in_place(&mut expected);

        let input = Fq6Input::new([a]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a] = input;
                Fq6::mul_by_nonresidue(ctx, a)
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_square_montgomery() {
        let a = random();
        let expected = Fq6::as_montgomery(a * a);

        let input = Fq6Input::new([Fq6::as_montgomery(a)]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a] = input;
                Fq6::square_montgomery(ctx, a)
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_inverse_montgomery() {
        let a = random();
        let expected = Fq6::as_montgomery(a.inverse().unwrap());

        let input = Fq6Input::new([Fq6::as_montgomery(a)]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a] = input;
                Fq6::inverse_montgomery(ctx, a)
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_mul_by_01_montgomery() {
        // Input with a, c0, c1
        struct In {
            a: ark_bn254::Fq6,
            c0: ark_bn254::Fq2,
            c1: ark_bn254::Fq2,
        }
        struct InWire {
            a: Fq6,
            c0: Fq2,
            c1: Fq2,
        }
        impl CircuitInput for In {
            type WireRepr = InWire;
            fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
                InWire {
                    a: Fq6::new(ctx),
                    c0: Fq2::new(ctx),
                    c1: Fq2::new(ctx),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = IntoWireList::into_wire_list(&repr.a);
                ids.extend(IntoWireList::into_wire_list(&repr.c0));
                ids.extend(IntoWireList::into_wire_list(&repr.c1));
                ids
            }
        }
        impl EncodeInput<Execute> for In {
            fn encode(self, repr: &InWire, cache: &mut Execute) {
                // a in montgomery
                let a_m = Fq6::as_montgomery(self.a);
                // c0
                let c0_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c0.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c0_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c0.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.a.0[0].0[0]
                    .0
                    .iter()
                    .zip(c0_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.a.0[0].0[1]
                    .0
                    .iter()
                    .zip(c0_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                // c1
                let c1_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c1.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c1_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c1.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.a.0[1].0[0]
                    .0
                    .iter()
                    .zip(c1_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.a.0[1].0[1]
                    .0
                    .iter()
                    .zip(c1_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                // c2
                let c2_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c2.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c2_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c2.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.a.0[2].0[0]
                    .0
                    .iter()
                    .zip(c2_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.a.0[2].0[1]
                    .0
                    .iter()
                    .zip(c2_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                // c0, c1 in montgomery
                let c0_m = Fq2::as_montgomery(self.c0);
                let c1_m = Fq2::as_montgomery(self.c1);
                let c0_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(c0_m.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c0_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(c0_m.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.c0.0[0]
                    .0
                    .iter()
                    .zip(c0_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.c0.0[1]
                    .0
                    .iter()
                    .zip(c0_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));

                let c1_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(c1_m.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c1_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(c1_m.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.c1.0[0]
                    .0
                    .iter()
                    .zip(c1_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.c1.0[1]
                    .0
                    .iter()
                    .zip(c1_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
            }
        }

        let a = random();
        let c0 = crate::gadgets::bn254::fq2::Fq2::random(&mut trng());
        let c1 = crate::gadgets::bn254::fq2::Fq2::random(&mut trng());
        let mut expected = a;
        expected.mul_by_01(&c0, &c1);
        let expected = Fq6::as_montgomery(expected);

        let input = In { a, c0, c1 };
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| Fq6::mul_by_01_montgomery(ctx, &input.a, &input.c0, &input.c1),
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_mul_by_01_constant1_montgomery() {
        // custom input with a and c0 wires
        struct In {
            a: ark_bn254::Fq6,
            c0: ark_bn254::Fq2,
        }
        struct InWire {
            a: Fq6,
            c0: Fq2,
        }
        impl CircuitInput for In {
            type WireRepr = InWire;
            fn allocate<C: CircuitContext>(&self, ctx: &mut C) -> Self::WireRepr {
                InWire {
                    a: Fq6::new(ctx),
                    c0: Fq2::new(ctx),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = IntoWireList::into_wire_list(&repr.a);
                ids.extend(IntoWireList::into_wire_list(&repr.c0));
                ids
            }
        }
        impl EncodeInput<Execute> for In {
            fn encode(self, repr: &InWire, cache: &mut Execute) {
                // a in montgomery
                let a_m = Fq6::as_montgomery(self.a);
                // c0
                let c0_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c0.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c0_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c0.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.a.0[0].0[0]
                    .0
                    .iter()
                    .zip(c0_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.a.0[0].0[1]
                    .0
                    .iter()
                    .zip(c0_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                // c1
                let c1_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c1.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c1_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c1.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.a.0[1].0[0]
                    .0
                    .iter()
                    .zip(c1_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.a.0[1].0[1]
                    .0
                    .iter()
                    .zip(c1_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                // c2
                let c2_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c2.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c2_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(a_m.c2.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.a.0[2].0[0]
                    .0
                    .iter()
                    .zip(c2_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.a.0[2].0[1]
                    .0
                    .iter()
                    .zip(c2_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));

                // c0 wires in montgomery
                let c0_m = Fq2::as_montgomery(self.c0);
                let c0_0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(c0_m.c0.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                let c0_1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(c0_m.c1.into_bigint()),
                    crate::gadgets::bn254::fq::Fq::N_BITS,
                )
                .unwrap();
                repr.c0.0[0]
                    .0
                    .iter()
                    .zip(c0_0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.c0.0[1]
                    .0
                    .iter()
                    .zip(c0_1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
            }
        }

        let a = random();
        let c0 = crate::gadgets::bn254::fq2::Fq2::random(&mut trng());
        let c1 = crate::gadgets::bn254::fq2::Fq2::random(&mut trng());
        let mut expected = a;
        expected.mul_by_01(&c0, &c1);
        let expected = Fq6::as_montgomery(expected);

        let input = In { a, c0 };
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                Fq6::mul_by_01_constant1_montgomery(
                    ctx,
                    &input.a,
                    &input.c0,
                    &Fq2::as_montgomery(c1),
                )
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_triple() {
        let a = random();
        let expected = a + a + a;
        let input = Fq6Input::new([a]);
        let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
            input,
            Execute::default(),
            |ctx, input| {
                let [a] = input;
                Fq6::triple(ctx, a)
            },
        );
        assert_eq!(result.output_wires.value, expected);
    }

    #[test]
    fn test_fq6_frobenius_montgomery() {
        let a_val = random();

        // i = 0
        {
            let input = Fq6Input::new([Fq6::as_montgomery(a_val)]);
            let expected = Fq6::as_montgomery(a_val.frobenius_map(0));
            let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
                input,
                Execute::default(),
                |ctx, input| {
                    let [a] = input;
                    Fq6::frobenius_montgomery(ctx, a, 0)
                },
            );
            assert_eq!(result.output_wires.value, expected);
        }

        // i = 1
        {
            let input = Fq6Input::new([Fq6::as_montgomery(a_val)]);
            let expected = Fq6::as_montgomery(a_val.frobenius_map(1));
            let result = CircuitBuilder::<Execute>::streaming_process::<_, _, Fq6Output>(
                input,
                Execute::default(),
                |ctx, input| {
                    let [a] = input;
                    Fq6::frobenius_montgomery(ctx, a, 1)
                },
            );
            assert_eq!(result.output_wires.value, expected);
        }
    }
}
