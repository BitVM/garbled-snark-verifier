use ark_ff::{Field, Fp12Config};
use circuit_component_macro::component;
use rand::Rng;

use super::fq6::Fq6Components;
use crate::{
    CircuitContext, Gate, WireId,
    circuit::{FromWires, WiresObject},
    gadgets::bn254::{fq::Fq, fq2::Fq2, fq6::Fq6},
};

pub type Fq12Element<T> = (Fq6Components<T>, Fq6Components<T>);

#[derive(Clone, Debug)]
pub struct Fq12(pub [Fq6; 2]);

impl WiresObject for Fq12 {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0[0]
            .to_wires_vec()
            .into_iter()
            .chain(self.0[1].to_wires_vec())
            .collect()
    }

    fn clone_from(&self, mut wire_gen: &mut impl FnMut() -> WireId) -> Self {
        let Self([fq6_1, fq6_2]) = self;

        Self([
            fq6_1.clone_from(&mut wire_gen),
            fq6_2.clone_from(&mut wire_gen),
        ])
    }
}

impl FromWires for Fq12 {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        if wires.len() >= 1524 {
            // 2 * 3 * 2 * 254 = 3048/2 = 1524 wires per Fq6
            let mid = wires.len() / 2;
            let fq6_1 = Fq6::from_wires(&wires[..mid])?;
            let fq6_2 = Fq6::from_wires(&wires[mid..])?;
            Some(Self([fq6_1, fq6_2]))
        } else {
            None
        }
    }
}

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

    pub fn len(&self) -> usize {
        self.0.iter().map(|fq6| fq6.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn new_constant(v: ark_bn254::Fq12) -> Fq12 {
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

    pub fn from_ctx<C: CircuitContext>(circuit: &mut C) -> Fq12 {
        Fq12([Fq6::from_ctx(circuit), Fq6::from_ctx(circuit)])
    }

    pub fn new(mut issue: impl FnMut() -> WireId) -> Fq12 {
        Fq12([Fq6::new(&mut issue), Fq6::new(issue)])
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

    pub fn equal_constant<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq12,
        b: &ark_bn254::Fq12,
    ) -> WireId {
        let u = Fq6::equal_constant(circuit, a.c0(), &b.c0);
        let v = Fq6::equal_constant(circuit, a.c1(), &b.c1);
        let w = circuit.issue_wire();
        circuit.add_gate(Gate::and(u, v, w));
        w
    }

    pub fn add<C: CircuitContext>(circuit: &mut C, a: &Fq12, b: &Fq12) -> Fq12 {
        let c0 = Fq6::add(circuit, a.c0(), b.c0());
        let c1 = Fq6::add(circuit, a.c1(), b.c1());

        Fq12::from_components(c0, c1)
    }

    pub fn neg<C: CircuitContext>(circuit: &mut C, a: &Fq12) -> Fq12 {
        Fq12::from_components(
            Fq6::neg(circuit, a.0[0].clone()),
            Fq6::neg(circuit, a.0[1].clone()),
        )
    }

    pub fn sub<C: CircuitContext>(circuit: &mut C, a: &Fq12, b: &Fq12) -> Fq12 {
        let c0 = Fq6::sub(circuit, a.c0(), b.c0());
        let c1 = Fq6::sub(circuit, a.c1(), b.c1());

        Fq12::from_components(c0, c1)
    }

    pub fn double<C: CircuitContext>(circuit: &mut C, a: &Fq12) -> Fq12 {
        let c0 = Fq6::double(circuit, a.c0());
        let c1 = Fq6::double(circuit, a.c1());

        Fq12::from_components(c0, c1)
    }

    #[component]
    pub fn mul_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq12, b: &Fq12) -> Fq12 {
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

    pub fn mul_by_constant_montgomery<C: CircuitContext>(
        circuit: &mut C,
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

    pub fn mul_by_34_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq12,
        c3: &Fq2,
        c4: &Fq2,
    ) -> Fq12 {
        let w1 = Fq6::mul_by_01_montgomery(circuit, a.c1(), c3, c4);
        let w2 = Fq6::mul_by_nonresidue(circuit, &w1);
        let new_c0 = Fq6::add(circuit, &w2, a.c0());
        let w3 = Fq6::add(circuit, a.c0(), a.c1());
        let w4 = Fq2::add_constant(circuit, c3, &Fq2::as_montgomery(ark_bn254::Fq2::ONE));
        let w5 = Fq6::mul_by_01_montgomery(circuit, &w3, &w4, c4);
        let w6 = Fq6::add(circuit, &w1, a.c0());
        let new_c1 = Fq6::sub(circuit, &w5, &w6);
        Fq12::from_components(new_c0, new_c1)
    }

    #[component]
    pub fn mul_by_034_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq12,
        c0: &Fq2,
        c3: &Fq2,
        c4: &Fq2,
    ) -> Fq12 {
        let w1 = Fq6::mul_by_01_montgomery(circuit, a.c1(), c3, c4);
        let w2 = Fq6::mul_by_nonresidue(circuit, &w1);
        let w3 = Fq6::mul_by_fq2_montgomery(circuit, a.c0(), c0);
        let new_c0 = Fq6::add(circuit, &w2, &w3);
        let w4 = Fq6::add(circuit, a.c0(), a.c1());
        let w5 = Fq2::add(circuit, c3, c0);
        let w6 = Fq6::mul_by_01_montgomery(circuit, &w4, &w5, c4);
        let w7 = Fq6::add(circuit, &w1, &w3);
        let new_c1 = Fq6::sub(circuit, &w6, &w7);
        Fq12::from_components(new_c0, new_c1)
    }

    #[component(offcircuit_args = "c4")]
    pub fn mul_by_034_constant4_montgomery<C: CircuitContext>(
        circuit: &mut C,
        a: &Fq12,
        c0: &Fq2,
        c3: &Fq2,
        c4: &ark_bn254::Fq2,
    ) -> Fq12 {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(c0.len(), Fq2::N_BITS);
        assert_eq!(c3.len(), Fq2::N_BITS);

        let w1 = Fq6::mul_by_01_constant1_montgomery(circuit, a.c1(), c3, c4);
        let w2 = Fq6::mul_by_nonresidue(circuit, &w1);
        let w3 = Fq6::mul_by_fq2_montgomery(circuit, a.c0(), c0);
        let new_c0 = Fq6::add(circuit, &w2, &w3);
        let w4 = Fq6::add(circuit, a.c0(), a.c1());
        let w5 = Fq2::add(circuit, c3, c0);
        let w6 = Fq6::mul_by_01_constant1_montgomery(circuit, &w4, &w5, c4);
        let w7 = Fq6::add(circuit, &w1, &w3);
        let new_c1 = Fq6::sub(circuit, &w6, &w7);
        Fq12::from_components(new_c0, new_c1)
    }

    #[component]
    pub fn square_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq12) -> Fq12 {
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

    pub fn cyclotomic_square_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq12) -> Fq12 {
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
        let w1 = Fq2::add(circuit, &t5_beta, &c3);
        let w2 = Fq2::double(circuit, &w1);
        let z2 = Fq2::add(circuit, &w2, &t5_beta);

        let w1 = Fq2::add(circuit, &t1, &c4);
        let w2 = Fq2::double(circuit, &w1);
        let z1 = Fq2::add(circuit, &w2, &t1);

        let w1 = Fq2::add(circuit, &t3, &c5);
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

    #[component]
    pub fn inverse_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq12) -> Fq12 {
        // For (a0 + a1*v)^-1 where v is the Fq6 nonresidue
        // Compute norm = a0^2 - a1^2 * v (where v is nonresidue for Fq12/Fq6)
        let a_c0_square = Fq6::square_montgomery(circuit, a.c0());
        let a_c1_square = Fq6::square_montgomery(circuit, a.c1());
        let a_c1_square_beta = Fq6::mul_by_nonresidue(circuit, &a_c1_square);
        let norm = Fq6::sub(circuit, &a_c0_square, &a_c1_square_beta);
        let inverse_norm = Fq6::inverse_montgomery(circuit, &norm);

        let res_c0 = Fq6::mul_montgomery(circuit, a.c0(), &inverse_norm);
        let neg_a_c1 = Fq6::neg(circuit, a.c1().clone());
        let res_c1 = Fq6::mul_montgomery(circuit, &inverse_norm, &neg_a_c1);

        Fq12::from_components(res_c0, res_c1)
    }

    pub fn frobenius_montgomery<C: CircuitContext>(circuit: &mut C, a: &Fq12, i: usize) -> Fq12 {
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

    pub fn conjugate<C: CircuitContext>(circuit: &mut C, a: &Fq12) -> Fq12 {
        let new_c1 = Fq6::neg(circuit, a.c1().clone());
        Fq12::from_components(a.c0().clone(), new_c1)
    }
}

#[cfg(test)]
mod tests {
    use std::{array, str::FromStr};

    use ark_ff::{CyclotomicMultSubgroup, PrimeField};
    use num_bigint::BigUint;
    use test_log::test;

    use super::*;
    use crate::{
        circuit::{
            CircuitBuilder, CircuitInput, CircuitOutput, EncodeInput,
            modes::{CircuitMode, ExecuteMode},
        },
        gadgets::{
            bigint::{BigUint as BigUintOutput, bits_from_biguint_with_len},
            bn254::{Fp254Impl, fq::Fq},
        },
        test_utils::trng,
    };

    fn random() -> ark_bn254::Fq12 {
        Fq12::random(&mut trng())
    }

    // Input struct for Fq12 tests
    struct Fq12Input<const N: usize> {
        values: [ark_bn254::Fq12; N],
    }

    impl<const N: usize> Fq12Input<N> {
        fn new(values: [ark_bn254::Fq12; N]) -> Self {
            Self { values }
        }
    }

    impl<const N: usize> CircuitInput for Fq12Input<N> {
        type WireRepr = [Fq12; N];

        fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
            array::from_fn(|_| Fq12::new(&mut issue))
        }

        fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
            repr.iter().flat_map(|fq12| fq12.to_wires_vec()).collect()
        }
    }

    impl<const N: usize, M: CircuitMode<WireValue = bool>> EncodeInput<M> for Fq12Input<N> {
        fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
            self.values
                .iter()
                .zip(repr.iter())
                .for_each(|(val, wires)| {
                    let v = val;
                    // encode c0 (Fq6)
                    encode_fq6_to_wires(&v.c0, &wires.0[0], cache);
                    // encode c1 (Fq6)
                    encode_fq6_to_wires(&v.c1, &wires.0[1], cache);
                });
        }
    }

    fn encode_fq6_to_wires<M: CircuitMode<WireValue = bool>>(
        val: &ark_bn254::Fq6,
        wires: &Fq6,
        cache: &mut M,
    ) {
        // c0
        let c0_c0_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(val.c0.c0.into_bigint()), Fq::N_BITS)
                .unwrap();
        let c0_c1_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(val.c0.c1.into_bigint()), Fq::N_BITS)
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

        // c1
        let c1_c0_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(val.c1.c0.into_bigint()), Fq::N_BITS)
                .unwrap();
        let c1_c1_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(val.c1.c1.into_bigint()), Fq::N_BITS)
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

        // c2
        let c2_c0_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(val.c2.c0.into_bigint()), Fq::N_BITS)
                .unwrap();
        let c2_c1_bits =
            bits_from_biguint_with_len(&BigUintOutput::from(val.c2.c1.into_bigint()), Fq::N_BITS)
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

    // Output struct for Fq12 tests
    struct Fq12Output {
        value: ark_bn254::Fq12,
    }

    impl CircuitOutput<ExecuteMode> for Fq12Output {
        type WireRepr = Fq12;

        fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
            let c0 = decode_fq6_from_wires(&wires.0[0], cache);
            let c1 = decode_fq6_from_wires(&wires.0[1], cache);
            let value = ark_bn254::Fq12::new(c0, c1);
            Self { value }
        }
    }

    fn decode_fq6_from_wires(wires: &Fq6, cache: &mut ExecuteMode) -> ark_bn254::Fq6 {
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
        let a = random();
        let b = random();
        let expected = a + b;

        let input = Fq12Input::new([a, b]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                let [a, b] = input;
                Fq12::add(ctx, a, b)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_neg() {
        let a = random();
        let expected = -a;

        let input = Fq12Input::new([a]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                let [a] = input;
                Fq12::neg(ctx, a)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_sub() {
        let a = random();
        let b = random();
        let expected = a - b;

        let input = Fq12Input::new([a, b]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                let [a, b] = input;
                Fq12::sub(ctx, a, b)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_double() {
        let a = random();
        let expected = a + a;

        let input = Fq12Input::new([a]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                let [a] = input;
                Fq12::double(ctx, a)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_mul_montgomery() {
        let a = random();
        let b = random();
        let a_m = Fq12::as_montgomery(a);
        let b_m = Fq12::as_montgomery(b);
        let expected = Fq12::as_montgomery(a * b);

        let input = Fq12Input::new([a_m, b_m]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                let [a, b] = input;
                Fq12::mul_montgomery(ctx, a, b)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_mul_by_constant_montgomery() {
        let a = random();
        let b = random();
        let a_m = Fq12::as_montgomery(a);
        let b_m = Fq12::as_montgomery(b);
        let expected = Fq12::as_montgomery(a * b);

        let input = Fq12Input::new([a_m]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                let [a] = input;
                Fq12::mul_by_constant_montgomery(ctx, a, &b_m)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_mul_by_34_montgomery() {
        let a = random();
        let c3 = Fq2::random(&mut trng());
        let c4 = Fq2::random(&mut trng());

        // Custom input type for this complex test
        struct MulBy34Input {
            a: ark_bn254::Fq12,
            c3: ark_bn254::Fq2,
            c4: ark_bn254::Fq2,
        }
        struct MulBy34Wire {
            a: Fq12,
            c3: Fq2,
            c4: Fq2,
        }
        impl CircuitInput for MulBy34Input {
            type WireRepr = MulBy34Wire;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                MulBy34Wire {
                    a: Fq12::new(&mut issue),
                    c3: Fq2::new(&mut issue),
                    c4: Fq2::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = WiresObject::to_wires_vec(&repr.a);
                ids.extend(WiresObject::to_wires_vec(&repr.c3));
                ids.extend(WiresObject::to_wires_vec(&repr.c4));
                ids
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for MulBy34Input {
            fn encode(&self, repr: &MulBy34Wire, cache: &mut M) {
                // Encode a (Fq12) in montgomery form
                let a_m = Fq12::as_montgomery(self.a);
                encode_fq6_to_wires(&a_m.c0, &repr.a.0[0], cache);
                encode_fq6_to_wires(&a_m.c1, &repr.a.0[1], cache);

                // Encode c3, c4 (Fq2) in montgomery form
                let c3_m = Fq2::as_montgomery(self.c3);
                let c4_m = Fq2::as_montgomery(self.c4);

                let c3_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(c3_m.c0.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let c3_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(c3_m.c1.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                repr.c3.0[0]
                    .0
                    .iter()
                    .zip(c3_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.c3.0[1]
                    .0
                    .iter()
                    .zip(c3_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));

                let c4_c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(c4_m.c0.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let c4_c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(c4_m.c1.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                repr.c4.0[0]
                    .0
                    .iter()
                    .zip(c4_c0_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
                repr.c4.0[1]
                    .0
                    .iter()
                    .zip(c4_c1_bits)
                    .for_each(|(w, b)| cache.feed_wire(*w, b));
            }
        }

        let mut expected_a = a;
        expected_a.mul_by_034(&ark_bn254::Fq2::ONE, &c3, &c4);
        let expected = Fq12::as_montgomery(expected_a);

        let input = MulBy34Input { a, c3, c4 };
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                Fq12::mul_by_34_montgomery(ctx, &input.a, &input.c3, &input.c4)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_mul_by_034_montgomery() {
        let a = random();
        let c0 = Fq2::random(&mut trng());
        let c3 = Fq2::random(&mut trng());
        let c4 = Fq2::random(&mut trng());

        // Custom input type for this complex test
        struct MulBy034Input {
            a: ark_bn254::Fq12,
            c0: ark_bn254::Fq2,
            c3: ark_bn254::Fq2,
            c4: ark_bn254::Fq2,
        }
        struct MulBy034Wire {
            a: Fq12,
            c0: Fq2,
            c3: Fq2,
            c4: Fq2,
        }
        impl CircuitInput for MulBy034Input {
            type WireRepr = MulBy034Wire;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                MulBy034Wire {
                    a: Fq12::new(&mut issue),
                    c0: Fq2::new(&mut issue),
                    c3: Fq2::new(&mut issue),
                    c4: Fq2::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = WiresObject::to_wires_vec(&repr.a);
                ids.extend(WiresObject::to_wires_vec(&repr.c0));
                ids.extend(WiresObject::to_wires_vec(&repr.c3));
                ids.extend(WiresObject::to_wires_vec(&repr.c4));
                ids
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for MulBy034Input {
            fn encode(&self, repr: &MulBy034Wire, cache: &mut M) {
                // Encode a (Fq12) in montgomery form
                let a_m = Fq12::as_montgomery(self.a);
                encode_fq6_to_wires(&a_m.c0, &repr.a.0[0], cache);
                encode_fq6_to_wires(&a_m.c1, &repr.a.0[1], cache);

                // Encode c0, c3, c4 (Fq2) in montgomery form
                for (val, wires) in [
                    (self.c0, &repr.c0),
                    (self.c3, &repr.c3),
                    (self.c4, &repr.c4),
                ] {
                    let val_m = Fq2::as_montgomery(val);
                    let c0_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(val_m.c0.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    let c1_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(val_m.c1.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    wires.0[0]
                        .0
                        .iter()
                        .zip(c0_bits)
                        .for_each(|(w, b)| cache.feed_wire(*w, b));
                    wires.0[1]
                        .0
                        .iter()
                        .zip(c1_bits)
                        .for_each(|(w, b)| cache.feed_wire(*w, b));
                }
            }
        }

        let mut expected_a = a;
        expected_a.mul_by_034(&c0, &c3, &c4);
        let expected = Fq12::as_montgomery(expected_a);

        let input = MulBy034Input { a, c0, c3, c4 };
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                Fq12::mul_by_034_montgomery(ctx, &input.a, &input.c0, &input.c3, &input.c4)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_mul_by_034_constant4_montgomery() {
        let a = random();
        let mut rng = trng();
        let c0 = Fq2::random(&mut rng);
        let c3 = Fq2::random(&mut rng);
        let c4 = Fq2::random(&mut rng);

        // Custom input type for this test (c0, c3 are wires, c4 is constant)
        struct MulBy034Const4Input {
            a: ark_bn254::Fq12,
            c0: ark_bn254::Fq2,
            c3: ark_bn254::Fq2,
        }
        struct MulBy034Const4Wire {
            a: Fq12,
            c0: Fq2,
            c3: Fq2,
        }
        impl CircuitInput for MulBy034Const4Input {
            type WireRepr = MulBy034Const4Wire;
            fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
                MulBy034Const4Wire {
                    a: Fq12::new(&mut issue),
                    c0: Fq2::new(&mut issue),
                    c3: Fq2::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
                let mut ids = WiresObject::to_wires_vec(&repr.a);
                ids.extend(WiresObject::to_wires_vec(&repr.c0));
                ids.extend(WiresObject::to_wires_vec(&repr.c3));
                ids
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for MulBy034Const4Input {
            fn encode(&self, repr: &MulBy034Const4Wire, cache: &mut M) {
                // Encode a (Fq12) in montgomery form
                let a_m = Fq12::as_montgomery(self.a);
                encode_fq6_to_wires(&a_m.c0, &repr.a.0[0], cache);
                encode_fq6_to_wires(&a_m.c1, &repr.a.0[1], cache);

                // Encode c0, c3 (Fq2) in montgomery form
                for (val, wires) in [(self.c0, &repr.c0), (self.c3, &repr.c3)] {
                    let val_m = Fq2::as_montgomery(val);
                    let c0_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(val_m.c0.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    let c1_bits = bits_from_biguint_with_len(
                        &BigUintOutput::from(val_m.c1.into_bigint()),
                        Fq::N_BITS,
                    )
                    .unwrap();
                    wires.0[0]
                        .0
                        .iter()
                        .zip(c0_bits)
                        .for_each(|(w, b)| cache.feed_wire(*w, b));
                    wires.0[1]
                        .0
                        .iter()
                        .zip(c1_bits)
                        .for_each(|(w, b)| cache.feed_wire(*w, b));
                }
            }
        }

        let mut expected_a = a;
        expected_a.mul_by_034(&c0, &c3, &c4);
        let expected = Fq12::as_montgomery(expected_a);

        let input = MulBy034Const4Input { a, c0, c3 };
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                Fq12::mul_by_034_constant4_montgomery(
                    ctx,
                    &input.a,
                    &input.c0,
                    &input.c3,
                    &Fq2::as_montgomery(c4),
                )
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_square_montgomery() {
        let a = random();
        let a_m = Fq12::as_montgomery(a);
        let expected = Fq12::as_montgomery(a * a);

        let input = Fq12Input::new([a_m]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                let [a] = input;
                Fq12::square_montgomery(ctx, a)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_cyclotomic_square_montgomery() {
        let p = Fq::modulus_as_biguint();
        let u = (p.pow(6) - BigUint::from_str("1").unwrap())
            * (p.pow(2) + BigUint::from_str("1").unwrap());
        let a = Fq12::random(&mut trng()).pow(u.to_u64_digits());
        let a_m = Fq12::as_montgomery(a);
        let mut expected_a = a;
        expected_a.cyclotomic_square_in_place();
        let expected = Fq12::as_montgomery(expected_a);

        let input = Fq12Input::new([a_m]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                let [a] = input;
                Fq12::cyclotomic_square_montgomery(ctx, a)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_frobenius_montgomery() {
        for i in [0, 1, 2, 3] {
            let a = random();
            let a_m = Fq12::as_montgomery(a);
            let mut expected = a;
            expected.frobenius_map_in_place(i);
            let expected_m = Fq12::as_montgomery(expected);

            let input = Fq12Input::new([a_m]);
            let result = CircuitBuilder::streaming_execute::<_, _, Fq12Output>(
                input,
                10_000,
                |ctx, input| {
                    let [a] = input;
                    Fq12::frobenius_montgomery(ctx, a, i)
                },
            );

            assert_eq!(result.output_value.value, expected_m);
        }
    }

    #[test]
    fn test_fq12_inverse_montgomery() {
        let a = random();
        let a_m = Fq12::as_montgomery(a);
        let expected = Fq12::as_montgomery(a.inverse().unwrap());

        let input = Fq12Input::new([a_m]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                let [a] = input;
                Fq12::inverse_montgomery(ctx, a)
            });

        assert_eq!(result.output_value.value, expected);
    }

    #[test]
    fn test_fq12_conjugate() {
        let a = random();
        let mut expected = a;
        expected.conjugate_in_place();

        let input = Fq12Input::new([a]);
        let result =
            CircuitBuilder::streaming_execute::<_, _, Fq12Output>(input, 10_000, |ctx, input| {
                let [a] = input;
                Fq12::conjugate(ctx, a)
            });

        assert_eq!(result.output_value.value, expected);
    }
}
