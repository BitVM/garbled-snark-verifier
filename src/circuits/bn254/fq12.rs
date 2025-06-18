use crate::{
    bag::*,
    circuits::bn254::{fp254impl::Fp254Impl, fq::Fq, fq2::Fq2, fq6::Fq6},
};
use ark_ff::{Field, Fp12Config, UniformRand};
use ark_std::rand::SeedableRng;
use rand::{Rng, rng};
use rand_chacha::ChaCha20Rng;
use std::iter::zip;

pub struct Fq12;

impl Fq12 {
    pub const N_BITS: usize = 2 * Fq6::N_BITS;

    pub fn as_montgomery(a: ark_bn254::Fq12) -> ark_bn254::Fq12 {
        ark_bn254::Fq12::new(Fq6::as_montgomery(a.c0), Fq6::as_montgomery(a.c1))
    }

    pub fn from_montgomery(a: ark_bn254::Fq12) -> ark_bn254::Fq12 {
        ark_bn254::Fq12::new(Fq6::from_montgomery(a.c0), Fq6::from_montgomery(a.c1))
    }

    pub fn random() -> ark_bn254::Fq12 {
        let mut prng = ChaCha20Rng::seed_from_u64(rng().random());
        ark_bn254::Fq12::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::Fq12) -> Vec<bool> {
        let mut bits = Vec::new();
        bits.extend(Fq6::to_bits(u.c0));
        bits.extend(Fq6::to_bits(u.c1));
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fq12 {
        let bits1 = &bits[0..Fq6::N_BITS].to_vec();
        let bits2 = &bits[Fq6::N_BITS..Fq6::N_BITS * 2].to_vec();
        ark_bn254::Fq12::new(Fq6::from_bits(bits1.clone()), Fq6::from_bits(bits2.clone()))
    }

    pub fn wires() -> Wires {
        (0..Self::N_BITS)
            .map(|_| Rc::new(RefCell::new(Wire::new())))
            .collect()
    }

    pub fn wires_set(u: ark_bn254::Fq12) -> Wires {
        Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                let wire = Rc::new(RefCell::new(Wire::new()));
                wire.borrow_mut().set(*bit);
                wire
            })
            .collect()
    }

    pub fn wires_set_montgomery(u: ark_bn254::Fq12) -> Wires {
        Self::wires_set(Self::as_montgomery(u))
    }

    pub fn from_wires(wires: Wires) -> ark_bn254::Fq12 {
        Self::from_bits(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_montgomery_wires(wires: Wires) -> ark_bn254::Fq12 {
        Self::from_montgomery(Self::from_wires(wires))
    }

    pub fn equal_constant(a: Wires, b: ark_bn254::Fq12) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a0 = a[..Fq::N_BITS].to_vec();
        let a1 = a[Fq::N_BITS..2 * Fq::N_BITS].to_vec();
        let a2 = a[2 * Fq::N_BITS..3 * Fq::N_BITS].to_vec();
        let a3 = a[3 * Fq::N_BITS..4 * Fq::N_BITS].to_vec();
        let a4 = a[4 * Fq::N_BITS..5 * Fq::N_BITS].to_vec();
        let a5 = a[5 * Fq::N_BITS..6 * Fq::N_BITS].to_vec();
        let a6 = a[6 * Fq::N_BITS..7 * Fq::N_BITS].to_vec();
        let a7 = a[7 * Fq::N_BITS..8 * Fq::N_BITS].to_vec();
        let a8 = a[8 * Fq::N_BITS..9 * Fq::N_BITS].to_vec();
        let a9 = a[9 * Fq::N_BITS..10 * Fq::N_BITS].to_vec();
        let a10 = a[10 * Fq::N_BITS..11 * Fq::N_BITS].to_vec();
        let a11 = a[11 * Fq::N_BITS..12 * Fq::N_BITS].to_vec();

        let mut results = Vec::new();

        for (x, y) in zip(
            [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11],
            b.to_base_prime_field_elements(),
        ) {
            let result = circuit.extend(Fq::equal_constant(x, y))[0].clone();
            results.push(result);
        }

        let mut wire = results[0].clone();

        for next in results[1..].iter().cloned() {
            let new_wire = Rc::new(RefCell::new(Wire::new()));
            circuit.add(Gate::and(wire, next, new_wire.clone()));
            wire = new_wire;
        }

        circuit.add_wire(wire);

        circuit
    }

    pub fn equal_constant_evaluate(a: Wires, b: ark_bn254::Fq12) -> (Wires, GateCount) {
        let circuit = Fq12::equal_constant(a, b);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }

    pub fn add(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();
        let b_c0 = b[0..Fq6::N_BITS].to_vec();
        let b_c1 = b[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::add(a_c0, b_c0));
        let wires_2 = circuit.extend(Fq6::add(a_c1, b_c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn neg(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::neg(a_c0));
        let wires_2 = circuit.extend(Fq6::neg(a_c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn sub(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();
        let b_c0 = b[0..Fq6::N_BITS].to_vec();
        let b_c1 = b[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::sub(a_c0, b_c0));
        let wires_2 = circuit.extend(Fq6::sub(a_c1, b_c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn double(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::double(a_c0));
        let wires_2 = circuit.extend(Fq6::double(a_c1));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit
    }

    pub fn mul(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();
        let b_c0 = b[0..Fq6::N_BITS].to_vec();
        let b_c1 = b[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_2 = circuit.extend(Fq6::add(b_c0.clone(), b_c1.clone()));
        let wires_3 = circuit.extend(Fq6::mul(a_c0.clone(), b_c0.clone()));
        let wires_4 = circuit.extend(Fq6::mul(a_c1.clone(), b_c1.clone()));
        let wires_5 = circuit.extend(Fq6::add(wires_3.clone(), wires_4.clone()));
        let wires_6 = circuit.extend(Fq6::mul_by_nonresidue(wires_4.clone()));
        let wires_7 = circuit.extend(Fq6::add(wires_6.clone(), wires_3.clone()));
        let wires_8 = circuit.extend(Fq6::mul(wires_1.clone(), wires_2.clone()));
        let wires_9 = circuit.extend(Fq6::sub(wires_8.clone(), wires_5.clone()));
        circuit.add_wires(wires_7);
        circuit.add_wires(wires_9);
        circuit
    }

    pub fn mul_montgomery(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();
        let b_c0 = b[0..Fq6::N_BITS].to_vec();
        let b_c1 = b[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_2 = circuit.extend(Fq6::add(b_c0.clone(), b_c1.clone()));
        let wires_3 = circuit.extend(Fq6::mul_montgomery(a_c0.clone(), b_c0.clone()));
        let wires_4 = circuit.extend(Fq6::mul_montgomery(a_c1.clone(), b_c1.clone()));
        let wires_5 = circuit.extend(Fq6::add(wires_3.clone(), wires_4.clone()));
        let wires_6 = circuit.extend(Fq6::mul_by_nonresidue(wires_4.clone()));
        let wires_7 = circuit.extend(Fq6::add(wires_6.clone(), wires_3.clone()));
        let wires_8 = circuit.extend(Fq6::mul_montgomery(wires_1.clone(), wires_2.clone()));
        let wires_9 = circuit.extend(Fq6::sub(wires_8.clone(), wires_5.clone()));
        circuit.add_wires(wires_7);
        circuit.add_wires(wires_9);
        circuit
    }

    pub fn mul_evaluate(a: Wires, b: Wires) -> (Wires, GateCount) {
        let circuit = Fq12::mul(a, b);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }

    pub fn mul_evaluate_montgomery(a: Wires, b: Wires) -> (Wires, GateCount) {
        let circuit = Fq12::mul_montgomery(a, b);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }

    pub fn mul_by_constant(a: Wires, b: ark_bn254::Fq12) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_2 = circuit.extend(Fq6::mul_by_constant(a_c0.clone(), b.c0));
        let wires_3 = circuit.extend(Fq6::mul_by_constant(a_c1.clone(), b.c1));
        let wires_4 = circuit.extend(Fq6::add(wires_2.clone(), wires_3.clone()));
        let wires_5 = circuit.extend(Fq6::mul_by_nonresidue(wires_3.clone()));
        let wires_6 = circuit.extend(Fq6::add(wires_5.clone(), wires_2.clone()));
        let wires_7 = circuit.extend(Fq6::mul_by_constant(wires_1.clone(), b.c0 + b.c1));
        let wires_8 = circuit.extend(Fq6::sub(wires_7.clone(), wires_4.clone()));
        circuit.add_wires(wires_6);
        circuit.add_wires(wires_8);
        circuit
    }

    pub fn mul_by_constant_montgomery(a: Wires, b: ark_bn254::Fq12) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_2 = circuit.extend(Fq6::mul_by_constant_montgomery(a_c0.clone(), b.c0));
        let wires_3 = circuit.extend(Fq6::mul_by_constant_montgomery(a_c1.clone(), b.c1));
        let wires_4 = circuit.extend(Fq6::add(wires_2.clone(), wires_3.clone()));
        let wires_5 = circuit.extend(Fq6::mul_by_nonresidue(wires_3.clone()));
        let wires_6 = circuit.extend(Fq6::add(wires_5.clone(), wires_2.clone()));
        let wires_7 = circuit.extend(Fq6::mul_by_constant_montgomery(
            wires_1.clone(),
            b.c0 + b.c1,
        ));
        let wires_8 = circuit.extend(Fq6::sub(wires_7.clone(), wires_4.clone()));
        circuit.add_wires(wires_6);
        circuit.add_wires(wires_8);
        circuit
    }

    pub fn mul_by_34(a: Wires, c3: Wires, c4: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(c3.len(), Fq2::N_BITS);
        assert_eq!(c4.len(), Fq2::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::mul_by_01(a_c1.clone(), c3.clone(), c4.clone()));
        let wires_2 = circuit.extend(Fq6::mul_by_nonresidue(wires_1.clone()));
        let c0 = circuit.extend(Fq6::add(wires_2.clone(), a_c0.clone()));
        let wires_3 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_4 = circuit.extend(Fq2::add_constant(c3.clone(), ark_bn254::Fq2::ONE));
        let wires_5 = circuit.extend(Fq6::mul_by_01(wires_3.clone(), wires_4.clone(), c4.clone()));
        let wires_6 = circuit.extend(Fq6::add(wires_1, a_c0));
        let c1 = circuit.extend(Fq6::sub(wires_5, wires_6));
        circuit.add_wires(c0);
        circuit.add_wires(c1);
        circuit
    }

    pub fn mul_by_34_montgomery(a: Wires, c3: Wires, c4: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(c3.len(), Fq2::N_BITS);
        assert_eq!(c4.len(), Fq2::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::mul_by_01_montgomery(
            a_c1.clone(),
            c3.clone(),
            c4.clone(),
        ));
        let wires_2 = circuit.extend(Fq6::mul_by_nonresidue(wires_1.clone()));
        let c0 = circuit.extend(Fq6::add(wires_2.clone(), a_c0.clone()));
        let wires_3 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_4 = circuit.extend(Fq2::add_constant(
            c3.clone(),
            Fq2::as_montgomery(ark_bn254::Fq2::ONE),
        ));
        let wires_5 = circuit.extend(Fq6::mul_by_01_montgomery(
            wires_3.clone(),
            wires_4.clone(),
            c4.clone(),
        ));
        let wires_6 = circuit.extend(Fq6::add(wires_1, a_c0));
        let c1 = circuit.extend(Fq6::sub(wires_5, wires_6));
        circuit.add_wires(c0);
        circuit.add_wires(c1);
        circuit
    }

    pub fn mul_by_034(a: Wires, c0: Wires, c3: Wires, c4: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(c0.len(), Fq2::N_BITS);
        assert_eq!(c3.len(), Fq2::N_BITS);
        assert_eq!(c4.len(), Fq2::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::mul_by_01(a_c1.clone(), c3.clone(), c4.clone()));
        let wires_2 = circuit.extend(Fq6::mul_by_nonresidue(wires_1.clone()));
        let wires_3 = circuit.extend(Fq6::mul_by_fq2(a_c0.clone(), c0.clone()));
        let new_c0 = circuit.extend(Fq6::add(wires_2.clone(), wires_3.clone()));
        let wires_4 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_5 = circuit.extend(Fq2::add(c3.clone(), c0.clone()));
        let wires_6 = circuit.extend(Fq6::mul_by_01(wires_4.clone(), wires_5.clone(), c4.clone()));
        let wires_7 = circuit.extend(Fq6::add(wires_1, wires_3));
        let new_c1 = circuit.extend(Fq6::sub(wires_6, wires_7));

        circuit.add_wires(new_c0);
        circuit.add_wires(new_c1);
        circuit
    }

    pub fn mul_by_034_montgomery(a: Wires, c0: Wires, c3: Wires, c4: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(c0.len(), Fq2::N_BITS);
        assert_eq!(c3.len(), Fq2::N_BITS);
        assert_eq!(c4.len(), Fq2::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::mul_by_01_montgomery(
            a_c1.clone(),
            c3.clone(),
            c4.clone(),
        ));
        let wires_2 = circuit.extend(Fq6::mul_by_nonresidue(wires_1.clone()));
        let wires_3 = circuit.extend(Fq6::mul_by_fq2_montgomery(a_c0.clone(), c0.clone()));
        let new_c0 = circuit.extend(Fq6::add(wires_2.clone(), wires_3.clone()));
        let wires_4 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_5 = circuit.extend(Fq2::add(c3.clone(), c0.clone()));
        let wires_6 = circuit.extend(Fq6::mul_by_01_montgomery(
            wires_4.clone(),
            wires_5.clone(),
            c4.clone(),
        ));
        let wires_7 = circuit.extend(Fq6::add(wires_1, wires_3));
        let new_c1 = circuit.extend(Fq6::sub(wires_6, wires_7));

        circuit.add_wires(new_c0);
        circuit.add_wires(new_c1);
        circuit
    }

    pub fn mul_by_034_constant4(a: Wires, c0: Wires, c3: Wires, c4: ark_bn254::Fq2) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(c0.len(), Fq2::N_BITS);
        assert_eq!(c3.len(), Fq2::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::mul_by_01_constant1(a_c1.clone(), c3.clone(), c4));
        let wires_2 = circuit.extend(Fq6::mul_by_nonresidue(wires_1.clone()));
        let wires_3 = circuit.extend(Fq6::mul_by_fq2(a_c0.clone(), c0.clone()));
        let new_c0 = circuit.extend(Fq6::add(wires_2.clone(), wires_3.clone()));
        let wires_4 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_5 = circuit.extend(Fq2::add(c3.clone(), c0.clone()));
        let wires_6 = circuit.extend(Fq6::mul_by_01_constant1(
            wires_4.clone(),
            wires_5.clone(),
            c4,
        ));
        let wires_7 = circuit.extend(Fq6::add(wires_1, wires_3));
        let new_c1 = circuit.extend(Fq6::sub(wires_6, wires_7));

        circuit.add_wires(new_c0);
        circuit.add_wires(new_c1);
        circuit
    }

    pub fn mul_by_034_constant4_montgomery(
        a: Wires,
        c0: Wires,
        c3: Wires,
        c4: ark_bn254::Fq2,
    ) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(c0.len(), Fq2::N_BITS);
        assert_eq!(c3.len(), Fq2::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq6::mul_by_01_constant1_montgomery(
            a_c1.clone(),
            c3.clone(),
            c4,
        ));
        let wires_2 = circuit.extend(Fq6::mul_by_nonresidue(wires_1.clone()));
        let wires_3 = circuit.extend(Fq6::mul_by_fq2_montgomery(a_c0.clone(), c0.clone()));
        let new_c0 = circuit.extend(Fq6::add(wires_2.clone(), wires_3.clone()));
        let wires_4 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_5 = circuit.extend(Fq2::add(c3.clone(), c0.clone()));
        let wires_6 = circuit.extend(Fq6::mul_by_01_constant1_montgomery(
            wires_4.clone(),
            wires_5.clone(),
            c4,
        ));
        let wires_7 = circuit.extend(Fq6::add(wires_1, wires_3));
        let new_c1 = circuit.extend(Fq6::sub(wires_6, wires_7));

        circuit.add_wires(new_c0);
        circuit.add_wires(new_c1);
        circuit
    }

    pub fn square(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();
        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();
        let wires_1 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_2 = circuit.extend(Fq6::square(a_c0.clone()));
        let wires_3 = circuit.extend(Fq6::square(a_c1.clone()));
        let wires_4 = circuit.extend(Fq6::add(wires_2.clone(), wires_3.clone()));
        let wires_5 = circuit.extend(Fq6::mul_by_nonresidue(wires_3.clone()));
        let wires_6 = circuit.extend(Fq6::add(wires_5.clone(), wires_2.clone()));
        let wires_7 = circuit.extend(Fq6::mul(wires_1.clone(), wires_1.clone()));
        let wires_8 = circuit.extend(Fq6::sub(wires_7.clone(), wires_4.clone()));
        circuit.add_wires(wires_6);
        circuit.add_wires(wires_8);
        circuit
    }

    pub fn square_montgomery(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();
        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();
        let wires_1 = circuit.extend(Fq6::add(a_c0.clone(), a_c1.clone()));
        let wires_2 = circuit.extend(Fq6::square_montgomery(a_c0.clone()));
        let wires_3 = circuit.extend(Fq6::square_montgomery(a_c1.clone()));
        let wires_4 = circuit.extend(Fq6::add(wires_2.clone(), wires_3.clone()));
        let wires_5 = circuit.extend(Fq6::mul_by_nonresidue(wires_3.clone()));
        let wires_6 = circuit.extend(Fq6::add(wires_5.clone(), wires_2.clone()));
        let wires_7 = circuit.extend(Fq6::mul_montgomery(wires_1.clone(), wires_1.clone()));
        let wires_8 = circuit.extend(Fq6::sub(wires_7.clone(), wires_4.clone()));
        circuit.add_wires(wires_6);
        circuit.add_wires(wires_8);
        circuit
    }

    pub fn square_evaluate(a: Wires) -> (Wires, GateCount) {
        let circuit = Fq12::square_montgomery(a);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }

    pub fn inverse(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();
        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();
        let a_c0_square = circuit.extend(Fq6::square(a_c0.clone()));
        let a_c1_square = circuit.extend(Fq6::square(a_c1.clone()));
        let a_c1_square_beta = circuit.extend(Fq6::mul_by_nonresidue(a_c1_square.clone()));
        let norm = circuit.extend(Fq6::sub(a_c0_square, a_c1_square_beta));
        let inverse_norm = circuit.extend(Fq6::inverse(norm));
        let res_c0 = circuit.extend(Fq6::mul(a_c0, inverse_norm.clone()));
        let neg_a_c1 = circuit.extend(Fq6::neg(a_c1));
        let res_c1 = circuit.extend(Fq6::mul(inverse_norm, neg_a_c1));

        circuit.add_wires(res_c0);
        circuit.add_wires(res_c1);
        circuit
    }

    pub fn inverse_montgomery(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();
        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();
        let a_c0_square = circuit.extend(Fq6::square_montgomery(a_c0.clone()));
        let a_c1_square = circuit.extend(Fq6::square_montgomery(a_c1.clone()));
        let a_c1_square_beta = circuit.extend(Fq6::mul_by_nonresidue(a_c1_square.clone()));
        let norm = circuit.extend(Fq6::sub(a_c0_square, a_c1_square_beta));
        let inverse_norm = circuit.extend(Fq6::inverse_montgomery(norm));
        let res_c0 = circuit.extend(Fq6::mul_montgomery(a_c0, inverse_norm.clone()));
        let neg_a_c1 = circuit.extend(Fq6::neg(a_c1));
        let res_c1 = circuit.extend(Fq6::mul_montgomery(inverse_norm, neg_a_c1));

        circuit.add_wires(res_c0);
        circuit.add_wires(res_c1);
        circuit
    }

    pub fn frobenius(a: Wires, i: usize) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let frobenius_a_c0 = circuit.extend(Fq6::frobenius(a_c0, i));
        let frobenius_a_c1 = circuit.extend(Fq6::frobenius(a_c1, i));

        let result = circuit.extend(Fq6::mul_by_constant_fq2(
            frobenius_a_c1,
            ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1
                [i % ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1.len()],
        ));
        circuit.0.extend(frobenius_a_c0);
        circuit.0.extend(result);
        circuit
    }

    pub fn frobenius_montgomery(a: Wires, i: usize) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let frobenius_a_c0 = circuit.extend(Fq6::frobenius_montgomery(a_c0, i));
        let frobenius_a_c1 = circuit.extend(Fq6::frobenius_montgomery(a_c1, i));

        let result = circuit.extend(Fq6::mul_by_constant_fq2_montgomery(
            frobenius_a_c1,
            Fq2::as_montgomery(
                ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1
                    [i % ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1.len()],
            ),
        ));
        circuit.0.extend(frobenius_a_c0);
        circuit.0.extend(result);
        circuit
    }

    pub fn frobenius_evaluate(a: Wires, i: usize) -> (Wires, GateCount) {
        let circuit = Fq12::frobenius(a, i);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }

    pub fn frobenius_evaluate_montgomery(a: Wires, i: usize) -> (Wires, GateCount) {
        let circuit = Fq12::frobenius_montgomery(a, i);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }

    pub fn conjugate(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq6::N_BITS].to_vec();
        let a_c1 = a[Fq6::N_BITS..2 * Fq6::N_BITS].to_vec();

        let new_a_c1 = circuit.extend(Fq6::neg(a_c1));

        circuit.0.extend(a_c0);
        circuit.0.extend(new_a_c1);
        circuit
    }

    pub fn conjugate_evaluate(a: Wires) -> (Wires, GateCount) {
        let circuit = Fq12::conjugate(a);
        let n = circuit.gate_counts();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        (circuit.0, n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Field;
    use serial_test::serial;

    #[test]
    fn test_fq12_random() {
        let u = Fq12::random();
        println!("u: {:?}", u);
        let b = Fq12::to_bits(u);
        let v = Fq12::from_bits(b);
        println!("v: {:?}", v);
        assert_eq!(u, v);
    }

    #[test]
    fn test_fq12_equal_constant() {
        let a = Fq12::random();
        let b = Fq12::random();
        let circuit = Fq12::equal_constant(Fq12::wires_set(a), b);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let result = circuit.0[0].clone().borrow().get_value();
        assert_eq!(result, a == b);

        let circuit = Fq12::equal_constant(Fq12::wires_set(a), a);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let result = circuit.0[0].clone().borrow().get_value();
        assert!(result);
    }

    #[test]
    fn test_fq12_add() {
        let a = Fq12::random();
        let b = Fq12::random();
        let circuit = Fq12::add(Fq12::wires_set(a), Fq12::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a + b);
    }

    #[test]
    fn test_fq12_neg() {
        let a = Fq12::random();
        let circuit = Fq12::neg(Fq12::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, -a);
    }

    #[test]
    fn test_fq12_sub() {
        let a = Fq12::random();
        let b = Fq12::random();
        let circuit = Fq12::sub(Fq12::wires_set(a), Fq12::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a - b);
    }

    #[test]
    fn test_fq12_double() {
        let a = Fq12::random();
        let mut circuit = Fq12::double(Fq12::wires_set(a));
        circuit.optimize_consts();
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a + a);
    }

    #[test]
    #[serial]
    fn test_fq12_mul() {
        let a = Fq12::random();
        let b = Fq12::random();
        let circuit = Fq12::mul(Fq12::wires_set(a), Fq12::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a * b);
    }

    #[test]
    #[serial]
    fn test_fq12_mul_montgomery() {
        let a = Fq12::random();
        let b = Fq12::random();
        let circuit = Fq12::mul_montgomery(
            Fq12::wires_set(Fq12::as_montgomery(a)),
            Fq12::wires_set(Fq12::as_montgomery(b)),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, Fq12::as_montgomery(a * b));
    }

    #[test]
    #[serial]
    fn test_fq12_mul_by_constant() {
        let a = Fq12::random();
        let b = Fq12::random();
        let circuit = Fq12::mul_by_constant(Fq12::wires_set(a), b);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a * b);
    }

    #[test]
    #[serial]
    fn test_fq12_mul_by_constant_montgomery() {
        let a = Fq12::random();
        let b = Fq12::random();
        let circuit =
            Fq12::mul_by_constant_montgomery(Fq12::wires_set_montgomery(a), Fq12::as_montgomery(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, Fq12::as_montgomery(a * b));
    }

    #[test]
    #[serial]
    fn test_fq12_mul_by_34() {
        let a = Fq12::random();
        let c3 = Fq2::random();
        let c4 = Fq2::random();
        let circuit = Fq12::mul_by_34(Fq12::wires_set(a), Fq2::wires_set(c3), Fq2::wires_set(c4));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        let mut b = a;
        b.mul_by_034(&ark_bn254::Fq2::ONE, &c3, &c4);
        assert_eq!(c, b);
    }

    #[test]
    #[serial]
    fn test_fq12_mul_by_34_montgomery() {
        let a = Fq12::random();
        let c3 = Fq2::random();
        let c4 = Fq2::random();
        let circuit = Fq12::mul_by_34_montgomery(
            Fq12::wires_set_montgomery(a),
            Fq2::wires_set_montgomery(c3),
            Fq2::wires_set_montgomery(c4),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        let mut b = a;
        b.mul_by_034(&ark_bn254::Fq2::ONE, &c3, &c4);
        assert_eq!(c, Fq12::as_montgomery(b));
    }

    #[test]
    #[serial]
    fn test_fq12_mul_by_034() {
        let a = Fq12::random();
        let c0 = Fq2::random();
        let c3 = Fq2::random();
        let c4 = Fq2::random();
        let circuit = Fq12::mul_by_034(
            Fq12::wires_set(a),
            Fq2::wires_set(c0),
            Fq2::wires_set(c3),
            Fq2::wires_set(c4),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        let mut b = a;
        b.mul_by_034(&c0, &c3, &c4);
        assert_eq!(c, b);
    }

    #[test]
    #[serial]
    fn test_fq12_mul_by_034_montgomery() {
        let a = Fq12::random();
        let c0 = Fq2::random();
        let c3 = Fq2::random();
        let c4 = Fq2::random();
        let circuit = Fq12::mul_by_034_montgomery(
            Fq12::wires_set_montgomery(a),
            Fq2::wires_set_montgomery(c0),
            Fq2::wires_set_montgomery(c3),
            Fq2::wires_set_montgomery(c4),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        let mut b = a;
        b.mul_by_034(&c0, &c3, &c4);
        assert_eq!(c, Fq12::as_montgomery(b));
    }

    #[test]
    #[serial]
    fn test_fq12_square() {
        let a = Fq12::random();
        let circuit = Fq12::square(Fq12::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a * a);
    }

    #[test]
    #[serial]
    fn test_fq12_square_montgomery() {
        let a = Fq12::random();
        let circuit = Fq12::square_montgomery(Fq12::wires_set_montgomery(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, Fq12::as_montgomery(a * a));
    }

    #[test]
    #[serial]
    fn test_fq12_inverse() {
        let a = Fq12::random();
        let circuit = Fq12::inverse(Fq12::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a.inverse().unwrap());
    }

    #[test]
    #[serial]
    fn test_fq12_inverse_montgomery() {
        let a = Fq12::random();
        let circuit = Fq12::inverse_montgomery(Fq12::wires_set_montgomery(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, Fq12::as_montgomery(a.inverse().unwrap()));
    }

    #[test]
    #[serial]
    fn test_fq12_frobenius() {
        let a = Fq12::random();

        let circuit = Fq12::frobenius(Fq12::wires_set(a), 0);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a.frobenius_map(0));

        let circuit = Fq12::frobenius(Fq12::wires_set(a), 1);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a.frobenius_map(1));

        let circuit = Fq12::frobenius(Fq12::wires_set(a), 2);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a.frobenius_map(2));

        let circuit = Fq12::frobenius(Fq12::wires_set(a), 3);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, a.frobenius_map(3));
    }

    #[test]
    #[serial]
    fn test_fq12_frobenius_montgomery() {
        let a = Fq12::random();

        let circuit = Fq12::frobenius_montgomery(Fq12::wires_set_montgomery(a), 0);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, Fq12::as_montgomery(a.frobenius_map(0)));

        let circuit = Fq12::frobenius(Fq12::wires_set_montgomery(a), 1);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, Fq12::as_montgomery(a.frobenius_map(1)));

        let circuit = Fq12::frobenius(Fq12::wires_set_montgomery(a), 2);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, Fq12::as_montgomery(a.frobenius_map(2)));

        let circuit = Fq12::frobenius(Fq12::wires_set_montgomery(a), 3);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, Fq12::as_montgomery(a.frobenius_map(3)));
    }

    #[test]
    fn test_fq12_conjugate() {
        let a = Fq12::random();

        let circuit = Fq12::conjugate(Fq12::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let mut b = a;
        b.conjugate_in_place();
        let c = Fq12::from_wires(circuit.0);
        assert_eq!(c, b);
    }
}
