use crate::{bag::*, circuits::bn254::fq2::Fq2};
use ark_ff::{Fp6Config, UniformRand, fields::AdditiveGroup};
use ark_std::rand::SeedableRng;
use rand::{Rng, rng};
use rand_chacha::ChaCha20Rng;

pub struct Fq6;

impl Fq6 {
    pub const N_BITS: usize = 3 * Fq2::N_BITS;

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

    pub fn random() -> ark_bn254::Fq6 {
        let mut prng = ChaCha20Rng::seed_from_u64(rng().random());
        ark_bn254::Fq6::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::Fq6) -> Vec<bool> {
        let mut bits = Vec::new();
        bits.extend(Fq2::to_bits(u.c0));
        bits.extend(Fq2::to_bits(u.c1));
        bits.extend(Fq2::to_bits(u.c2));
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fq6 {
        let bits1 = &bits[0..Fq2::N_BITS].to_vec();
        let bits2 = &bits[Fq2::N_BITS..Fq2::N_BITS * 2].to_vec();
        let bits3 = &bits[Fq2::N_BITS * 2..Fq2::N_BITS * 3].to_vec();
        ark_bn254::Fq6::new(
            Fq2::from_bits(bits1.clone()),
            Fq2::from_bits(bits2.clone()),
            Fq2::from_bits(bits3.clone()),
        )
    }

    pub fn wires() -> Wires {
        (0..Self::N_BITS).map(|_| new_wirex()).collect()
    }

    pub fn wires_set(u: ark_bn254::Fq6) -> Wires {
        Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                let wire = new_wirex();
                wire.borrow_mut().set(*bit);
                wire
            })
            .collect()
    }

    pub fn wires_set_montgomery(u: ark_bn254::Fq6) -> Wires {
        Self::wires_set(Self::as_montgomery(u))
    }

    pub fn from_wires(wires: Wires) -> ark_bn254::Fq6 {
        Self::from_bits(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_montgomery_wires(wires: Wires) -> ark_bn254::Fq6 {
        Self::from_montgomery(Self::from_wires(wires))
    }

    pub fn add(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();
        let b_c0 = b[0..Fq2::N_BITS].to_vec();
        let b_c1 = b[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let b_c2 = b[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();
        let wires_1 = circuit.extend(Fq2::add(a_c0, b_c0));
        let wires_2 = circuit.extend(Fq2::add(a_c1, b_c1));
        let wires_3 = circuit.extend(Fq2::add(a_c2, b_c2));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit.add_wires(wires_3);
        circuit
    }

    pub fn neg(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq2::neg(a_c0));
        let wires_2 = circuit.extend(Fq2::neg(a_c1));
        let wires_3 = circuit.extend(Fq2::neg(a_c2));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit.add_wires(wires_3);
        circuit
    }

    pub fn sub(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();
        let b_c0 = b[0..Fq2::N_BITS].to_vec();
        let b_c1 = b[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let b_c2 = b[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();
        let wires_1 = circuit.extend(Fq2::sub(a_c0, b_c0));
        let wires_2 = circuit.extend(Fq2::sub(a_c1, b_c1));
        let wires_3 = circuit.extend(Fq2::sub(a_c2, b_c2));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit.add_wires(wires_3);
        circuit
    }

    pub fn double(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq2::double(a_c0));
        let wires_2 = circuit.extend(Fq2::double(a_c1));
        let wires_3 = circuit.extend(Fq2::double(a_c2));
        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit.add_wires(wires_3);
        circuit
    }

    pub fn div6(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq2::div6(a_c0.clone()));
        let wires_2 = circuit.extend(Fq2::div6(a_c1.clone()));
        let wires_3 = circuit.extend(Fq2::div6(a_c2.clone()));

        circuit.add_wires(wires_1);
        circuit.add_wires(wires_2);
        circuit.add_wires(wires_3);

        circuit
    }

    pub fn mul_montgomery(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();
        let b_c0 = b[0..Fq2::N_BITS].to_vec();
        let b_c1 = b[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let b_c2 = b[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let v0 = circuit.extend(Fq2::mul_montgomery(a_c0.clone(), b_c0.clone()));

        let wires_2: Wires = circuit.extend(Fq2::add(a_c0.clone(), a_c2.clone()));
        let wires_3: Wires = circuit.extend(Fq2::add(wires_2.clone(), a_c1.clone()));
        let wires_4: Wires = circuit.extend(Fq2::sub(wires_2.clone(), a_c1.clone()));
        let wires_5: Wires = circuit.extend(Fq2::double(a_c1.clone()));
        let wires_6: Wires = circuit.extend(Fq2::double(a_c2.clone()));
        let wires_7: Wires = circuit.extend(Fq2::double(wires_6.clone()));
        let wires_8: Wires = circuit.extend(Fq2::add(a_c0.clone(), wires_5.clone()));
        let wires_9: Wires = circuit.extend(Fq2::add(wires_8.clone(), wires_7.clone()));

        let wires_10: Wires = circuit.extend(Fq2::add(b_c0.clone(), b_c2.clone()));
        let wires_11: Wires = circuit.extend(Fq2::add(wires_10.clone(), b_c1.clone()));
        let wires_12: Wires = circuit.extend(Fq2::sub(wires_10.clone(), b_c1.clone()));
        let wires_13: Wires = circuit.extend(Fq2::double(b_c1.clone()));
        let wires_14: Wires = circuit.extend(Fq2::double(b_c2.clone()));
        let wires_15: Wires = circuit.extend(Fq2::double(wires_14.clone()));
        let wires_16: Wires = circuit.extend(Fq2::add(b_c0.clone(), wires_13.clone()));
        let wires_17: Wires = circuit.extend(Fq2::add(wires_16.clone(), wires_15.clone()));

        let v1 = circuit.extend(Fq2::mul_montgomery(wires_3.clone(), wires_11.clone()));
        let v2 = circuit.extend(Fq2::mul_montgomery(wires_4.clone(), wires_12.clone()));
        let v3 = circuit.extend(Fq2::mul_montgomery(wires_9.clone(), wires_17.clone()));
        let v4 = circuit.extend(Fq2::mul_montgomery(a_c2.clone(), b_c2.clone()));

        let v2_2 = circuit.extend(Fq2::double(v2.clone()));

        let v0_3 = circuit.extend(Fq2::triple(v0.clone()));
        let v1_3 = circuit.extend(Fq2::triple(v1.clone()));
        let v2_3 = circuit.extend(Fq2::triple(v2.clone()));
        let v4_3 = circuit.extend(Fq2::triple(v4.clone()));

        let v0_6 = circuit.extend(Fq2::double(v0_3.clone()));
        let v1_6 = circuit.extend(Fq2::double(v1_3.clone()));
        let v4_6 = circuit.extend(Fq2::double(v4_3.clone()));

        let v4_12 = circuit.extend(Fq2::double(v4_6.clone()));

        let wires_18: Wires = circuit.extend(Fq2::sub(v0_3.clone(), v1_3.clone()));
        let wires_19: Wires = circuit.extend(Fq2::sub(wires_18.clone(), v2.clone()));
        let wires_20: Wires = circuit.extend(Fq2::add(wires_19.clone(), v3.clone()));
        let wires_21: Wires = circuit.extend(Fq2::sub(wires_20.clone(), v4_12.clone()));
        let wires_22: Wires = circuit.extend(Fq2::mul_by_nonresidue(wires_21.clone()));
        let mut c0 = circuit.extend(Fq2::add(wires_22.clone(), v0_6.clone()));

        let wires_23: Wires = circuit.extend(Fq2::sub(v1_6.clone(), v0_3.clone()));
        let wires_24: Wires = circuit.extend(Fq2::sub(wires_23.clone(), v2_2.clone()));
        let wires_25: Wires = circuit.extend(Fq2::sub(wires_24.clone(), v3.clone()));
        let wires_26: Wires = circuit.extend(Fq2::add(wires_25.clone(), v4_12.clone()));
        let wires_27: Wires = circuit.extend(Fq2::mul_by_nonresidue(v4_6.clone()));
        let c1: Wires = circuit.extend(Fq2::add(wires_26, wires_27));

        let wires_28: Wires = circuit.extend(Fq2::sub(v1_3.clone(), v0_6.clone()));
        let wires_29: Wires = circuit.extend(Fq2::add(wires_28.clone(), v2_3.clone()));
        let c2: Wires = circuit.extend(Fq2::sub(wires_29.clone(), v4_6.clone()));

        c0.extend(c1);
        c0.extend(c2);
        let result = circuit.extend(Fq6::div6(c0));

        circuit.add_wires(result);
        circuit
    }

    pub fn mul_by_constant_montgomery(a: Wires, b: ark_bn254::Fq6) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let v0 = circuit.extend(Fq2::mul_by_constant_montgomery(a_c0.clone(), b.c0));

        let wires_2: Wires = circuit.extend(Fq2::add(a_c0.clone(), a_c2.clone()));
        let wires_3: Wires = circuit.extend(Fq2::add(wires_2.clone(), a_c1.clone()));
        let wires_4: Wires = circuit.extend(Fq2::sub(wires_2.clone(), a_c1.clone()));
        let wires_5: Wires = circuit.extend(Fq2::double(a_c1.clone()));
        let wires_6: Wires = circuit.extend(Fq2::double(a_c2.clone()));
        let wires_7: Wires = circuit.extend(Fq2::double(wires_6.clone()));
        let wires_8: Wires = circuit.extend(Fq2::add(a_c0.clone(), wires_5.clone()));
        let wires_9: Wires = circuit.extend(Fq2::add(wires_8.clone(), wires_7.clone()));

        let v1 = circuit.extend(Fq2::mul_by_constant_montgomery(
            wires_3.clone(),
            b.c0 + b.c1 + b.c2,
        ));
        let v2 = circuit.extend(Fq2::mul_by_constant_montgomery(
            wires_4.clone(),
            b.c0 - b.c1 + b.c2,
        ));
        let v3 = circuit.extend(Fq2::mul_by_constant_montgomery(
            wires_9.clone(),
            b.c0 + b.c1.double() + b.c2.double().double(),
        ));
        let v4 = circuit.extend(Fq2::mul_by_constant_montgomery(a_c2.clone(), b.c2));

        let v2_2 = circuit.extend(Fq2::double(v2.clone()));

        let v0_3 = circuit.extend(Fq2::triple(v0.clone()));
        let v1_3 = circuit.extend(Fq2::triple(v1.clone()));
        let v2_3 = circuit.extend(Fq2::triple(v2.clone()));
        let v4_3 = circuit.extend(Fq2::triple(v4.clone()));

        let v0_6 = circuit.extend(Fq2::double(v0_3.clone()));
        let v1_6 = circuit.extend(Fq2::double(v1_3.clone()));
        let v4_6 = circuit.extend(Fq2::double(v4_3.clone()));

        let v4_12 = circuit.extend(Fq2::double(v4_6.clone()));

        let wires_18: Wires = circuit.extend(Fq2::sub(v0_3.clone(), v1_3.clone()));
        let wires_19: Wires = circuit.extend(Fq2::sub(wires_18.clone(), v2.clone()));
        let wires_20: Wires = circuit.extend(Fq2::add(wires_19.clone(), v3.clone()));
        let wires_21: Wires = circuit.extend(Fq2::sub(wires_20.clone(), v4_12.clone()));
        let wires_22: Wires = circuit.extend(Fq2::mul_by_nonresidue(wires_21.clone()));
        let mut c0 = circuit.extend(Fq2::add(wires_22.clone(), v0_6.clone()));

        let wires_23: Wires = circuit.extend(Fq2::sub(v1_6.clone(), v0_3.clone()));
        let wires_24: Wires = circuit.extend(Fq2::sub(wires_23.clone(), v2_2.clone()));
        let wires_25: Wires = circuit.extend(Fq2::sub(wires_24.clone(), v3.clone()));
        let wires_26: Wires = circuit.extend(Fq2::add(wires_25.clone(), v4_12.clone()));
        let wires_27: Wires = circuit.extend(Fq2::mul_by_nonresidue(v4_6.clone()));
        let c1: Wires = circuit.extend(Fq2::add(wires_26, wires_27));

        let wires_28: Wires = circuit.extend(Fq2::sub(v1_3.clone(), v0_6.clone()));
        let wires_29: Wires = circuit.extend(Fq2::add(wires_28.clone(), v2_3.clone()));
        let c2: Wires = circuit.extend(Fq2::sub(wires_29.clone(), v4_6.clone()));

        c0.extend(c1);
        c0.extend(c2);
        let result = circuit.extend(Fq6::div6(c0));

        circuit.add_wires(result);
        circuit
    }

    pub fn mul_by_fq2_montgomery(a: Wires, b: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(b.len(), Fq2::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let c0 = circuit.extend(Fq2::mul_montgomery(a_c0, b.clone()));
        let c1 = circuit.extend(Fq2::mul_montgomery(a_c1, b.clone()));
        let c2 = circuit.extend(Fq2::mul_montgomery(a_c2, b.clone()));
        circuit.add_wires(c0);
        circuit.add_wires(c1);
        circuit.add_wires(c2);
        circuit
    }

    pub fn mul_by_constant_fq2_montgomery(a: Wires, b: ark_bn254::Fq2) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let c0 = circuit.extend(Fq2::mul_by_constant_montgomery(a_c0, b));
        let c1 = circuit.extend(Fq2::mul_by_constant_montgomery(a_c1, b));
        let c2 = circuit.extend(Fq2::mul_by_constant_montgomery(a_c2, b));
        circuit.add_wires(c0);
        circuit.add_wires(c1);
        circuit.add_wires(c2);
        circuit
    }

    pub fn mul_by_nonresidue(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();
        let u = circuit.extend(Fq2::mul_by_nonresidue(a_c2));

        circuit.add_wires(u);
        circuit.add_wires(a_c0);
        circuit.add_wires(a_c1);
        circuit
    }

    pub fn mul_by_01_montgomery(a: Wires, c0: Wires, c1: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(c0.len(), Fq2::N_BITS);
        assert_eq!(c1.len(), Fq2::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq2::mul_montgomery(a_c0.clone(), c0.clone()));
        let wires_2 = circuit.extend(Fq2::mul_montgomery(a_c1.clone(), c1.clone()));
        let wires_3 = circuit.extend(Fq2::add(a_c1.clone(), a_c2.clone()));
        let wires_4 = circuit.extend(Fq2::mul_montgomery(wires_3.clone(), c1.clone()));
        let wires_5 = circuit.extend(Fq2::sub(wires_4.clone(), wires_2.clone()));
        let wires_6 = circuit.extend(Fq2::mul_by_nonresidue(wires_5.clone()));
        let wires_7 = circuit.extend(Fq2::add(wires_6.clone(), wires_1.clone()));
        let wires_8 = circuit.extend(Fq2::add(a_c0.clone(), a_c1.clone()));
        let wires_9 = circuit.extend(Fq2::add(c0.clone(), c1.clone()));
        let wires_10 = circuit.extend(Fq2::mul_montgomery(wires_8.clone(), wires_9.clone()));
        let wires_11 = circuit.extend(Fq2::sub(wires_10.clone(), wires_1.clone()));
        let wires_12 = circuit.extend(Fq2::sub(wires_11.clone(), wires_2.clone()));
        let wires_13 = circuit.extend(Fq2::add(a_c0.clone(), a_c2.clone()));
        let wires_14 = circuit.extend(Fq2::mul_montgomery(wires_13.clone(), c0.clone()));
        let wires_15 = circuit.extend(Fq2::sub(wires_14.clone(), wires_1.clone()));
        let wires_16 = circuit.extend(Fq2::add(wires_15.clone(), wires_2.clone()));
        circuit.add_wires(wires_7);
        circuit.add_wires(wires_12);
        circuit.add_wires(wires_16);
        circuit
    }

    pub fn mul_by_01_constant1_montgomery(a: Wires, c0: Wires, c1: ark_bn254::Fq2) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        assert_eq!(c0.len(), Fq2::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let wires_1 = circuit.extend(Fq2::mul_montgomery(a_c0.clone(), c0.clone()));
        let wires_2 = circuit.extend(Fq2::mul_by_constant_montgomery(a_c1.clone(), c1));
        let wires_3 = circuit.extend(Fq2::add(a_c1.clone(), a_c2.clone()));
        let wires_4 = circuit.extend(Fq2::mul_by_constant_montgomery(wires_3.clone(), c1));
        let wires_5 = circuit.extend(Fq2::sub(wires_4.clone(), wires_2.clone()));
        let wires_6 = circuit.extend(Fq2::mul_by_nonresidue(wires_5.clone()));
        let wires_7 = circuit.extend(Fq2::add(wires_6.clone(), wires_1.clone()));
        let wires_8 = circuit.extend(Fq2::add(a_c0.clone(), a_c1.clone()));
        let wires_9 = circuit.extend(Fq2::add_constant(c0.clone(), c1));
        let wires_10 = circuit.extend(Fq2::mul_montgomery(wires_8.clone(), wires_9.clone()));
        let wires_11 = circuit.extend(Fq2::sub(wires_10.clone(), wires_1.clone()));
        let wires_12 = circuit.extend(Fq2::sub(wires_11.clone(), wires_2.clone()));
        let wires_13 = circuit.extend(Fq2::add(a_c0.clone(), a_c2.clone()));
        let wires_14 = circuit.extend(Fq2::mul_montgomery(wires_13.clone(), c0.clone()));
        let wires_15 = circuit.extend(Fq2::sub(wires_14.clone(), wires_1.clone()));
        let wires_16 = circuit.extend(Fq2::add(wires_15.clone(), wires_2.clone()));
        circuit.add_wires(wires_7);
        circuit.add_wires(wires_12);
        circuit.add_wires(wires_16);
        circuit
    }

    // https://eprint.iacr.org/2006/471.pdf
    pub fn square_montgomery(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let s_0 = circuit.extend(Fq2::square_montgomery(a_c0.clone()));
        let wires_1 = circuit.extend(Fq2::add(a_c0.clone(), a_c2.clone()));
        let wires_2 = circuit.extend(Fq2::add(wires_1.clone(), a_c1.clone()));
        let wires_3 = circuit.extend(Fq2::sub(wires_1.clone(), a_c1.clone()));
        let s_1 = circuit.extend(Fq2::square_montgomery(wires_2));
        let s_2 = circuit.extend(Fq2::square_montgomery(wires_3));
        let wires_4: Wires = circuit.extend(Fq2::mul_montgomery(a_c1.clone(), a_c2.clone()));
        let s_3: Wires = circuit.extend(Fq2::double(wires_4));
        let s_4 = circuit.extend(Fq2::square_montgomery(a_c2.clone()));
        let wires_5 = circuit.extend(Fq2::add(s_1.clone(), s_2.clone()));
        let t_1 = circuit.extend(Fq2::half(wires_5));

        let wires_6 = circuit.extend(Fq2::mul_by_nonresidue(s_3.clone()));
        let res_c0 = circuit.extend(Fq2::add(s_0.clone(), wires_6.clone()));
        let wires_7 = circuit.extend(Fq2::mul_by_nonresidue(s_4.clone()));
        let wires_8 = circuit.extend(Fq2::sub(s_1.clone(), s_3.clone()));
        let wires_9 = circuit.extend(Fq2::sub(wires_8.clone(), t_1.clone()));
        let res_c1 = circuit.extend(Fq2::add(wires_9, wires_7.clone()));
        let wires_10 = circuit.extend(Fq2::sub(t_1, s_0));
        let res_c2 = circuit.extend(Fq2::sub(wires_10, s_4));

        circuit.add_wires(res_c0);
        circuit.add_wires(res_c1);
        circuit.add_wires(res_c2);
        circuit
    }

    pub fn inverse_montgomery(r: Wires) -> Circuit {
        assert_eq!(r.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a = r[0..Fq2::N_BITS].to_vec();
        let b = r[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let c = r[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let a_square = circuit.extend(Fq2::square_montgomery(a.clone()));
        let b_square = circuit.extend(Fq2::square_montgomery(b.clone()));
        let c_square = circuit.extend(Fq2::square_montgomery(c.clone()));

        let ab = circuit.extend(Fq2::mul_montgomery(a.clone(), b.clone()));
        let ac = circuit.extend(Fq2::mul_montgomery(a.clone(), c.clone()));
        let bc = circuit.extend(Fq2::mul_montgomery(b.clone(), c.clone()));

        let bc_beta = circuit.extend(Fq2::mul_by_nonresidue(bc));

        let a_square_minus_bc_beta = circuit.extend(Fq2::sub(a_square, bc_beta));

        let c_square_beta = circuit.extend(Fq2::mul_by_nonresidue(c_square));
        let c_square_beta_minus_ab = circuit.extend(Fq2::sub(c_square_beta, ab));
        let b_square_minus_ac = circuit.extend(Fq2::sub(b_square, ac));

        let wires_1 = circuit.extend(Fq2::mul_montgomery(
            c_square_beta_minus_ab.clone(),
            c.clone(),
        ));

        let wires_2 = circuit.extend(Fq2::mul_montgomery(b_square_minus_ac.clone(), b));

        let wires_1_plus_wires_2 = circuit.extend(Fq2::add(wires_1.clone(), wires_2.clone()));
        let wires_3 = circuit.extend(Fq2::mul_by_nonresidue(wires_1_plus_wires_2));

        let wires_4 = circuit.extend(Fq2::mul_montgomery(a, a_square_minus_bc_beta.clone()));
        let norm = circuit.extend(Fq2::add(wires_4, wires_3));

        let inverse_norm = circuit.extend(Fq2::inverse_montgomery(norm));
        let res_c0 = circuit.extend(Fq2::mul_montgomery(
            a_square_minus_bc_beta,
            inverse_norm.clone(),
        ));
        let res_c1 = circuit.extend(Fq2::mul_montgomery(
            c_square_beta_minus_ab,
            inverse_norm.clone(),
        ));
        let res_c2 = circuit.extend(Fq2::mul_montgomery(b_square_minus_ac, inverse_norm.clone()));

        circuit.add_wires(res_c0);
        circuit.add_wires(res_c1);
        circuit.add_wires(res_c2);
        circuit
    }

    pub fn frobenius_montgomery(a: Wires, i: usize) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();

        let a_c0 = a[0..Fq2::N_BITS].to_vec();
        let a_c1 = a[Fq2::N_BITS..2 * Fq2::N_BITS].to_vec();
        let a_c2 = a[2 * Fq2::N_BITS..3 * Fq2::N_BITS].to_vec();

        let frobenius_a_c0 = circuit.extend(Fq2::frobenius_montgomery(a_c0, i));
        let frobenius_a_c1 = circuit.extend(Fq2::frobenius_montgomery(a_c1, i));
        let frobenius_a_c2 = circuit.extend(Fq2::frobenius_montgomery(a_c2, i));
        let frobenius_a_c1_updated = circuit.extend(Fq2::mul_by_constant_montgomery(
            frobenius_a_c1,
            Fq2::as_montgomery(
                ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C1
                    [i % ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C1.len()],
            ),
        ));
        let frobenius_a_c2_updated = circuit.extend(Fq2::mul_by_constant_montgomery(
            frobenius_a_c2,
            Fq2::as_montgomery(
                ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C2
                    [i % ark_bn254::Fq6Config::FROBENIUS_COEFF_FP6_C2.len()],
            ),
        ));
        circuit.0.extend(frobenius_a_c0);
        circuit.0.extend(frobenius_a_c1_updated);
        circuit.0.extend(frobenius_a_c2_updated);
        circuit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Field, Fp12Config};
    use serial_test::serial;

    #[test]
    fn test_fq6_random() {
        let u = Fq6::random();
        println!("u: {:?}", u);
        let b = Fq6::to_bits(u);
        let v = Fq6::from_bits(b);
        println!("v: {:?}", v);
        assert_eq!(u, v);
    }

    #[test]
    fn test_fq6_add() {
        let a = Fq6::random();
        let b = Fq6::random();
        let circuit = Fq6::add(Fq6::wires_set(a), Fq6::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c, a + b);
    }

    #[test]
    fn test_fq6_neg() {
        let a = Fq6::random();
        let circuit = Fq6::neg(Fq6::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c, -a);
    }

    #[test]
    fn test_fq6_sub() {
        let a = Fq6::random();
        let b = Fq6::random();
        let circuit = Fq6::sub(Fq6::wires_set(a), Fq6::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c, a - b);
    }

    #[test]
    fn test_fq6_double() {
        let a = Fq6::random();
        let circuit = Fq6::double(Fq6::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c, a + a);
    }

    #[test]
    fn test_fq6_div6() {
        let a = Fq6::random();
        let circuit = Fq6::div6(Fq6::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c + c + c + c + c + c, a);
    }

    #[test]
    #[serial]
    fn test_fq6_mul_montgomery() {
        let a = Fq6::random();
        let b = Fq6::random();
        let circuit = Fq6::mul_montgomery(
            Fq6::wires_set(Fq6::as_montgomery(a)),
            Fq6::wires_set(Fq6::as_montgomery(b)),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c, Fq6::as_montgomery(a * b));
    }

    #[test]
    fn test_fq6_mul_by_constant_montgomery() {
        let a = Fq6::random();
        let b = Fq6::random();
        let circuit =
            Fq6::mul_by_constant_montgomery(Fq6::wires_set_montgomery(a), Fq6::as_montgomery(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c, Fq6::as_montgomery(a * b));
    }

    #[test]
    fn test_fq6_mul_by_fq2_montgomery() {
        let a = Fq6::random();
        let b = Fq2::random();
        let circuit =
            Fq6::mul_by_fq2_montgomery(Fq6::wires_set_montgomery(a), Fq2::wires_set_montgomery(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(
            c,
            Fq6::as_montgomery(
                a * ark_bn254::Fq6::new(b, ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
            )
        );
    }

    #[test]
    fn test_fq6_mul_by_constant_fq2_montgomery() {
        let a = Fq6::random();
        let b = Fq2::random();
        let circuit = Fq6::mul_by_constant_fq2_montgomery(
            Fq6::wires_set_montgomery(a),
            Fq2::as_montgomery(b),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(
            c,
            Fq6::as_montgomery(
                a * ark_bn254::Fq6::new(b, ark_bn254::Fq2::ZERO, ark_bn254::Fq2::ZERO)
            )
        );
    }

    #[test]
    fn test_fq6_mul_by_nonresidue() {
        let a = Fq6::random();
        let circuit = Fq6::mul_by_nonresidue(Fq6::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        let mut a_nonresiude = a;
        ark_bn254::Fq12Config::mul_fp6_by_nonresidue_in_place(&mut a_nonresiude);
        assert_eq!(c, a_nonresiude);
    }

    #[test]
    fn test_fq6_mul_by_01_montgomery() {
        let a = Fq6::random();
        let c0 = Fq2::random();
        let c1 = Fq2::random();
        let circuit = Fq6::mul_by_01_montgomery(
            Fq6::wires_set_montgomery(a),
            Fq2::wires_set_montgomery(c0),
            Fq2::wires_set_montgomery(c1),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        let mut b = a;
        b.mul_by_01(&c0, &c1);
        assert_eq!(c, Fq6::as_montgomery(b));
    }

    #[test]
    #[serial]
    fn test_fq6_square_montgomery() {
        let a = Fq6::random();
        let circuit = Fq6::square_montgomery(Fq6::wires_set_montgomery(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c, Fq6::as_montgomery(a * a));
    }

    #[test]
    #[serial]
    fn test_fq6_inverse_montgomery() {
        let a = Fq6::random();
        let circuit = Fq6::inverse_montgomery(Fq6::wires_set_montgomery(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c, Fq6::as_montgomery(a.inverse().unwrap()));
    }

    #[test]
    fn test_fq6_frobenius_montgomery() {
        let a = Fq6::random();

        let circuit = Fq6::frobenius_montgomery(Fq6::wires_set_montgomery(a), 0);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c, Fq6::as_montgomery(a.frobenius_map(0)));

        let circuit = Fq6::frobenius_montgomery(Fq6::wires_set_montgomery(a), 1);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq6::from_wires(circuit.0);
        assert_eq!(c, Fq6::as_montgomery(a.frobenius_map(1)));
    }
}
