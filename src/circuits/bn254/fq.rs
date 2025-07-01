use crate::circuits::bigint::U254;
use crate::{bag::*, circuits::bn254::fp254impl::Fp254Impl};
use ark_ff::Field;
use ark_ff::{PrimeField, UniformRand};
use ark_std::rand::SeedableRng;
use num_bigint::BigUint;
use rand::{Rng, rng};
use rand_chacha::ChaCha20Rng;
use std::str::FromStr;

pub struct Fq;

impl Fp254Impl for Fq {
    const MODULUS: &'static str =
        "21888242871839275222246405745257275088696311157297823662689037894645226208583";
    const MONTGOMERY_M_INVERSE: &'static str =
        "4759646384140481320982610724935209484903937857060724391493050186936685796471";
    const MONTGOMERY_R_INVERSE: &'static str =
        "18289368484950178621272022062020525048389989670507786348948026221581485535495";
    const N_BITS: usize = 254;

    fn half_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fq::from(1) / ark_bn254::Fq::from(2))
    }

    fn one_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fq::from(1) / ark_bn254::Fq::from(3))
    }

    fn two_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fq::from(2) / ark_bn254::Fq::from(3))
    }
}

impl Fq {
    pub fn as_montgomery(a: ark_bn254::Fq) -> ark_bn254::Fq {
        a * ark_bn254::Fq::from(Self::montgomery_r_as_biguint())
    }

    pub fn from_montgomery(a: ark_bn254::Fq) -> ark_bn254::Fq {
        a / ark_bn254::Fq::from(Self::montgomery_r_as_biguint())
    }

    pub fn random() -> ark_bn254::Fq {
        let mut prng = ChaCha20Rng::seed_from_u64(rng().random());
        ark_bn254::Fq::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::Fq) -> Vec<bool> {
        let mut bytes = BigUint::from(u).to_bytes_le();
        bytes.extend(vec![0_u8; 32 - bytes.len()]);
        let mut bits = Vec::new();
        for byte in bytes {
            for i in 0..8 {
                bits.push(((byte >> i) & 1) == 1)
            }
        }
        bits.pop();
        bits.pop();
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fq {
        let zero = BigUint::ZERO;
        let one = BigUint::from(1_u8);
        let mut u = zero.clone();
        for bit in bits.iter().rev() {
            u = u.clone() + u.clone() + if *bit { one.clone() } else { zero.clone() };
        }
        ark_bn254::Fq::from(u)
    }

    pub fn wires() -> Wires {
        (0..Self::N_BITS).map(|_| new_wirex()).collect()
    }

    pub fn wires_set(u: ark_bn254::Fq) -> Wires {
        Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                let wire = new_wirex();
                wire.borrow_mut().set(*bit);
                wire
            })
            .collect()
    }

    pub fn wires_set_montgomery(u: ark_bn254::Fq) -> Wires {
        Self::wires_set(Self::as_montgomery(u))
    }

    pub fn from_wires(wires: Wires) -> ark_bn254::Fq {
        Self::from_bits(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_montgomery_wires(wires: Wires) -> ark_bn254::Fq {
        Self::from_montgomery(Self::from_wires(wires))
    }

    // check if x is a quadratic non-residue (QNR) in Fq
    pub fn is_qnr_montgomery(x: Wires) -> Circuit {
        let mut circuit = Circuit::empty();
        // y = x^((p - 1)/2)
        let exp = ark_bn254::Fq::from(ark_bn254::Fq::MODULUS_MINUS_ONE_DIV_TWO);
        let y = circuit.extend(Fq::exp_by_constant_montgomery(x.clone(), exp));

        let neg_one = -ark_bn254::Fq::ONE;
        let neg_one_mont = Fq::wires_set_montgomery(neg_one);

        let is_qnr = circuit.extend(U254::equal(y, neg_one_mont));

        circuit.add_wires(is_qnr);
        circuit
    }

    pub fn sqrt_montgomery(a: Wires) -> Circuit {
        assert_eq!(a.len(), Self::N_BITS);
        let mut circuit = Circuit::empty();
        let b = circuit.extend(Self::exp_by_constant_montgomery(
            a,
            ark_bn254::Fq::from_str(Self::MODULUS_ADD_1_DIV_4).unwrap(),
        ));
        circuit.add_wires(b);
        circuit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::AdditiveGroup;
    use ark_std::test_rng;

    #[test]
    fn test_fq_random() {
        let u = Fq::random();
        println!("u: {:?}", u);
        let b = Fq::to_bits(u);
        let v = Fq::from_bits(b);
        println!("v: {:?}", v);
        assert_eq!(u, v);
    }

    #[test]
    fn test_fq_add() {
        let a = Fq::random();
        let b = Fq::random();
        let circuit = Fq::add(Fq::wires_set(a), Fq::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, a + b);
    }

    #[test]
    fn test_fq_add_constant() {
        let a = Fq::random();
        let b = Fq::random();
        let circuit = Fq::add_constant(Fq::wires_set(a), b);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, a + b);
    }

    #[test]
    fn test_fq_neg() {
        let a = Fq::random();
        let circuit = Fq::neg(Fq::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, -a);
    }

    #[test]
    fn test_fq_sub() {
        let a = Fq::random();
        let b = Fq::random();
        let circuit = Fq::sub(Fq::wires_set(a), Fq::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, a - b);
    }

    #[test]
    fn test_fq_double() {
        let a = Fq::random();
        let circuit = Fq::double(Fq::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, a + a);
    }

    #[test]
    fn test_fq_half() {
        let a = Fq::random();
        let circuit = Fq::half(Fq::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c + c, a);
    }

    #[test]
    fn test_fq_triple() {
        let a = Fq::random();
        let circuit = Fq::triple(Fq::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, a + a + a);
    }

    #[test]
    fn test_fq_mul() {
        let a = Fq::random();
        let b = Fq::random();
        let circuit = Fq::mul(Fq::wires_set(a), Fq::wires_set(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, a * b);
    }

    #[test]
    fn test_fq_mul_montgomery() {
        let a = Fq::random();
        let b = Fq::random();
        let circuit = Fq::mul_montgomery(
            Fq::wires_set(Fq::as_montgomery(a)),
            Fq::wires_set(Fq::as_montgomery(b)),
        );
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, Fq::as_montgomery(a * b));
    }

    #[test]
    fn test_fq_mul_by_constant() {
        let a = Fq::random();
        let b = Fq::random();
        let circuit = Fq::mul_by_constant(Fq::wires_set(a), b);
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, a * b);
    }

    #[test]
    fn test_fq_mul_by_constant_montgomery() {
        let a = Fq::random();
        let b = Fq::random();
        let c = ark_bn254::Fq::ONE;
        let d = ark_bn254::Fq::ZERO;

        let circuit =
            Fq::mul_by_constant_montgomery(Fq::wires_set_montgomery(a), Fq::as_montgomery(b));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let e = Fq::from_wires(circuit.0);
        assert_eq!(e, Fq::as_montgomery(a * b));

        let circuit =
            Fq::mul_by_constant_montgomery(Fq::wires_set_montgomery(a), Fq::as_montgomery(c));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let e = Fq::from_wires(circuit.0);
        assert_eq!(e, Fq::as_montgomery(a * c));

        let circuit =
            Fq::mul_by_constant_montgomery(Fq::wires_set_montgomery(a), Fq::as_montgomery(d));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let e = Fq::from_wires(circuit.0);
        assert_eq!(e, Fq::as_montgomery(a * d));
    }

    #[test]
    fn test_fq_square() {
        let a = Fq::random();
        let circuit = Fq::square(Fq::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, a * a);
    }

    #[test]
    fn test_fq_square_montgomery() {
        let a = Fq::random();
        let circuit = Fq::square_montgomery(Fq::wires_set_montgomery(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, Fq::as_montgomery(a * a));
    }

    #[test]
    fn test_fq_inverse() {
        let a = Fq::random();
        let circuit = Fq::inverse(Fq::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, a.inverse().unwrap());
    }

    #[test]
    fn test_fq_inverse_montgomery() {
        let a = Fq::random();
        let circuit = Fq::inverse_montgomery(Fq::wires_set_montgomery(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.0);
        assert_eq!(c, Fq::as_montgomery(a.inverse().unwrap()));
    }

    #[test]
    fn test_fq_div6() {
        let a = Fq::random();
        let circuit = Fq::div6(Fq::wires_set(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }

        let c = Fq::from_wires(circuit.0);
        assert_eq!(c + c + c + c + c + c, a);
    }

    #[test]
    fn test_fq_exp_by_constant_montgomery() {
        use ark_ff::PrimeField;
        let ut = |b: u32| {
            let a = Fq::random();
            let b = ark_bn254::Fq::from(b);
            let expect_a_to_power_of_b = a.pow(b.into_bigint());

            let circuit =
                Fq::exp_by_constant_montgomery(Fq::wires_set_montgomery(a), ark_bn254::Fq::from(b));
            circuit.gate_counts().print();
            for mut gate in circuit.1 {
                gate.evaluate();
            }
            let c = Fq::from_montgomery_wires(circuit.0);
            assert_eq!(expect_a_to_power_of_b, c);
        };
        ut(0);
        ut(1);
        ut(u32::rand(&mut test_rng()));
    }

    #[test]
    fn test_fq_sqrt_montgomery() {
        let a = Fq::random();
        let aa = a * a;
        let circuit = Fq::sqrt_montgomery(Fq::wires_set_montgomery(aa));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let c = Fq::from_montgomery_wires(circuit.0);
        let la = match a > -a {
            true => a,
            false => -a,
        };
        assert_eq!(c, la);
    }

    #[test]
    fn test_fq_is_qnr_montgomery() {
        use num_traits::One;
        let a = Fq::random();
        println!("{}", a.legendre().is_qnr());
        let circuit = Fq::is_qnr_montgomery(Fq::wires_set_montgomery(a));
        circuit.gate_counts().print();
        for mut gate in circuit.1 {
            gate.evaluate();
        }
        let is_qnr = Fq::from_montgomery_wires(circuit.0);
        assert_eq!(is_qnr.is_one(), a.legendre().is_qnr());
    }
}
