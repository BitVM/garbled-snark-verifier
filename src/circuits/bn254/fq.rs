use crate::{bag::*, circuits::bn254::fp254impl::Fp254Impl};
use ark_ff::UniformRand;
use ark_std::rand::SeedableRng;
use num_bigint::BigUint;
use rand::{Rng, rng};
use rand_chacha::ChaCha20Rng;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{AdditiveGroup, Field};

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
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, a + b);
    }

    #[test]
    fn test_fq_add_constant() {
        let a = Fq::random();
        let b = Fq::random();
        let circuit = Fq::add_constant(Fq::wires_set(a), b);
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, a + b);
    }

    #[test]
    fn test_fq_neg() {
        let a = Fq::random();
        let circuit = Fq::neg(Fq::wires_set(a));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, -a);
    }

    #[test]
    fn test_fq_sub() {
        let a = Fq::random();
        let b = Fq::random();
        let circuit = Fq::sub(Fq::wires_set(a), Fq::wires_set(b));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, a - b);
    }

    #[test]
    fn test_fq_double() {
        let a = Fq::random();
        let circuit = Fq::double(Fq::wires_set(a));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, a + a);
    }

    #[test]
    fn test_fq_half() {
        let a = Fq::random();
        let circuit = Fq::half(Fq::wires_set(a));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c + c, a);
    }

    #[test]
    fn test_fq_triple() {
        let a = Fq::random();
        let circuit = Fq::triple(Fq::wires_set(a));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, a + a + a);
    }

    #[test]
    fn test_fq_mul() {
        let a = Fq::random();
        let b = Fq::random();
        let circuit = Fq::mul(Fq::wires_set(a), Fq::wires_set(b));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
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
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, Fq::as_montgomery(a * b));
    }

    #[test]
    fn test_fq_mul_by_constant() {
        let a = Fq::random();
        let b = Fq::random();
        let circuit = Fq::mul_by_constant(Fq::wires_set(a), b);
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
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
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let e = Fq::from_wires(circuit.wires);
        assert_eq!(e, Fq::as_montgomery(a * b));

        let circuit =
            Fq::mul_by_constant_montgomery(Fq::wires_set_montgomery(a), Fq::as_montgomery(c));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let e = Fq::from_wires(circuit.wires);
        assert_eq!(e, Fq::as_montgomery(a * c));

        let circuit =
            Fq::mul_by_constant_montgomery(Fq::wires_set_montgomery(a), Fq::as_montgomery(d));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let e = Fq::from_wires(circuit.wires);
        assert_eq!(e, Fq::as_montgomery(a * d));
    }

    #[test]
    fn test_fq_square() {
        let a = Fq::random();
        let circuit = Fq::square(Fq::wires_set(a));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, a * a);
    }

    #[test]
    fn test_fq_square_montgomery() {
        let a = Fq::random();
        let circuit = Fq::square_montgomery(Fq::wires_set_montgomery(a));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, Fq::as_montgomery(a * a));
    }

    #[test]
    fn test_fq_inverse() {
        let a = Fq::random();
        let circuit = Fq::inverse(Fq::wires_set(a));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, a.inverse().unwrap());
    }

    #[test]
    fn test_fq_inverse_montgomery() {
        let a = Fq::random();
        let circuit = Fq::inverse_montgomery(Fq::wires_set_montgomery(a));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }
        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c, Fq::as_montgomery(a.inverse().unwrap()));
    }

    #[test]
    fn test_fq_div6() {
        let a = Fq::random();
        let circuit = Fq::div6(Fq::wires_set(a));
        circuit.circuit_metricss().print();
        for mut gate in circuit.gates() {
            gate.evaluate();
        }

        let c = Fq::from_wires(circuit.wires);
        assert_eq!(c + c + c + c + c + c, a);
    }
}
