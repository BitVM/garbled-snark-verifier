use ark_ff::{Field, PrimeField, UniformRand};
use num_bigint::BigUint;
use rand::{Rng, rng};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use super::Fp254Impl;
use crate::{gadgets::{self, bigint::BigIntWires}, Circuit, WireId};

pub struct Fr;

impl Fp254Impl for Fr {
    const MODULUS: &'static str =
        "21888242871839275222246405745257275088548364400416034343698204186575808495617";
    const MONTGOMERY_M_INVERSE: &'static str =
        "5441563794177615591428663161977496376097281981129373443346157590346630955009";
    const MONTGOMERY_R_INVERSE: &'static str =
        "17773755579518009376303681366703133516854333631346829854655645366227550102839";
    const N_BITS: usize = 254;

    fn half_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(1) / ark_bn254::Fr::from(2))
    }

    fn one_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(1) / ark_bn254::Fr::from(3))
    }
    fn two_third_modulus() -> BigUint {
        BigUint::from(ark_bn254::Fr::from(2) / ark_bn254::Fr::from(3))
    }
}

impl Fr {
    pub fn random() -> ark_bn254::Fr {
        let mut prng = ChaCha20Rng::seed_from_u64(rng().random());
        ark_bn254::Fr::rand(&mut prng)
    }

    /// Create new field element wires
    pub fn new_bn(circuit: &mut Circuit, is_input: bool, is_output: bool) -> BigIntWires {
        BigIntWires::new(circuit, Self::N_BITS, is_input, is_output)
    }

    pub fn get_wire_bits_fn(
        wires: &BigIntWires,
        value: &ark_bn254::Fr,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, gadgets::bigint::Error> {
        wires.get_wire_bits_fn(&BigUint::from(value.into_bigint()))
    }

    pub fn as_montgomery(a: ark_bn254::Fr) -> ark_bn254::Fr {
        a * ark_bn254::Fr::from(Self::montgomery_r_as_biguint())
    }

    pub fn from_montgomery(a: ark_bn254::Fr) -> ark_bn254::Fr {
        a / ark_bn254::Fr::from(Self::montgomery_r_as_biguint())
    }

    pub fn to_bits(u: ark_bn254::Fr) -> Vec<bool> {
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

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::Fr {
        let zero = BigUint::ZERO;
        let one = BigUint::from(1_u8);
        let mut u = zero.clone();
        for bit in bits.iter().rev() {
            u = u.clone() + u.clone() + if *bit { one.clone() } else { zero.clone() };
        }
        ark_bn254::Fr::from(u)
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;

    use super::*;
    use crate::test_utils::trng;

    fn rnd() -> ark_bn254::Fr {
        loop {
            if let Some(bn) = ark_bn254::Fr::from_random_bytes(&trng().random::<[u8; 32]>()) {
                return bn;
            }
        }
    }

    #[test]
    fn test_fr_random() {
        let u = rnd();
        println!("u: {u:?}");
        let b = Fr::to_bits(u);
        let v = Fr::from_bits(b);
        println!("v: {v:?}");
        assert_eq!(u, v);
    }
}
