use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use ark_ff::{Field, PrimeField, UniformRand};
use bitvec::vec::BitVec;
use num_bigint::BigUint;
use rand::{Rng, rng};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

use super::super::bn254::fp254impl::Fp254Impl;
use crate::{
    Circuit, WireId,
    core::wire,
    gadgets::{
        self,
        bigint::{self, BigIntWires, Error},
    },
};

/// BN254 scalar field Fr implementation
#[derive(Clone)]
pub struct Fr(pub BigIntWires);

impl Deref for Fr {
    type Target = BigIntWires;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Fr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

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
    pub fn random(rng: &mut impl Rng) -> ark_bn254::Fr {
        let mut prng = ChaCha20Rng::seed_from_u64(rng.random());
        ark_bn254::Fr::rand(&mut prng)
    }

    pub fn new_constant(circuit: &mut Circuit, u: &ark_bn254::Fr) -> Result<Fr, Error> {
        Ok(Fr(BigIntWires::new_constant(
            circuit,
            Self::N_BITS,
            &BigUint::from(u.into_bigint()),
        )?))
    }

    /// Create new field element wires
    pub fn new(circuit: &mut Circuit, is_input: bool, is_output: bool) -> Fr {
        Fr(BigIntWires::new(circuit, Self::N_BITS, is_input, is_output))
    }

    pub fn get_wire_bits_fn(
        wires: &Fr,
        value: &ark_bn254::Fr,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, gadgets::bigint::Error> {
        wires
            .0
            .get_wire_bits_fn(&BigUint::from(value.into_bigint()))
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

    pub fn wires(circuit: &mut Circuit) -> Fr {
        Fr(BigIntWires::new(circuit, Self::N_BITS, false, false))
    }

    // Field arithmetic methods (wrapping the Fp254Impl trait methods)
    pub fn add(circuit: &mut impl crate::CircuitContext, a: &Fr, b: &Fr) -> Fr {
        Fr(Self::add_bigint(circuit, &a.0, &b.0))
    }

    pub fn add_constant(circuit: &mut impl crate::CircuitContext, a: &Fr, b: &ark_bn254::Fr) -> Fr {
        Fr(Self::add_constant_bigint(circuit, &a.0, b))
    }

    pub fn sub(circuit: &mut impl crate::CircuitContext, a: &Fr, b: &Fr) -> Fr {
        Fr(Self::sub_bigint(circuit, &a.0, &b.0))
    }

    pub fn neg(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(Self::neg_bigint(circuit, &a.0))
    }

    pub fn double(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(Self::double_bigint(circuit, &a.0))
    }

    pub fn half(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(Self::half_bigint(circuit, &a.0))
    }

    pub fn triple(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(Self::triple_bigint(circuit, &a.0))
    }

    pub fn div6(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(Self::div6_bigint(circuit, &a.0))
    }

    pub fn inverse(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(Self::inverse_bigint(circuit, &a.0))
    }

    pub fn mul_montgomery(circuit: &mut impl crate::CircuitContext, a: &Fr, b: &Fr) -> Fr {
        Fr(Self::mul_montgomery_bigint(circuit, &a.0, &b.0))
    }

    pub fn mul_by_constant_montgomery(
        circuit: &mut impl crate::CircuitContext,
        a: &Fr,
        b: &ark_bn254::Fr,
    ) -> Fr {
        Fr(Self::mul_by_constant_montgomery_bigint(circuit, &a.0, b))
    }

    pub fn square_montgomery(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(Self::square_montgomery_bigint(circuit, &a.0))
    }

    pub fn montgomery_reduce(circuit: &mut impl crate::CircuitContext, x: &BigIntWires) -> Fr {
        Fr(Self::montgomery_reduce_bigint(circuit, x))
    }

    pub fn inverse_montgomery(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(Self::inverse_montgomery_bigint(circuit, &a.0))
    }

    pub fn exp_by_constant_montgomery(
        circuit: &mut impl crate::CircuitContext,
        a: &Fr,
        exp: &BigUint,
    ) -> Fr {
        Fr(Self::exp_by_constant_montgomery_bigint(circuit, &a.0, exp))
    }

    pub fn multiplexer(
        circuit: &mut impl crate::CircuitContext,
        a: &[Fr],
        s: &[WireId],
        w: usize,
    ) -> Fr {
        let bigint_array: Vec<BigIntWires> = a.iter().map(|fr| fr.0.clone()).collect();
        Fr(Self::multiplexer_bigint(circuit, &bigint_array, s, w))
    }

    pub fn equal_constant(
        circuit: &mut impl crate::CircuitContext,
        a: &Fr,
        b: &ark_bn254::Fr,
    ) -> WireId {
        Self::equal_constant_bigint(circuit, &a.0, b)
    }

    // Low-level methods that work with BigIntWires directly (for backward compatibility)

    /// Field addition: (a + b) mod p (low-level API)
    pub fn add_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &BigIntWires,
        b: &BigIntWires,
    ) -> BigIntWires {
        <Self as Fp254Impl>::add(circuit, a, b)
    }

    /// Field addition with constant: (a + b) mod p (low-level API)
    pub fn add_constant_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &BigIntWires,
        b: &ark_bn254::Fr,
    ) -> BigIntWires {
        bigint::add_constant(circuit, a, &BigUint::from(b.into_bigint()))
    }

    /// Field subtraction: (a - b) mod p (low-level API)
    pub fn sub_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &BigIntWires,
        b: &BigIntWires,
    ) -> BigIntWires {
        <Self as Fp254Impl>::sub(circuit, a, b)
    }

    /// Field negation: (-a) mod p (low-level API)
    pub fn neg_bigint(circuit: &mut impl crate::CircuitContext, a: &BigIntWires) -> BigIntWires {
        <Self as Fp254Impl>::neg(circuit, a)
    }

    /// Field doubling: (2 * a) mod p (low-level API)
    pub fn double_bigint(circuit: &mut impl crate::CircuitContext, a: &BigIntWires) -> BigIntWires {
        <Self as Fp254Impl>::double(circuit, a)
    }

    /// Field halving: (a / 2) mod p (low-level API)
    pub fn half_bigint(circuit: &mut impl crate::CircuitContext, a: &BigIntWires) -> BigIntWires {
        <Self as Fp254Impl>::half(circuit, a)
    }

    /// Field tripling: (3 * a) mod p (low-level API)
    pub fn triple_bigint(circuit: &mut impl crate::CircuitContext, a: &BigIntWires) -> BigIntWires {
        <Self as Fp254Impl>::triple(circuit, a)
    }

    /// Field division by 6: (a / 6) mod p (low-level API)
    pub fn div6_bigint(circuit: &mut impl crate::CircuitContext, a: &BigIntWires) -> BigIntWires {
        <Self as Fp254Impl>::div6(circuit, a)
    }

    /// Modular inverse using extended Euclidean algorithm (low-level API)
    pub fn inverse_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &BigIntWires,
    ) -> BigIntWires {
        <Self as Fp254Impl>::inverse(circuit, a)
    }

    /// Montgomery multiplication for circuit wires (low-level API)
    pub fn mul_montgomery_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &BigIntWires,
        b: &BigIntWires,
    ) -> BigIntWires {
        <Self as Fp254Impl>::mul_montgomery(circuit, a, b)
    }

    /// Montgomery multiplication by constant (low-level API)
    pub fn mul_by_constant_montgomery_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &BigIntWires,
        b: &ark_bn254::Fr,
    ) -> BigIntWires {
        let b_mont = Self::as_montgomery(*b);
        let b_wires =
            BigIntWires::new_constant(circuit, Self::N_BITS, &BigUint::from(b_mont.into_bigint()))
                .unwrap();
        <Self as Fp254Impl>::mul_montgomery(circuit, a, &b_wires)
    }

    /// Montgomery squaring for circuit wires (low-level API)
    pub fn square_montgomery_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &BigIntWires,
    ) -> BigIntWires {
        <Self as Fp254Impl>::square_montgomery(circuit, a)
    }

    /// Montgomery reduction for circuit wires (low-level API)
    pub fn montgomery_reduce_bigint(
        circuit: &mut impl crate::CircuitContext,
        x: &BigIntWires,
    ) -> BigIntWires {
        <Self as Fp254Impl>::montgomery_reduce(circuit, x)
    }

    /// Modular inverse in Montgomery form for circuit wires (low-level API)
    pub fn inverse_montgomery_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &BigIntWires,
    ) -> BigIntWires {
        <Self as Fp254Impl>::inverse_montgomery(circuit, a)
    }

    /// Exponentiation by constant in Montgomery form (low-level API)
    pub fn exp_by_constant_montgomery_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &BigIntWires,
        exp: &BigUint,
    ) -> BigIntWires {
        <Self as Fp254Impl>::exp_by_constant_montgomery(circuit, a, exp)
    }

    /// Multiplexer for field elements (low-level API)
    pub fn multiplexer_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &[BigIntWires],
        s: &[WireId],
        w: usize,
    ) -> BigIntWires {
        <Self as Fp254Impl>::multiplexer(circuit, a, s, w)
    }

    /// Check if two field elements are equal (low-level API)
    pub fn equal_constant_bigint(
        circuit: &mut impl crate::CircuitContext,
        a: &BigIntWires,
        b: &ark_bn254::Fr,
    ) -> WireId {
        bigint::equal_constant(circuit, a, &BigUint::from(b.into_bigint()))
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
