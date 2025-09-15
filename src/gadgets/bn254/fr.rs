//! BN254 Scalar Field Fr Implementation
//!
//! This module provides circuit-based operations on the BN254 scalar field Fr.
//! The scalar field Fr is used for exponents in elliptic curve operations and
//! has the modulus: 21888242871839275222246405745257275088548364400416034343698204186575808495617
//!
//! The Fr type wraps BigIntWires to provide field-specific operations in Montgomery form
//! for efficient modular arithmetic within garbled circuits.

use std::ops::{Deref, DerefMut};

use ark_ff::PrimeField;
use num_bigint::BigUint;

use super::super::bn254::fp254impl::Fp254Impl;
use crate::{
    CircuitContext, WireId,
    circuit::WiresObject,
    gadgets::{
        self,
        bigint::{self, BigIntWires, Error},
    },
};

/// BN254 scalar field Fr implementation
///
/// Represents elements in the scalar field Fr of the BN254 elliptic curve.
/// This is the field used for private keys and exponents in BN254 operations.
#[derive(Clone, Debug)]
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

impl WiresObject for Fr {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0.iter().copied().collect()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        Self(self.0.clone_from(wire_gen))
    }
}

impl crate::circuit::FromWires for Fr {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        Some(Self(crate::gadgets::bigint::BigIntWires::from_bits(
            wires.iter().copied(),
        )))
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
    /// Create constant field element wires from a known value
    ///
    /// # Arguments
    /// * `circuit` - Circuit to add wires to
    /// * `u` - Field element value to encode as constant
    ///
    /// # Returns
    /// Field element wires representing the constant value
    pub fn new_constant(u: &ark_bn254::Fr) -> Result<Fr, Error> {
        Ok(Fr(BigIntWires::new_constant(
            Self::N_BITS,
            &BigUint::from(u.into_bigint()),
        )?))
    }

    pub fn from_ctx<C: CircuitContext>(circuit: &mut C) -> Fr {
        Fr(BigIntWires::from_ctx(circuit, Self::N_BITS))
    }

    pub fn new(issue: impl FnMut() -> WireId) -> Fr {
        Fr(BigIntWires::new(issue, Self::N_BITS))
    }

    pub fn get_wire_bits_fn(
        wires: &Fr,
        value: &ark_bn254::Fr,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, gadgets::bigint::Error> {
        wires
            .0
            .get_wire_bits_fn(&BigUint::from(value.into_bigint()))
    }

    /// Convert field element wires to a bitmask string for debugging
    ///
    /// # Arguments
    /// * `wires` - The field element wires
    /// * `get_val` - Function to get the boolean value of a wire
    ///
    /// # Returns
    /// String representation of the field element as bits
    pub fn to_bitmask(wires: &Fr, get_val: impl Fn(WireId) -> bool) -> String {
        wires.0.to_bitmask(&get_val)
    }

    /// Convert a field element to Montgomery form
    ///
    /// Montgomery form represents a field element `a` as `a * R mod p` where R = 2^254.
    /// This form enables efficient modular multiplication using Montgomery reduction.
    ///
    /// # Arguments
    /// * `a` - Field element in standard form
    ///
    /// # Returns
    /// Field element in Montgomery form (a * R mod p)
    pub fn as_montgomery(a: ark_bn254::Fr) -> ark_bn254::Fr {
        a * ark_bn254::Fr::from(Self::montgomery_r_as_biguint())
    }

    /// Convert a field element from Montgomery form back to standard form
    ///
    /// # Arguments
    /// * `a` - Field element in Montgomery form
    ///
    /// # Returns
    /// Field element in standard form (a / R mod p)
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

    // Field arithmetic methods (directly using Fp254Impl trait methods)
    pub fn add(circuit: &mut impl crate::CircuitContext, a: &Fr, b: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::add(circuit, &a.0, &b.0))
    }

    pub fn add_constant(circuit: &mut impl crate::CircuitContext, a: &Fr, b: &ark_bn254::Fr) -> Fr {
        Fr(bigint::add_constant(
            circuit,
            &a.0,
            &BigUint::from(b.into_bigint()),
        ))
    }

    pub fn sub(circuit: &mut impl crate::CircuitContext, a: &Fr, b: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::sub(circuit, &a.0, &b.0))
    }

    pub fn neg(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::neg(circuit, &a.0))
    }

    pub fn double(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::double(circuit, &a.0))
    }

    pub fn half(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::half(circuit, &a.0))
    }

    pub fn triple(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::triple(circuit, &a.0))
    }

    pub fn div6(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::div6(circuit, &a.0))
    }

    pub fn inverse(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::inverse(circuit, &a.0))
    }

    pub fn mul_montgomery(circuit: &mut impl crate::CircuitContext, a: &Fr, b: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::mul_montgomery(circuit, &a.0, &b.0))
    }

    pub fn mul_by_constant_montgomery(
        circuit: &mut impl crate::CircuitContext,
        a: &Fr,
        b: &ark_bn254::Fr,
    ) -> Fr {
        let b_mont = Self::as_montgomery(*b);
        let b_wires =
            BigIntWires::new_constant(Self::N_BITS, &BigUint::from(b_mont.into_bigint())).unwrap();
        Fr(<Self as Fp254Impl>::mul_montgomery(circuit, &a.0, &b_wires))
    }

    pub fn square_montgomery(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::square_montgomery(circuit, &a.0))
    }

    pub fn montgomery_reduce(circuit: &mut impl crate::CircuitContext, x: &BigIntWires) -> Fr {
        Fr(<Self as Fp254Impl>::montgomery_reduce(circuit, x))
    }

    pub fn inverse_montgomery(circuit: &mut impl crate::CircuitContext, a: &Fr) -> Fr {
        Fr(<Self as Fp254Impl>::inverse_montgomery(circuit, &a.0))
    }

    pub fn exp_by_constant_montgomery(
        circuit: &mut impl crate::CircuitContext,
        a: &Fr,
        exp: &BigUint,
    ) -> Fr {
        Fr(<Self as Fp254Impl>::exp_by_constant_montgomery(
            circuit, &a.0, exp,
        ))
    }

    pub fn multiplexer(
        circuit: &mut impl crate::CircuitContext,
        a: &[Fr],
        s: &[WireId],
        w: usize,
    ) -> Fr {
        let bigint_array: Vec<BigIntWires> = a.iter().map(|fr| fr.0.clone()).collect();
        Fr(<Self as Fp254Impl>::multiplexer(
            circuit,
            &bigint_array,
            s,
            w,
        ))
    }

    pub fn equal_constant(
        circuit: &mut impl crate::CircuitContext,
        a: &Fr,
        b: &ark_bn254::Fr,
    ) -> WireId {
        bigint::equal_constant(circuit, &a.0, &BigUint::from(b.into_bigint()))
    }
}

#[cfg(test)]
mod tests {
    use ark_ff::Field;
    use rand::Rng;

    use super::*;
    use crate::test_utils::trng;

    fn rnd() -> ark_bn254::Fr {
        loop {
            if let Some(bn) = ark_bn254::Fr::from_random_bytes(&trng().r#gen::<[u8; 32]>()) {
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
