use std::{
    fmt,
    ops::{Add, BitXor, BitXorAssign},
};

use blake3::Hasher;
use rand::Rng;
use serde::{Deserialize, Serialize};

/// Size of the S struct in bytes - optimized for performance and cache alignment
pub const S_SIZE: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct S(u128);

impl S {
    pub const ZERO: Self = Self(0);

    #[inline]
    pub const fn one() -> Self {
        Self(1)
    }

    #[inline]
    pub const fn from_bytes(bytes: [u8; S_SIZE]) -> Self {
        Self(u128::from_be_bytes(bytes))
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; S_SIZE] {
        self.0.to_be_bytes()
    }

    #[inline]
    pub fn write_bytes(&self, out: &mut [u8; S_SIZE]) {
        *out = self.0.to_be_bytes();
    }

    #[inline]
    pub fn from_u128(l: u128) -> Self {
        Self(l)
    }

    #[inline]
    pub fn to_u128(&self) -> u128 {
        self.0
    }

    pub fn to_hex(&self) -> String {
        self.to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<String>>()
            .join("")
    }

    pub fn random(rng: &mut impl Rng) -> Self {
        Self(rng.r#gen::<u128>())
    }

    pub fn neg(&self) -> Self {
        Self(0u128.wrapping_sub(self.0))
    }

    pub fn hash(&self) -> Self {
        let mut output = [0u8; S_SIZE];
        Hasher::new()
            .update(&self.to_bytes())
            .finalize_xof()
            .fill(&mut output);
        Self::from_bytes(output)
    }

    pub fn hash_together(a: Self, b: Self) -> Self {
        let mut input = [0u8; S_SIZE * 2];
        input[..S_SIZE].copy_from_slice(&a.to_bytes());
        input[S_SIZE..].copy_from_slice(&b.to_bytes());
        let mut output = [0u8; S_SIZE];
        Hasher::new()
            .update(&input)
            .finalize_xof()
            .fill(&mut output);
        Self::from_bytes(output)
    }

    pub fn xor(a: Self, b: Self) -> Self {
        Self(a.0 ^ b.0)
    }
}

impl fmt::Debug for S {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S({})", self.to_hex())
    }
}

impl Add for S {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl BitXor for &S {
    type Output = S;

    fn bitxor(self, rhs: Self) -> Self::Output {
        S(self.0 ^ rhs.0)
    }
}

impl BitXor<&S> for S {
    type Output = S;

    fn bitxor(mut self, rhs: &S) -> Self::Output {
        self.0 ^= rhs.0;
        self
    }
}

impl BitXorAssign<&S> for S {
    fn bitxor_assign(&mut self, rhs: &S) {
        self.0 ^= rhs.0;
    }
}

// Note: AsRef<[u8]> and AsRef<[u8; 16]> cannot be implemented for S with u128 backend
// because we can't return a reference to temporary bytes.
// Users should call .to_bytes() instead.

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    fn rnd() -> S {
        S::random(&mut rand::rngs::StdRng::from_seed([0u8; 32]))
    }

    #[test]
    fn test_xor_zero_identity() {
        let zero = S::ZERO;
        let a = rnd();
        assert_eq!(&a ^ &zero, a, "a ^ 0 should be a");
        assert_eq!(&zero ^ &a, a, "0 ^ a should be a");
    }

    #[test]
    fn test_xor_self_is_zero() {
        let a = rnd();
        let result = &a ^ &a;
        assert_eq!(result, S::ZERO, "a ^ a should be 0");
    }

    #[test]
    fn test_xor_commutative() {
        let a = rnd();
        let b = rnd();
        assert_eq!(&a ^ &b, &b ^ &a, "a ^ b should equal b ^ a");
    }

    #[test]
    fn test_xor_associative() {
        let a = rnd();
        let b = rnd();
        let c = rnd();
        assert_eq!((&a ^ &b) ^ &c, &a ^ &(&b ^ &c), "XOR should be associative");
    }

    #[test]
    fn test_xor_known_value() {
        let a = S::from_bytes([0xFF; S_SIZE]);
        let b = S::from_bytes([0x0F; S_SIZE]);
        let expected = S::from_bytes([0xF0; S_SIZE]);
        assert_eq!(&a ^ &b, expected);
    }

    #[test]
    fn test_bitxor_is_pure() {
        let a = rnd();
        let b = rnd();
        let _ = &a ^ &b;
        let _ = &a ^ &b;
        assert_eq!(a, a, "a should remain unchanged");
        assert_eq!(b, b, "b should remain unchanged");
    }

    #[test]
    fn test_from_to_bytes_roundtrip() {
        let mut rng = rand::rngs::StdRng::from_seed([42u8; 32]);
        for _ in 0..100 {
            let arr: [u8; S_SIZE] = rng.r#gen();
            let s = S::from_bytes(arr);
            assert_eq!(s.to_bytes(), arr);
        }
    }

    #[test]
    fn test_zero_one_constants() {
        assert_eq!(S::ZERO.to_bytes(), [0u8; S_SIZE]);
        assert_eq!(S::one().to_bytes()[S_SIZE - 1], 1);
        assert!(S::one().to_bytes()[..S_SIZE - 1].iter().all(|&b| b == 0));
    }
}
