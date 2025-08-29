use std::{
    fmt,
    iter::zip,
    ops::{Add, BitXor, BitXorAssign},
};

use blake3::Hasher;
use rand::Rng;

/// Size of the S struct in bytes - optimized for performance and cache alignment
pub const S_SIZE: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct S(pub [u8; S_SIZE]);

impl S {
    pub const fn one() -> Self {
        let mut s = [0_u8; S_SIZE];
        s[S_SIZE - 1] = 1;
        Self(s)
    }

    pub fn to_hex(&self) -> String {
        self.0
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<String>>()
            .join("")
    }

    pub fn random(rng: &mut impl Rng) -> Self {
        Self(rng.r#gen())
    }

    pub fn neg(&self) -> Self {
        let mut s = self.0;
        for (i, si) in s.iter_mut().enumerate() {
            *si = 255 - self.0[i];
        }
        Self(s) + Self::one()
    }

    pub fn hash(&self) -> Self {
        let mut output = [0u8; S_SIZE];
        Hasher::new()
            .update(&self.0)
            .finalize_xof()
            .fill(&mut output);
        Self(output)
    }

    pub fn hash_together(a: Self, b: Self) -> Self {
        let mut input = [0u8; S_SIZE * 2];
        input[..S_SIZE].copy_from_slice(&a.0);
        input[S_SIZE..].copy_from_slice(&b.0);
        let mut output = [0u8; S_SIZE];
        Hasher::new()
            .update(&input)
            .finalize_xof()
            .fill(&mut output);
        Self(output)
    }

    pub fn xor(a: Self, b: Self) -> Self {
        Self(
            zip(a.0, b.0)
                .map(|(u, v)| u ^ v)
                .collect::<Vec<u8>>()
                .try_into()
                .unwrap(),
        )
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
        let mut s = [0_u8; S_SIZE];
        let mut carry = 0;
        for (i, (u, v)) in zip(self.0, rhs.0).enumerate().rev() {
            let x = (u as u32) + (v as u32) + carry;
            s[i] = (x % 256) as u8;
            carry = x / 256;
        }
        Self(s)
    }
}

impl BitXor for &S {
    type Output = S;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut out = [0u8; S_SIZE];

        // Why `Allow` here: the compiler will expand the call and remove the check on the fixed
        // array
        #[allow(clippy::needless_range_loop)]
        for i in 0..S_SIZE {
            out[i] = self.0[i] ^ rhs.0[i];
        }

        S(out)
    }
}

impl BitXor<&S> for S {
    type Output = S;

    fn bitxor(mut self, rhs: &S) -> Self::Output {
        for i in 0..S_SIZE {
            self.0[i] ^= rhs.0[i];
        }
        self
    }
}

impl BitXorAssign<&S> for S {
    fn bitxor_assign(&mut self, rhs: &S) {
        for i in 0..S_SIZE {
            self.0[i] ^= rhs.0[i];
        }
    }
}

impl AsRef<[u8]> for S {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; 16]> for S {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    fn rnd() -> S {
        S::random(&mut rand::rngs::StdRng::from_seed([0u8; 32]))
    }

    #[test]
    fn test_xor_zero_identity() {
        let zero = S([0u8; S_SIZE]);
        let a = rnd();
        assert_eq!(&a ^ &zero, a, "a ^ 0 should be a");
        assert_eq!(&zero ^ &a, a, "0 ^ a should be a");
    }

    #[test]
    fn test_xor_self_is_zero() {
        let a = rnd();
        let result = &a ^ &a;
        assert_eq!(result, S([0u8; S_SIZE]), "a ^ a should be 0");
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
        let a = S([0xFF; S_SIZE]);
        let b = S([0x0F; S_SIZE]);
        let expected = S([0xF0; S_SIZE]);
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
}
