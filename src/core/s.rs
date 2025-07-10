use blake3::hash;
use rand::{Rng, rng};
use std::{iter::zip, ops::Add};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct S(pub [u8; 32]);

impl S {
    pub const fn one() -> Self {
        let mut s = [0_u8; 32];
        s[31] = 1;
        Self(s)
    }

    pub fn random() -> Self {
        Self(rng().random::<[u8; 32]>())
    }

    pub fn neg(&self) -> Self {
        let mut s = self.0;
        for (i, si) in s.iter_mut().enumerate() {
            *si = 255 - self.0[i];
        }
        Self(s) + Self::one()
    }

    pub fn hash(&self) -> Self {
        Self(*hash(&self.0).as_bytes())
    }

    pub fn hash_together(a: Self, b: Self) -> Self {
        let mut h = a.0.to_vec();
        h.extend(b.0.to_vec());
        Self(*hash(&h).as_bytes())
    }

    pub fn xor(mut a: Self, b: Self) -> Self {
        for i in 0..32 {
            a.0[i] ^= b.0[i];
        }
        a
    }
}

impl Add for S {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut s = [0_u8; 32];
        let mut carry = 0;
        for (i, (u, v)) in zip(self.0, rhs.0).enumerate().rev() {
            let x = (u as u32) + (v as u32) + carry;
            s[i] = (x % 256) as u8;
            carry = x / 256;
        }
        Self(s)
    }
}
