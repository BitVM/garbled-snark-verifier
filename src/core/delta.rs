use std::ops::Deref;

use rand::{rng, Rng};

use crate::S;

/// A wrapper type for the global Free-XOR delta `Δ`,
/// ensuring that its permutation bit (LSB of the last byte) is always `1`.
///
/// This is **required** for compatibility with point-and-permute:
/// when computing `label1 = label0 ⊕ Δ`, the resulting labels must differ
/// in their permutation bit so that the evaluator can use it to select
/// the correct entry in the garbled table.
///
/// Use [`Delta::generate()`] to obtain a valid instance.
///
/// # Invariant
/// ```text
/// delta.0[31] & 1 == 1
/// ```
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Delta(S);

impl Delta {
    /// Generates a new delta with a guaranteed permutation bit of 1.
    ///
    /// This function loops internally until the generated value
    /// satisfies `delta.0[31] & 1 == 1`.
    ///
    /// This ensures that XOR-ing with delta flips the LSB of the last byte,
    /// enabling safe use of point-and-permute.
    pub fn generate() -> Self {
        let mut s = rng().random::<[u8; 32]>();
        s[31] |= 1; // set LSB of last byte
        Self(S(s))
    }
}

impl Deref for Delta {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
