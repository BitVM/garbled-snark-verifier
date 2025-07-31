use std::ops::Deref;

use rand::Rng;

use crate::S;

/// A wrapper type for the global Free-XOR delta `Δ`.
///
/// This wrapper provides semantic clarity and ensures proper handling
/// of the delta value in garbled circuits. The delta is used in the
/// Free-XOR technique where `label1 = label0 ⊕ Δ`.
///
/// Use [`Delta::generate(rng)`] to obtain a valid instance.
///
/// # Security Note
/// The delta value must be kept secret during garbling and must not leak
/// to the evaluator. Proper wrapper usage helps prevent accidental exposure.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Delta(S);

impl Delta {
    /// Generates a new delta using the provided RNG.
    ///
    /// This ensures the delta generation is part of the single source of truth
    /// for randomness in the garbling process.
    pub fn generate(rng: &mut impl Rng) -> Self {
        Self(S::random(rng))
    }
}

impl Deref for Delta {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
