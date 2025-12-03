//! Gate hashers used by garbling/degabbling, moved to crate root.
//! These mirror the previous implementations under core::gate::garbling::hashers
//! without functional changes.

use std::fmt::Debug;

use rand::Rng;
use serde::{Serialize, de::DeserializeOwned};

use crate::{S, core::s::S_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HasherKind {
    Blake3,
    Aes,
}

pub mod aes_ni;
pub mod sha256;

// Re-export label commit hashers and trait for public API
pub use sha256::{
    AesLabelCommitHasher, Commit, DefaultLabelCommitHasher, LabelCommitHasher,
    Sha256LabelCommitHasher, commit_label_with,
};

/// Trait for gate hashers used in garbling/degarbling.
///
/// Each hasher may have associated seed data.
/// Stateless hashers use `Seed = ()`.
pub trait GateHasher: HashWithGate<1> + HashWithGate<2> + Clone + Debug + Send + Sync {
    /// Data needed to reconstruct this hasher. `()` for stateless hashers, `S` for SwankyAes.
    type Seed: Clone + Debug + PartialEq + Eq + Serialize + DeserializeOwned + Send + Sync;

    /// Create hasher from RNG (used during garbling)
    fn from_rng<R: Rng>(rng: &mut R) -> Self;

    /// Reconstruct hasher from seed (used during evaluation)
    fn from_seed(seed: Self::Seed) -> Self;

    /// Get seed from hasher (no separate storage needed)
    fn seed(&self) -> &Self::Seed;
}

pub trait HashWithGate<const N: usize>: Clone + Send + Sync {
    fn hash_with_gate(&self, labels: &[S; N], gate_id: usize) -> [S; N];
}

#[derive(Clone, Debug, Default)]
pub struct Blake3Hasher;

impl HashWithGate<2> for Blake3Hasher {
    fn hash_with_gate(&self, labels: &[S; 2], gate_id: usize) -> [S; 2] {
        let [selected_label, other_label] = labels;

        let [h_selected] = self.hash_with_gate(&[*selected_label], gate_id);
        let [h_other] = self.hash_with_gate(&[*other_label], gate_id);

        [h_selected, h_other]
    }
}

impl HashWithGate<1> for Blake3Hasher {
    fn hash_with_gate(&self, label: &[S; 1], gate_id: usize) -> [S; 1] {
        let mut result = [0u8; S_SIZE];
        let mut hasher = blake3::Hasher::new();

        let b = label[0].to_bytes();

        hasher.update(&b);
        hasher.update(&gate_id.to_le_bytes());

        let hash = hasher.finalize();
        result.copy_from_slice(&hash.as_bytes()[0..S_SIZE]);

        [S::from_bytes(result)]
    }
}

impl GateHasher for Blake3Hasher {
    type Seed = ();

    fn from_rng<R: Rng>(_rng: &mut R) -> Self {
        Self
    }

    fn from_seed(_seed: Self::Seed) -> Self {
        Self
    }

    fn seed(&self) -> &Self::Seed {
        &()
    }
}

/// Single-AES hasher
/// 1-AES circular correlation-robust hash from Guo–Katz–Wang–Yu (ePrint 2019/074, Section 7.3, Theorem 5) combined with
/// the half-gates salt construction from their Section 5 / Theorem 3:
///
/// `H_S(label, tweak) = AES_K(perm(S ⊕ label ⊕ tweak)) ⊕ perm(S ⊕ label ⊕ tweak)`
///
/// where `perm(x_L || x_R) = (x_L ⊕ x_R) || x_L`. The salt `S` is public and
/// must be set once via [`set_garbling_salt`] before hashing.
#[derive(Clone, Debug)]
pub struct AesCcrGateHasher {
    pub salt: S,
}

/// Linear orthomorphism σ from Section 7.3:
/// `σ(x_L || x_R) = (x_L ⊕ x_R) || x_L`.
#[inline]
fn perm_u128(x: S) -> S {
    let x = x.to_u128();
    let x_l = x as u64;
    let x_r = (x >> 64) as u64;

    let y_l = x_l ^ x_r;
    let y_r = x_l;

    S::from_u128((y_l as u128) | ((y_r as u128) << 64))
}

#[inline]
fn hash_label_with_gate(salt: S, label: S, gate_id: usize) -> S {
    let tweak = S::from_u128(gate_id as u128);

    let x0 = label ^ &tweak ^ &salt;

    let p = perm_u128(x0);

    let c = aes_ni::aes128_encrypt_block_static(p.to_le_bytes()).expect("AES backend unavailable");

    S::from_le_bytes(c) ^ &p
}

impl HashWithGate<2> for AesCcrGateHasher {
    #[inline(always)]
    fn hash_with_gate(&self, labels: &[S; 2], gate_id: usize) -> [S; 2] {
        let tweak = S::from_u128(gate_id as u128);

        let x0 = labels[0] ^ &tweak ^ &self.salt;
        let x1 = labels[1] ^ &tweak ^ &self.salt;

        let p0 = perm_u128(x0);
        let p1 = perm_u128(x1);

        let (c0, c1) = aes_ni::aes128_encrypt2_blocks_static(p0.to_le_bytes(), p1.to_le_bytes())
            .expect("AES backend unavailable");

        let h0 = S::from_le_bytes(c0) ^ &p0;
        let h1 = S::from_le_bytes(c1) ^ &p1;

        [h0, h1]
    }
}

impl HashWithGate<1> for AesCcrGateHasher {
    #[inline(always)]
    fn hash_with_gate(&self, label: &[S; 1], gate_id: usize) -> [S; 1] {
        [hash_label_with_gate(self.salt, label[0], gate_id)]
    }
}

impl AesCcrGateHasher {
    pub fn new(salt: S) -> Self {
        Self { salt }
    }
}

impl GateHasher for AesCcrGateHasher {
    type Seed = S;

    fn from_rng<R: Rng>(rng: &mut R) -> Self {
        Self {
            salt: S::random(rng),
        }
    }

    fn from_seed(seed: Self::Seed) -> Self {
        Self { salt: seed }
    }

    fn seed(&self) -> &Self::Seed {
        &self.salt
    }
}
