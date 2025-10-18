//! Label commit hashers for the cut-and-choose protocol.

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{S, hashers};

/// Trait for hashing garbled circuit labels for commitment.
pub trait LabelCommitHasher: fmt::Debug {
    type Output: Copy
        + fmt::Debug
        + Eq
        + Send
        + Sync
        + Serialize
        + for<'de> Deserialize<'de>
        + AsRef<[u8]>;

    fn hash_label(label: S) -> Self::Output;
}

/// SHA-256 based label commit hasher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sha256LabelCommitHasher;

impl LabelCommitHasher for Sha256LabelCommitHasher {
    type Output = [u8; 32];

    fn hash_label(label: S) -> Self::Output {
        let digest = Sha256::digest(label.to_u128().to_be_bytes());
        digest.into()
    }
}

/// AES-based label commit hasher.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AesLabelCommitHasher;

impl LabelCommitHasher for AesLabelCommitHasher {
    type Output = [u8; 16];

    fn hash_label(label: S) -> Self::Output {
        hashers::aes_ni::aes128_encrypt_block_static(label.to_bytes())
            .expect("AES backend should be available (HW or software)")
    }
}

/// Helper function to commit a label using a specific hasher.
pub fn commit_label_with<H: LabelCommitHasher>(label: S) -> H::Output {
    H::hash_label(label)
}

/// Default label commit hasher type.
pub type DefaultLabelCommitHasher = AesLabelCommitHasher;
/// Default commit type.
pub type Commit = <DefaultLabelCommitHasher as LabelCommitHasher>::Output;
