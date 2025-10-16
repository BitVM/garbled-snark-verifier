use std::array;

use crate::{
    S,
    circuit::MultiCiphertextHandler,
    hashers::aes_ni::{aes128_encrypt_block_static, aes128_encrypt_blocks_static_xor_masks},
};

// It can be any, we use it to use AES as a hash.
pub struct AESAccumulatingHash {
    running_hash: S,
}

impl Default for AESAccumulatingHash {
    fn default() -> Self {
        Self {
            running_hash: S::ZERO,
        }
    }
}

impl AESAccumulatingHash {
    pub fn digest(input: S) -> [u8; 16] {
        let mut h = Self::default();
        h.update(input);
        h.finalize()
    }

    pub fn update(&mut self, ciphertext: S) {
        // Use the static pre-expanded AES key to avoid per-call key schedule cost.
        self.running_hash = S::from_bytes(
            aes128_encrypt_block_static((self.running_hash ^ &ciphertext).to_bytes())
                .expect("AES backend should be available (HW or software)"),
        );
    }

    pub fn finalize(&self) -> [u8; 16] {
        self.running_hash.to_bytes()
    }
}

pub struct AESAccumulatingHashBatch<const N: usize> {
    running_hashes: [[u8; 16]; N],
}

impl<const N: usize> Default for AESAccumulatingHashBatch<N> {
    fn default() -> Self {
        Self {
            running_hashes: [[0u8; 16]; N],
        }
    }
}

pub struct AESHashBatchResult<const N: usize>(pub [[u8; 16]; N]);

impl<const N: usize> Default for AESHashBatchResult<N> {
    fn default() -> Self {
        AESHashBatchResult([[0u8; 16]; N])
    }
}

impl<const N: usize> IntoIterator for AESHashBatchResult<N> {
    type Item = [u8; 16];
    type IntoIter = std::array::IntoIter<[u8; 16], N>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<const N: usize> MultiCiphertextHandler<N> for AESAccumulatingHashBatch<N> {
    type Result = AESHashBatchResult<N>;

    fn handle(&mut self, cts: [S; N]) {
        let blocks: [[u8; 16]; N] = array::from_fn(|i| cts[i].to_u128().to_le_bytes());
        let masks: [[u8; 16]; N] = self.running_hashes;
        let out = aes128_encrypt_blocks_static_xor_masks::<N>(blocks, masks)
            .expect("AES backend should be available (HW or software)");
        self.running_hashes = out;
    }

    fn finalize(self) -> Self::Result {
        AESHashBatchResult(self.running_hashes)
    }
}
