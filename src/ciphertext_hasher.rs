use crate::{S, hashers::aes_ni::aes128_encrypt_block_static};

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
