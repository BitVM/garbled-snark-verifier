use crate::{S, core::gate::garbling::aes_ni::aes128_encrypt_block_static};

// It can be any, we use it to use AES as a hash.
pub struct CiphertextHashAcc {
    running_hash: S,
}

impl Default for CiphertextHashAcc {
    fn default() -> Self {
        Self {
            running_hash: S::ZERO,
        }
    }
}

impl CiphertextHashAcc {
    pub fn update(&mut self, ciphertext: S) {
        // Use the static pre-expanded AES key to avoid per-call key schedule cost.
        self.running_hash = S::from_bytes(
            aes128_encrypt_block_static((self.running_hash ^ &ciphertext).to_bytes())
                .expect("AES backend should be available (HW or software)"),
        );
    }

    pub fn finalize(self) -> u128 {
        self.running_hash.to_u128()
    }
}
