use crate::{S, core::gate::garbling::aes_ni::aes128_encrypt_block};

// It can be any, we use it to use AES as a hash.
const MAGIC_CONST: [u8; 16] = [0x42; 16];

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
        self.running_hash = S::from_bytes(
            aes128_encrypt_block(MAGIC_CONST, (self.running_hash ^ &ciphertext).to_bytes())
                .expect("AES-NI should be available"),
        );
    }

    pub fn finalize(self) -> u128 {
        self.running_hash.to_u128()
    }
}
