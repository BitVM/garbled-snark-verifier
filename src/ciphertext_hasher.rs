use crossbeam::channel::Receiver;

use crate::{
    S,
    core::gate::garbling::aes_ni::{aes128_encrypt_block, aes128_encrypt8_blocks},
};

fn xor_arrays(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

fn xor_u128_with_bytes(running_hash: &[u8; 16], ciphertext: S) -> [u8; 16] {
    // Convert running_hash to u128 for fast XOR, then back to bytes
    let hash_u128 = u128::from_be_bytes(*running_hash);
    let result_u128 = hash_u128 ^ ciphertext.to_u128(); // Fast u128 XOR!
    result_u128.to_be_bytes()
}

fn xor_8_arrays(arrays: &[[u8; 16]; 8]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for array in arrays {
        for i in 0..16 {
            result[i] ^= array[i];
        }
    }
    result
}

pub enum CiphertextHasher {
    Sequential {
        running_hash: [u8; 16],
        key: [u8; 16],
    },
    Batched {
        batch_buffer: Vec<S>,
        running_hash: [u8; 16],
        key1: [u8; 16],
        key2: [u8; 16],
    },
}

impl CiphertextHasher {
    pub fn new_sequential() -> Self {
        Self::Sequential {
            running_hash: [0u8; 16],
            key: [0x42u8; 16],
        }
    }

    pub fn new_batched() -> Self {
        Self::Batched {
            batch_buffer: Vec::with_capacity(8),
            running_hash: [0u8; 16],
            key1: [0x42u8; 16],
            key2: [0x24u8; 16],
        }
    }

    pub fn run(mut self, receiver: Receiver<(usize, S)>) -> [u8; 16] {
        match &mut self {
            CiphertextHasher::Sequential { running_hash, key } => {
                while let Ok((_, ciphertext)) = receiver.recv() {
                    let input = xor_u128_with_bytes(running_hash, ciphertext);
                    *running_hash =
                        aes128_encrypt_block(*key, input).expect("AES-NI should be available");
                }
                *running_hash
            }
            CiphertextHasher::Batched {
                batch_buffer,
                running_hash,
                key1,
                key2,
            } => {
                while let Ok((_, ciphertext)) = receiver.recv() {
                    batch_buffer.push(ciphertext);

                    if batch_buffer.len() == 8 {
                        let blocks = (
                            batch_buffer[0].to_bytes(),
                            batch_buffer[1].to_bytes(),
                            batch_buffer[2].to_bytes(),
                            batch_buffer[3].to_bytes(),
                            batch_buffer[4].to_bytes(),
                            batch_buffer[5].to_bytes(),
                            batch_buffer[6].to_bytes(),
                            batch_buffer[7].to_bytes(),
                        );
                        let (h0, h1, h2, h3, h4, h5, h6, h7) =
                            aes128_encrypt8_blocks(*key1, blocks)
                                .expect("AES-NI should be available");

                        let xor_result = xor_8_arrays(&[h0, h1, h2, h3, h4, h5, h6, h7]);
                        let batch_hash = aes128_encrypt_block(*key2, xor_result)
                            .expect("AES-NI should be available");

                        let combined = xor_arrays(running_hash, &batch_hash);
                        *running_hash = aes128_encrypt_block(*key1, combined)
                            .expect("AES-NI should be available");

                        batch_buffer.clear();
                    }
                }

                for remaining_ciphertext in batch_buffer {
                    let input = xor_u128_with_bytes(running_hash, *remaining_ciphertext);
                    *running_hash =
                        aes128_encrypt_block(*key1, input).expect("AES-NI should be available");
                }

                *running_hash
            }
        }
    }
}
