use std::array;

use crate::{S, circuit::MultiCiphertextHandler};

/// Batch size for Blake3 accumulating hash (64 ciphertexts = 1KB)
pub const BATCH_SIZE: usize = 64;
/// Output hash size (full Blake3)
pub const HASH_OUTPUT_SIZE: usize = 32;
/// Batch input buffer size: 8 bytes index + 64 * 16 bytes ciphertexts
const BATCH_INPUT_SIZE: usize = 8 + BATCH_SIZE * 16;

/// Blake3-based accumulating hash optimized for high-volume ciphertext hashing.
///
/// Designed for 2.7B+ ciphertexts with zero heap allocations in hot path:
/// - Batches 64 ciphertexts (1KB) before hashing
/// - Uses batch index prefix for domain separation
/// - Sequential batch hash combination (order-dependent)
pub struct Blake3AccumulatingHash {
    buffer: [S; BATCH_SIZE],
    buffer_pos: usize,
    running_hasher: blake3::Hasher,
    batch_index: u64,
    batch_input: [u8; BATCH_INPUT_SIZE],
}

impl Default for Blake3AccumulatingHash {
    fn default() -> Self {
        Self {
            buffer: [S::ZERO; BATCH_SIZE],
            buffer_pos: 0,
            running_hasher: blake3::Hasher::new(),
            batch_index: 0,
            batch_input: [0u8; BATCH_INPUT_SIZE],
        }
    }
}

impl Blake3AccumulatingHash {
    pub fn digest(input: S) -> [u8; HASH_OUTPUT_SIZE] {
        let mut h = Self::default();
        h.update(input);
        h.finalize()
    }

    #[inline]
    pub fn update(&mut self, ciphertext: S) {
        self.buffer[self.buffer_pos] = ciphertext;
        self.buffer_pos += 1;
        if self.buffer_pos == BATCH_SIZE {
            self.flush_batch();
        }
    }

    fn flush_batch(&mut self) {
        if self.buffer_pos == 0 {
            return;
        }

        // Write batch index to pre-allocated buffer (first 8 bytes)
        self.batch_input[..8].copy_from_slice(&self.batch_index.to_le_bytes());

        // Serialize ciphertexts to pre-allocated buffer (no allocation!)
        for i in 0..self.buffer_pos {
            let start = 8 + i * 16;
            self.batch_input[start..start + 16].copy_from_slice(&self.buffer[i].to_bytes());
        }

        // Hash only the filled portion (handles partial batches)
        let filled_len = 8 + self.buffer_pos * 16;
        let batch_hash = blake3::hash(&self.batch_input[..filled_len]);

        // Feed batch hash into running hasher (order-dependent)
        self.running_hasher.update(batch_hash.as_bytes());

        // Increment batch index, reset position
        self.batch_index += 1;
        self.buffer_pos = 0;
    }

    pub fn finalize(mut self) -> [u8; HASH_OUTPUT_SIZE] {
        self.flush_batch();
        *self.running_hasher.finalize().as_bytes()
    }
}

/// Batch version for N parallel lanes, used in multigarbling mode.
pub struct Blake3AccumulatingHashBatch<const N: usize> {
    buffers: [[S; BATCH_SIZE]; N],
    buffer_positions: [usize; N],
    running_hashers: [blake3::Hasher; N],
    batch_indices: [u64; N],
    batch_inputs: [[u8; BATCH_INPUT_SIZE]; N],
}

impl<const N: usize> Default for Blake3AccumulatingHashBatch<N> {
    fn default() -> Self {
        Self {
            buffers: [[S::ZERO; BATCH_SIZE]; N],
            buffer_positions: [0; N],
            running_hashers: array::from_fn(|_| blake3::Hasher::new()),
            batch_indices: [0; N],
            batch_inputs: [[0u8; BATCH_INPUT_SIZE]; N],
        }
    }
}

impl<const N: usize> Blake3AccumulatingHashBatch<N> {
    fn flush_batch(&mut self, lane: usize) {
        let pos = self.buffer_positions[lane];
        if pos == 0 {
            return;
        }

        let batch_input = &mut self.batch_inputs[lane];
        let batch_index = self.batch_indices[lane];

        // Write batch index
        batch_input[..8].copy_from_slice(&batch_index.to_le_bytes());

        // Serialize ciphertexts
        for i in 0..pos {
            let start = 8 + i * 16;
            batch_input[start..start + 16].copy_from_slice(&self.buffers[lane][i].to_bytes());
        }

        // Hash the filled portion
        let filled_len = 8 + pos * 16;
        let batch_hash = blake3::hash(&batch_input[..filled_len]);

        // Feed to running hasher
        self.running_hashers[lane].update(batch_hash.as_bytes());

        // Reset
        self.batch_indices[lane] += 1;
        self.buffer_positions[lane] = 0;
    }
}

pub struct Blake3HashBatchResult<const N: usize>(pub [[u8; HASH_OUTPUT_SIZE]; N]);

impl<const N: usize> Default for Blake3HashBatchResult<N> {
    fn default() -> Self {
        Blake3HashBatchResult([[0u8; HASH_OUTPUT_SIZE]; N])
    }
}

impl<const N: usize> IntoIterator for Blake3HashBatchResult<N> {
    type Item = [u8; HASH_OUTPUT_SIZE];
    type IntoIter = std::array::IntoIter<[u8; HASH_OUTPUT_SIZE], N>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<const N: usize> MultiCiphertextHandler<N> for Blake3AccumulatingHashBatch<N> {
    type Result = Blake3HashBatchResult<N>;

    fn handle(&mut self, cts: [S; N]) {
        for (i, ct) in cts.into_iter().enumerate() {
            self.buffers[i][self.buffer_positions[i]] = ct;
            self.buffer_positions[i] += 1;
            if self.buffer_positions[i] == BATCH_SIZE {
                self.flush_batch(i);
            }
        }
    }

    fn finalize(mut self) -> Self::Result {
        let mut result = [[0u8; HASH_OUTPUT_SIZE]; N];
        for (i, res) in result.iter_mut().enumerate() {
            self.flush_batch(i);
            *res = *self.running_hashers[i].finalize().as_bytes();
        }
        Blake3HashBatchResult(result)
    }
}
