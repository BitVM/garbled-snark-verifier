use crate::{S, circuit::MultiCiphertextHandler};

/// Batch size for Blake3 accumulating hash (64 ciphertexts = 1KB)
pub const BATCH_SIZE: usize = 61;
/// Output hash size (full Blake3)
pub const HASH_OUTPUT_SIZE: usize = 32;
/// Batch input buffer size: 8 bytes index + 32 bytes prev_hash + 64 * 16 bytes ciphertexts
const BATCH_INPUT_SIZE: usize = 8 + 32 + BATCH_SIZE * 16;

/// Blake3-based chained hash optimized for high-volume ciphertext hashing.
///
/// Designed for 2.7B+ ciphertexts with zero heap allocations in hot path:
/// - Batches 64 ciphertexts (1KB) before hashing
/// - Uses batch index prefix for domain separation
/// - Chained hash: hash[i] = blake3(batch_index || hash[i-1] || ciphertexts)
pub struct Blake3AccumulatingHash {
    batch_input: [u8; BATCH_INPUT_SIZE],
    buffer_pos: usize,
    batch_index: u64,
}

impl Default for Blake3AccumulatingHash {
    fn default() -> Self {
        Self {
            batch_input: [0u8; BATCH_INPUT_SIZE],
            buffer_pos: 0,
            batch_index: 0,
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
        let start = 40 + self.buffer_pos * 16;
        ciphertext.write_bytes_le(
            (&mut self.batch_input[start..start + 16])
                .try_into()
                .unwrap(),
        );
        self.buffer_pos += 1;
        if self.buffer_pos == BATCH_SIZE {
            self.flush_batch();
        }
    }

    fn flush_batch(&mut self) {
        if self.buffer_pos == 0 {
            return;
        }

        // Write batch index (first 8 bytes)
        self.batch_input[..8].copy_from_slice(&self.batch_index.to_le_bytes());
        // batch_input[8..40] already has prev_hash (zeros initially, then chained)
        // batch_input[40..] already has ciphertexts from update()

        // Hash and write result directly to prev_hash slot for next iteration
        let filled_len = 40 + self.buffer_pos * 16;
        blake3::Hasher::new()
            .update(&self.batch_input[..filled_len])
            .finalize_xof()
            .fill(&mut self.batch_input[8..40]);

        self.batch_index += 1;
        self.buffer_pos = 0;
    }

    pub fn finalize(mut self) -> [u8; HASH_OUTPUT_SIZE] {
        self.flush_batch();
        self.batch_input[8..40].try_into().unwrap()
    }
}

/// Batch version for N parallel lanes, used in multigarbling mode.
pub struct Blake3AccumulatingHashBatch<const N: usize> {
    batch_inputs: [[u8; BATCH_INPUT_SIZE]; N],
    buffer_positions: [usize; N],
    batch_indices: [u64; N],
}

impl<const N: usize> Default for Blake3AccumulatingHashBatch<N> {
    fn default() -> Self {
        Self {
            batch_inputs: [[0u8; BATCH_INPUT_SIZE]; N],
            buffer_positions: [0; N],
            batch_indices: [0; N],
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
        // batch_input[8..40] already has prev_hash
        // batch_input[40..] already has ciphertexts from handle()

        // Hash and write result directly to prev_hash slot
        let filled_len = 40 + pos * 16;
        blake3::Hasher::new()
            .update(&batch_input[..filled_len])
            .finalize_xof()
            .fill(&mut batch_input[8..40]);

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
            let start = 40 + self.buffer_positions[i] * 16;
            ct.write_bytes_le(
                (&mut self.batch_inputs[i][start..start + 16])
                    .try_into()
                    .unwrap(),
            );
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
            *res = self.batch_inputs[i][8..40].try_into().unwrap();
        }
        Blake3HashBatchResult(result)
    }
}
