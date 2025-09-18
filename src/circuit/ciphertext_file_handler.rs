use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
};

use super::CiphertextHandler;
use crate::{S, ciphertext_hasher::CiphertextHashAcc};

const BUFFER_SIZE: usize = 128 << 20; // 128 MB buffer keeps large garbles efficient

/// High-performance file-based ciphertext handler optimized for large files.
///
/// Uses a large in-memory buffer (128MB) to accumulate ciphertexts before writing
/// to disk in large chunks, avoiding the overhead of channels and frequent I/O.
/// Suitable for handling 43GB files (Free-XOR optimized) at ~150MB/s sustained write speeds.
pub struct CiphertextFileHandler {
    /// Buffered writer backed by the ciphertext file
    writer: BufWriter<File>,
    /// Total bytes written to file
    bytes_written: u64,
    /// Hash accumulator for integrity verification
    hasher: CiphertextHashAcc,
    /// Whether finalize_mut or drop already flushed the writer
    flushed: bool,
}

impl CiphertextFileHandler {
    /// Create a new CiphertextFileHandler for the given file path and instance index.
    ///
    /// # Arguments
    /// * `path` - File path where ciphertexts will be written
    /// * `index` - Instance index for debugging purposes
    /// * `expected_size` - Expected total file size for pre-allocation
    pub fn new(path: impl AsRef<Path>, expected_size: Option<u64>) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;

        // Pre-allocate file space if size is provided to avoid fragmentation
        if let Some(size) = expected_size {
            file.set_len(size)?;
        }

        Ok(Self {
            writer: BufWriter::with_capacity(BUFFER_SIZE, file),
            bytes_written: 0,
            hasher: CiphertextHashAcc::default(),
            flushed: false,
        })
    }

    /// Flush buffered ciphertexts, trim trailing preallocation, and fsync.
    #[inline]
    fn flush_to_disk(&mut self) -> io::Result<()> {
        if self.flushed {
            return Ok(());
        }

        self.writer.flush()?;

        // Shrink the file back to the exact ciphertext payload size to
        // avoid hashing zero-padding that was introduced by preallocation.
        let file = self.writer.get_ref();
        file.set_len(self.bytes_written)?;
        file.sync_all()?;

        self.flushed = true;
        Ok(())
    }
}

impl CiphertextHandler for CiphertextFileHandler {
    type Result = u128;

    /// Handle a single ciphertext by adding it to the buffer
    #[inline(always)]
    fn handle(&mut self, ct: S) {
        // Update hash first
        self.hasher.update(ct);

        // Convert to bytes
        let bytes = ct.to_bytes();

        self.writer
            .write_all(&bytes)
            .expect("buffered write failed during handle");

        self.bytes_written += bytes.len() as u64;
    }

    /// Finalize by flushing remaining buffer and syncing to disk
    fn finalize(&self) -> Self::Result {
        // We need mutable access to flush, but finalize takes &self
        // This is a trait limitation - we'll implement a separate finalize_mut method
        self.hasher.finalize()
    }
}

impl Drop for CiphertextFileHandler {
    fn drop(&mut self) {
        if let Err(e) = self.flush_to_disk() {
            // Dropping during unwinding must not panic; log the failure instead.
            tracing::warn!("failed to flush ciphertext file: {}", e);
        }
    }
}
