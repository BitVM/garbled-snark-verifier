use std::{
    fs::File,
    io::{self, BufReader, Read},
    path::Path,
};

use crossbeam::channel;
use tracing::error;

use crate::{CiphertextHashAcc, S};

/// Abstraction over a stream of ciphertexts
/// Mirrors `CiphertextHandler` on the consumption side.
pub trait CiphertextSource: Send {
    type Result: Default;

    /// Receive next ciphertext label in stream order.
    fn recv(&mut self) -> Option<S>;
    fn finalize(&self) -> Self::Result;
}

/// Channel-based source to preserve backward compatibility.
pub type ChannelSource = channel::Receiver<S>;

impl CiphertextSource for ChannelSource {
    type Result = ();

    fn recv(&mut self) -> Option<S> {
        channel::Receiver::recv(self).ok()
    }
    fn finalize(&self) {}
}

/// File-backed source that reads records directly from disk.
/// Record format (compact): 16-byte big-endian S label only.
pub struct FileSource {
    reader: BufReader<File>,
    // Scratch buffer for a single record (16)
    rec: [u8; 16],
    eof: bool,
    // Optional hasher to accumulate ciphertext hash for verification
    hasher: CiphertextHashAcc,
}

impl FileSource {
    pub fn from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        // Large buffer to reduce syscalls on fast disks
        const BUF_CAP: usize = 4 << 20;
        let file = File::open(path)?;
        let reader = BufReader::with_capacity(BUF_CAP, file);
        Ok(Self {
            reader,
            rec: [0u8; 16],
            eof: false,
            hasher: CiphertextHashAcc::default(),
        })
    }
}

impl CiphertextSource for FileSource {
    type Result = u128;
    fn recv(&mut self) -> Option<S> {
        if self.eof {
            return None;
        }

        let mut read = 0usize;
        while read < self.rec.len() {
            match self.reader.read(&mut self.rec[read..]) {
                Ok(0) => {
                    if read == 0 {
                        // Clean EOF - finalize hash if enabled
                        self.eof = true;

                        return None;
                    } else {
                        error!(
                            "unexpected EOF while reading ciphertext record ({} of {} bytes)",
                            read,
                            self.rec.len()
                        );
                        self.eof = true;
                        return None;
                    }
                }
                Ok(n) => read += n,
                Err(e) => {
                    error!("I/O error while reading ciphertexts: {e}");
                    self.eof = true;
                    return None;
                }
            }
        }

        let mut s_bytes = [0u8; 16];
        s_bytes.copy_from_slice(&self.rec[..]);
        let s = S::from_bytes(s_bytes);

        self.hasher.update(s);

        Some(s)
    }

    fn finalize(&self) -> Self::Result {
        self.hasher.finalize()
    }
}
