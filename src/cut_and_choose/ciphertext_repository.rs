use std::{
    fmt,
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::PathBuf,
};

use crossbeam::channel;
use tracing::error;

use crate::{
    CiphertextHashAcc, S,
    circuit::{CiphertextHandler, ciphertext_source},
    cut_and_choose::Commit,
};

pub trait CiphertextSourceProvider {
    type Source: ciphertext_source::CiphertextSource;
    type Error: fmt::Debug;

    fn source_for(&self, index: usize) -> Result<Self::Source, Self::Error>;
}

impl CiphertextSourceProvider for PathBuf {
    type Source = ciphertext_source::FileSource;
    type Error = io::Error;

    fn source_for(&self, index: usize) -> Result<Self::Source, Self::Error> {
        let path = self.join(format!("gc_{index}.bin"));
        if !path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("ciphertext file {path:?} not found"),
            ));
        }

        ciphertext_source::FileSource::from_path(path)
    }
}

impl CiphertextSourceProvider for Vec<(usize, channel::Receiver<S>)> {
    type Source = channel::Receiver<S>;
    type Error = ();

    fn source_for(&self, index: usize) -> Result<Self::Source, Self::Error> {
        self.iter()
            .find_map(|(i, rx)| i.eq(&index).then_some(rx).cloned())
            .ok_or(())
    }
}

pub trait CiphertextHandlerProvider {
    type Handler: CiphertextHandler + Send;
    type Error: fmt::Debug;

    fn handler_for(&self, index: usize) -> Result<Self::Handler, Self::Error>;
}

pub struct FileCiphertextHandler {
    path: PathBuf,
    writer: BufWriter<File>,
    hasher: CiphertextHashAcc,
}

impl FileCiphertextHandler {
    pub fn create(path: PathBuf, pre_allocate: Option<u64>) -> io::Result<Self> {
        let file = File::create(&path)?;

        if let Some(size) = pre_allocate
            && let Err(err) = file.set_len(size)
        {
            error!(path = %path.display(), ?err, "failed to pre-allocate ciphertext file");
        }

        let buffer_size = if pre_allocate.unwrap_or(0) > 10 * (1 << 30) {
            1 << 25 // 32MB buffer for files > 10GB
        } else {
            1 << 20 // 1MB buffer for smaller files
        };

        Ok(Self {
            path,
            writer: BufWriter::with_capacity(buffer_size, file),
            hasher: CiphertextHashAcc::default(),
        })
    }
}

impl CiphertextHandler for FileCiphertextHandler {
    type Result = Commit;

    fn handle(&mut self, ct: S) {
        self.hasher.update(ct);

        self.writer.write_all(&ct.to_bytes()).unwrap_or_else(|err| {
            panic!(
                "failed to write ciphertext to {}: {err}",
                self.path.display()
            )
        });
    }

    fn finalize(&self) -> Self::Result {
        self.hasher.finalize()
    }
}

#[derive(Clone, Debug)]
pub struct FileCiphertextHandlerProvider {
    root: PathBuf,
    pre_allocate: Option<u64>,
}

impl FileCiphertextHandlerProvider {
    pub fn new(root: impl Into<PathBuf>, pre_allocate: Option<u64>) -> io::Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self { root, pre_allocate })
    }
}

impl CiphertextHandlerProvider for FileCiphertextHandlerProvider {
    type Handler = FileCiphertextHandler;
    type Error = io::Error;

    fn handler_for(&self, index: usize) -> Result<Self::Handler, Self::Error> {
        let path = self.root.join(format!("gc_{}.bin", index));
        FileCiphertextHandler::create(path, self.pre_allocate)
    }
}
