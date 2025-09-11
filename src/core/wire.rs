use std::{fmt, ops::Deref};

use crate::S;

/// Errors that can occur during wire operations
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Wire with the given ID was not found
    #[error("Wire with id {0} not found")]
    WireNotFound(WireId),
    /// Wire with the given ID is already initialized
    #[error("Wire with id {0} already initialized")]
    WireAlreadyInitialized(WireId),
    /// Invalid wire index provided
    #[error("Invalid wire index: {0}")]
    InvalidWireIndex(WireId),
}
pub type WireError = Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireId(pub usize);

impl WireId {
    pub const MIN: WireId = WireId(2);
    pub const UNREACHABLE: WireId = WireId(usize::MAX);
}

impl fmt::Display for WireId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Deref for WireId {
    type Target = usize;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Provide simple conversions so `WireId` can be used as a key type
// for generic storage utilities that expect `From<usize>`/`Into<usize>`.
impl From<usize> for WireId {
    fn from(v: usize) -> Self {
        WireId(v)
    }
}

impl From<WireId> for usize {
    fn from(w: WireId) -> usize {
        w.0
    }
}

pub use crate::circuit::streaming::modes::garble_mode::GarbledWire;

// Legacy GarbledWires container removed in favor of direct GarbledWire usage.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluatedWire {
    pub active_label: S,
    pub value: bool,
}

impl Default for EvaluatedWire {
    fn default() -> Self {
        Self {
            active_label: S::ZERO,
            value: Default::default(),
        }
    }
}

impl EvaluatedWire {
    pub fn new_from_garbled(garbled_wire: &GarbledWire, value: bool) -> Self {
        Self {
            active_label: garbled_wire.select(value),
            value,
        }
    }

    pub fn value(&self) -> bool {
        self.value
    }
}
