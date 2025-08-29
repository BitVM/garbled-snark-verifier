use std::{fmt, mem, ops::Deref};

use rand::Rng;

use crate::{Delta, S};

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GarbledWire {
    pub label0: S,
    pub label1: S,
}

impl GarbledWire {
    pub(crate) fn new(label0: S, label1: S) -> Self {
        GarbledWire { label0, label1 }
    }

    pub fn toggle_not(&mut self) {
        mem::swap(&mut self.label1, &mut self.label0);
    }

    pub fn random(rng: &mut impl Rng, delta: &Delta) -> Self {
        let label0 = S::random(rng);

        GarbledWire {
            label0,
            // free-XOR: label1 = label0 ^ Δ
            label1: label0 ^ delta,
        }
    }

    pub fn select(&self, bit: bool) -> S {
        match bit {
            false => self.label0,
            true => self.label1,
        }
    }
}

impl Default for GarbledWire {
    fn default() -> Self {
        GarbledWire {
            label0: S::ZERO,
            label1: S::ZERO,
        }
    }
}

mod garbled_wires {
    use std::collections::{HashMap, hash_map::Entry};

    use super::{GarbledWire, WireError, WireId};

    #[derive(Debug)]
    pub struct GarbledWires {
        wires: HashMap<WireId, GarbledWire>,
    }

    impl GarbledWires {
        pub fn new(_num_wires: usize) -> Self {
            Self {
                wires: HashMap::new(),
            }
        }

        pub fn get(&self, wire_id: WireId) -> Result<&GarbledWire, WireError> {
            self.wires
                .get(&wire_id)
                .ok_or(WireError::InvalidWireIndex(wire_id))
        }

        pub fn init(
            &mut self,
            wire_id: WireId,
            wire: GarbledWire,
        ) -> Result<&GarbledWire, WireError> {
            //if wire_id.0 > self.num_wires {
            //    return Err(WireError::InvalidWireIndex(wire_id));
            //}
            match self.wires.entry(wire_id) {
                Entry::Occupied(_) => Err(WireError::InvalidWireIndex(wire_id)),
                Entry::Vacant(vac) => Ok(vac.insert(wire)),
            }
        }

        pub fn toggle_wire_not_mark(&mut self, wire_id: WireId) -> Result<(), WireError> {
            self.wires
                .get_mut(&wire_id)
                .ok_or(WireError::InvalidWireIndex(wire_id))?
                .toggle_not();

            Ok(())
        }

        pub fn get_or_init<'s>(
            &'s mut self,
            wire_id: WireId,
            init: &mut impl FnMut() -> GarbledWire,
        ) -> Result<&'s GarbledWire, WireError> {
            let containt = self.wires.contains_key(&wire_id);

            match containt {
                true => self.get(wire_id),
                false => {
                    self.init(wire_id, init())?;
                    self.get(wire_id)
                }
            }
        }

        pub fn size(&self) -> usize {
            // TODO Double check
            self.wires.len()
        }
    }
}
pub use garbled_wires::GarbledWires;

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
