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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GarbledWire {
    pub label0: S,
    pub label1: S,
}

impl GarbledWire {
    pub(super) fn new(label0: S, label1: S) -> Self {
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

mod garbled_wires {
    use std::mem::MaybeUninit;

    use bitvec::vec::BitVec;

    use super::{GarbledWire, WireError, WireId};

    #[derive(Debug)]
    pub struct GarbledWires {
        wires: Vec<MaybeUninit<GarbledWire>>,
        initialized: BitVec,
        max_wire_id: usize,
    }

    impl GarbledWires {
        pub fn new(num_wires: usize) -> Self {
            Self {
                wires: {
                    // Safe because we won't read before writing
                    let mut vec = Vec::with_capacity(num_wires);
                    vec.resize_with(num_wires, MaybeUninit::uninit);
                    vec
                },
                initialized: BitVec::repeat(false, num_wires),
                max_wire_id: num_wires,
            }
        }

        pub fn get(&self, wire_id: WireId) -> Result<&GarbledWire, WireError> {
            if wire_id.0 >= self.initialized.len() || !self.initialized[wire_id.0] {
                return Err(WireError::InvalidWireIndex(wire_id));
            }

            // SAFETY: We checked it's initialized
            Ok(unsafe { self.wires[wire_id.0].assume_init_ref() })
        }

        pub fn init(
            &mut self,
            wire_id: WireId,
            wire: GarbledWire,
        ) -> Result<&GarbledWire, WireError> {
            self.ensure_capacity(wire_id.0 + 1)?;

            if self.initialized[wire_id.0] {
                return Err(WireError::InvalidWireIndex(wire_id));
            }

            self.wires[wire_id.0] = MaybeUninit::new(wire);
            self.initialized.set(wire_id.0, true);
            self.get(wire_id)
        }

        pub fn toggle_wire_not_mark(&mut self, wire_id: WireId) -> Result<(), WireError> {
            if wire_id.0 >= self.initialized.len() || !self.initialized[wire_id.0] {
                return Err(WireError::InvalidWireIndex(wire_id));
            }

            unsafe {
                self.wires[wire_id.0].assume_init_mut().toggle_not();
            }

            Ok(())
        }

        pub fn get_or_init(
            &mut self,
            wire_id: WireId,
            init: &mut impl FnMut() -> GarbledWire,
        ) -> Result<&GarbledWire, WireError> {
            if wire_id.0 >= self.max_wire_id {
                return Err(WireError::InvalidWireIndex(wire_id));
            }

            self.ensure_capacity(wire_id.0 + 1)?;

            if !self.initialized[wire_id.0] {
                let wire = init();
                self.wires[wire_id.0] = MaybeUninit::new(wire);
                self.initialized.set(wire_id.0, true);
            }

            Ok(unsafe { self.wires[wire_id.0].assume_init_ref() })
        }

        fn ensure_capacity(&mut self, size: usize) -> Result<(), WireError> {
            if self.wires.len() < size {
                self.wires.resize_with(size, MaybeUninit::uninit);
                self.initialized.resize(size, false);
            }
            Ok(())
        }
        pub fn size(&self) -> usize {
            // TODO Double check
            self.initialized.last_one().unwrap_or(0)
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
            active_label: S([0u8; crate::core::s::S_SIZE]),
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
