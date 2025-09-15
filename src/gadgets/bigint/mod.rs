use std::{collections::HashMap, iter};

use bitvec::prelude::*;
pub use num_bigint::BigUint;

use crate::{
    CircuitContext, WireId,
    circuit::{CircuitOutput, FALSE_WIRE, TRUE_WIRE, modes::ExecuteMode},
};

mod add;
mod cmp;
mod mul;
pub use add::*;
pub use cmp::*;
pub use mul::*;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("BigUint overflow: value requires {actual} bits, limit is {limit}")]
    TooBigUint { limit: usize, actual: usize },
}
pub type BigUintError = Error;

pub fn bits_from_biguint(u: &BigUint) -> BitVec<u8> {
    let mut bytes = u.to_bytes_le();
    if bytes.len() < 32 {
        bytes.resize(32, 0);
    }
    BitVec::from_vec(bytes)
}

pub fn bits_from_biguint_with_len(u: &BigUint, bit_count: usize) -> Result<BitVec<u8>, Error> {
    if u.bits() as usize > bit_count {
        return Err(Error::TooBigUint {
            limit: bit_count,
            actual: u.bits() as usize,
        });
    }

    let mut bytes = u.to_bytes_le();
    let byte_count = bit_count.div_ceil(8);
    bytes.resize(byte_count, 0);
    let mut bv = BitVec::from_vec(bytes);
    bv.truncate(bit_count);

    Ok(bv)
}

#[derive(Debug, Clone)]
pub struct BigIntWires {
    pub bits: Vec<WireId>,
}

impl BigIntWires {
    pub fn new(issue: impl FnMut() -> WireId, len: usize) -> Self {
        Self {
            bits: iter::repeat_with(issue).take(len).collect(),
        }
    }

    pub fn from_ctx<C: CircuitContext>(circuit: &mut C, len: usize) -> Self {
        Self {
            bits: iter::repeat_with(|| circuit.issue_wire())
                .take(len)
                .collect(),
        }
    }

    pub fn from_bits(bits: impl IntoIterator<Item = WireId>) -> Self {
        Self {
            bits: bits.into_iter().collect(),
        }
    }

    pub fn new_constant(len: usize, u: &BigUint) -> Result<Self, Error> {
        let bits = bits_from_biguint_with_len(u, len)?;

        let bits = (0..len)
            .map(|i| match *bits.get(i).unwrap() {
                true => TRUE_WIRE,
                false => FALSE_WIRE,
            })
            .collect::<Vec<_>>();

        Ok(Self { bits })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> impl Iterator<Item = &WireId> {
        self.bits.iter()
    }

    pub fn to_into_iter(self) -> impl IntoIterator<Item = WireId> {
        self.bits.into_iter()
    }

    pub fn pop(&mut self) -> Option<WireId> {
        self.bits.pop()
    }

    pub fn insert(&mut self, index: usize, wire: WireId) {
        self.bits.insert(index, wire);
    }

    pub fn last(&self) -> Option<WireId> {
        self.bits.last().copied()
    }

    pub fn get(&self, index: usize) -> Option<WireId> {
        self.bits.get(index).copied()
    }

    pub fn set(&mut self, index: usize, w: WireId) -> Option<WireId> {
        self.bits.get_mut(index).map(|entry| {
            let old = *entry;
            *entry = w;
            old
        })
    }

    /// Get a range of wires as a new BigIntWires
    pub fn get_range(&self, range: impl std::ops::RangeBounds<usize>) -> BigIntWires {
        use std::ops::Bound;
        let start = match range.start_bound() {
            Bound::Included(&start) => start,
            Bound::Excluded(&start) => start + 1,
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(&end) => end + 1,
            Bound::Excluded(&end) => end,
            Bound::Unbounded => self.bits.len(),
        };
        BigIntWires {
            bits: self.bits[start..end].to_vec(),
        }
    }

    /// Get the first wire ID
    pub fn first(&self) -> Option<WireId> {
        self.bits.first().copied()
    }

    pub fn split_at(mut self, index: usize) -> (BigIntWires, BigIntWires) {
        let right_bits = self.bits.split_off(index);

        (
            BigIntWires { bits: self.bits },
            BigIntWires { bits: right_bits },
        )
    }

    pub fn truncate(mut self, new_len: usize) -> Self {
        self.bits.truncate(new_len);
        self
    }

    pub fn get_wire_bits_fn(
        &self,
        u: &BigUint,
    ) -> Result<impl Fn(WireId) -> Option<bool> + use<>, Error> {
        let bits = bits_from_biguint_with_len(u, self.bits.len())?;

        let mapping = (0..self.bits.len())
            .map(|i| (self.bits[i], *bits.get(i).unwrap()))
            .collect::<HashMap<WireId, bool>>();

        Ok(move |wire_id| mapping.get(&wire_id).copied())
    }

    pub fn to_bitmask(&self, get_val: impl Fn(WireId) -> bool) -> String {
        let to_char = |wire_id: &WireId| if (get_val)(*wire_id) { '1' } else { '0' };
        self.bits.iter().map(to_char).collect()
    }
}

impl AsRef<[WireId]> for BigIntWires {
    fn as_ref(&self) -> &[WireId] {
        self.bits.as_ref()
    }
}

impl CircuitOutput<ExecuteMode> for BigUint {
    type WireRepr = BigIntWires;

    fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
        use crate::circuit::modes::CircuitMode;

        let bit_len = wires.len();

        let mut bytes = vec![0u8; bit_len.div_ceil(8)];

        for (i, w) in wires.iter().enumerate() {
            let bit = cache.lookup_wire(*w).expect("missing wire value");
            if bit {
                bytes[i / 8] |= 1u8 << (i % 8);
            }
        }

        BigUint::from_bytes_le(&bytes)
    }
}
