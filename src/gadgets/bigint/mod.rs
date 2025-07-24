#![allow(dead_code)]

use std::{collections::HashMap, iter};

use bitvec::prelude::*;
pub use num_bigint::BigUint;

use crate::{Circuit, WireId};

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
    //let byte_count = (bit_count + 7) / 8;
    let byte_count = bit_count.div_ceil(8);
    bytes.resize(byte_count, 0);
    Ok(BitVec::from_vec(bytes))
}

#[derive(Debug, Clone)]
pub struct BigIntWires {
    bits: Vec<WireId>,
}

impl BigIntWires {
    pub fn new(circuit: &mut Circuit, len: usize, is_input: bool, is_output: bool) -> Self {
        Self {
            bits: iter::repeat_with(|| {
                let w = circuit.issue_wire();
                if is_input {
                    circuit.make_wire_input(w);
                }
                if is_output {
                    circuit.make_wire_output(w);
                }
                w
            })
            .take(len)
            .collect(),
        }
    }

    pub fn from_bits(bits: impl IntoIterator<Item = WireId>) -> Self {
        Self {
            bits: bits.into_iter().collect(),
        }
    }

    pub fn new_constant(circuit: &mut Circuit, len: usize, u: &BigUint) -> Result<Self, Error> {
        let bits = bits_from_biguint_with_len(u, len)?;

        let bits = (0..len)
            .map(|i| match *bits.get(i).unwrap() {
                true => circuit.get_true_wire_constant(),
                false => circuit.get_false_wire_constant(),
            })
            .collect::<Vec<_>>();

        Ok(Self { bits })
    }

    pub fn mark_as_output(&self, circuit: &mut Circuit) {
        self.bits.iter().for_each(|wire_bit| {
            circuit.make_wire_output(*wire_bit);
        });
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
