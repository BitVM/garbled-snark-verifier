#![allow(non_snake_case)]
use crate::{
    WireId,
    gadgets::{
        bigint::BigIntWires,
        bn254::{Fp254Impl, Fq, Fq12, G1Projective, G2Projective, fq2::Fq2, fq6::Fq6, fr::Fr},
    },
};

impl<const N: usize> WiresObject for [WireId; N] {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.to_vec()
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        if wires.len() != N {
            return None;
        }
        let mut array = [WireId(0); N];
        array.copy_from_slice(wires);
        Some(array)
    }
}

impl WiresObject for &Vec<WireId> {
    fn to_wires_vec(&self) -> Vec<WireId> {
        (*self).clone()
    }

    fn from_wires(_wires: &[WireId]) -> Option<Self> {
        // Can't construct a reference from owned data
        None
    }
}

impl WiresObject for &WireId {
    fn to_wires_vec(&self) -> Vec<WireId> {
        vec![**self]
    }

    fn from_wires(_wires: &[WireId]) -> Option<Self> {
        // Can't construct a reference from owned data
        None
    }
}

// Only implement for specific types to avoid conflict
impl WiresObject for &[Fr] {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|t| t.to_wires_vec()).collect()
    }

    fn from_wires(_wires: &[WireId]) -> Option<Self> {
        // Can't construct a reference from owned data
        None
    }
}

impl WiresObject for &[Fq] {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|t| t.to_wires_vec()).collect()
    }

    fn from_wires(_wires: &[WireId]) -> Option<Self> {
        // Can't construct a reference from owned data
        None
    }
}

impl WiresObject for &[WireId] {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.to_vec()
    }

    fn from_wires(_wires: &[WireId]) -> Option<Self> {
        // Can't construct a reference from owned data
        None
    }
}

impl WiresObject for &[BigIntWires] {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|t| t.to_wires_vec()).collect()
    }

    fn from_wires(_wires: &[WireId]) -> Option<Self> {
        // Can't construct a reference from owned data
        None
    }
}

impl WiresObject for &[G1Projective] {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|t| t.to_wires_vec()).collect()
    }

    fn from_wires(_wires: &[WireId]) -> Option<Self> {
        // Can't construct a reference from owned data
        None
    }
}

impl WiresObject for &[G2Projective] {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|t| t.to_wires_vec()).collect()
    }

    fn from_wires(_wires: &[WireId]) -> Option<Self> {
        // Can't construct a reference from owned data
        None
    }
}

// Simple WiresObject implementations for common tuple types
impl WiresObject for (WireId, WireId) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        vec![self.0, self.1]
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        if wires.len() != 2 {
            return None;
        }
        Some((wires[0], wires[1]))
    }
}

impl WiresObject for (WireId, WireId, WireId) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        vec![self.0, self.1, self.2]
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        if wires.len() != 3 {
            return None;
        }
        Some((wires[0], wires[1], wires[2]))
    }
}

/// Trait for types with compile-time known wire count
pub trait WiresArity {
    const ARITY: usize;
}

impl WiresArity for WireId {
    const ARITY: usize = 1;
}

impl WiresArity for () {
    const ARITY: usize = 0;
}

impl WiresArity for Fq {
    const ARITY: usize = Self::N_BITS;
}

impl WiresArity for Fr {
    const ARITY: usize = Self::N_BITS;
}

impl WiresArity for Fq2 {
    const ARITY: usize = Self::N_BITS;
}

impl WiresArity for Fq6 {
    const ARITY: usize = Self::N_BITS;
}

impl WiresArity for Fq12 {
    const ARITY: usize = Self::N_BITS;
}

impl WiresArity for G1Projective {
    const ARITY: usize = Self::N_BITS;
}

impl WiresArity for G2Projective {
    const ARITY: usize = Self::N_BITS;
}

pub trait WiresObject: Sized {
    fn to_wires_vec(&self) -> Vec<WireId>;

    fn from_wires(wires: &[WireId]) -> Option<Self>;
}

impl WiresObject for WireId {
    fn to_wires_vec(&self) -> Vec<WireId> {
        vec![*self]
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        match wires {
            [wire_id] => Some(*wire_id),
            _ => None,
        }
    }
}

impl WiresObject for &BigIntWires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().copied().collect()
    }

    fn from_wires(_wires: &[WireId]) -> Option<Self> {
        // Can't construct a reference from owned data
        None
    }
}

impl WiresObject for BigIntWires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().copied().collect()
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        Some(BigIntWires::from_bits(wires.iter().copied()))
    }
}

impl WiresObject for Vec<WireId> {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.clone()
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        Some(wires.to_vec())
    }
}

impl WiresObject for (BigIntWires, BigIntWires) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0
            .to_wires_vec()
            .into_iter()
            .chain(self.1.to_wires_vec())
            .collect()
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        let mid = wires.len() / 2;
        let (p1, p2) = wires.split_at(mid);

        Some((
            BigIntWires::from_bits(p1.iter().copied()),
            BigIntWires::from_bits(p2.iter().copied()),
        ))
    }
}

impl<const N: usize> WiresObject for [BigIntWires; N] {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|bn| bn.to_wires_vec()).collect()
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        let r = wires
            .chunks(N)
            .map(BigIntWires::from_wires)
            .collect::<Option<Vec<_>>>()?;

        Some(r.try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_id_wires_object() {
        let wire = WireId(42);
        assert_eq!(wire.to_wires_vec(), vec![WireId(42)]);
        assert_eq!(WireId::from_wires(&[WireId(42)]), Some(WireId(42)));
    }

    #[test]
    fn test_vec_wires_object() {
        let wires = vec![WireId(1), WireId(2), WireId(3)];
        assert_eq!(wires.to_wires_vec(), vec![WireId(1), WireId(2), WireId(3)]);
    }

    #[test]
    fn test_array_wires_object() {
        let array = [WireId(1), WireId(2), WireId(3)];
        assert_eq!(array.to_wires_vec(), vec![WireId(1), WireId(2), WireId(3)]);
        assert_eq!(
            <[WireId; 3]>::from_wires(&[WireId(1), WireId(2), WireId(3)]),
            Some([WireId(1), WireId(2), WireId(3)])
        );
    }

    #[test]
    fn test_tuple_wires_object() {
        let tuple = (WireId(1), WireId(2));
        assert_eq!(tuple.to_wires_vec(), vec![WireId(1), WireId(2)]);
        assert_eq!(
            <(WireId, WireId)>::from_wires(&[WireId(1), WireId(2)]),
            Some((WireId(1), WireId(2)))
        );
    }
}
