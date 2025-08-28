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

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        let wires: Vec<WireId> = iter.take(N).collect();
        if wires.len() != N {
            return None;
        }
        let mut array = [WireId(0); N];
        array.copy_from_slice(&wires);
        Some(array)
    }
}

// Generate WiresObject implementations for tuples up to 12 elements
macro_rules! impl_wires_object_for_tuples {
    ($(($($T:ident : $idx:tt),*)),+) => {
        $(
            impl<$($T: WiresObject),*> WiresObject for ($($T,)*) {
                fn to_wires_vec(&self) -> Vec<WireId> {
                    let mut wires = Vec::new();
                    $(wires.extend(self.$idx.to_wires_vec());)*
                    wires
                }

                fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
                    $(
                        let $T = $T::from_wire_iter(iter)?;
                    )*
                    Some(($($T,)*))
                }
            }
        )*
    };
}

impl_wires_object_for_tuples!(
    (T0: 0, T1: 1, T2: 2, T3: 3),
    (T0: 0, T1: 1, T2: 2, T3: 3, T4: 4),
    (T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5),
    (T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6),
    (T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6, T7: 7),
    (T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6, T7: 7, T8: 8),
    (T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6, T7: 7, T8: 8, T9: 9),
    (T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6, T7: 7, T8: 8, T9: 9, T10: 10),
    (T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6, T7: 7, T8: 8, T9: 9, T10: 10, T11: 11),
    (T0: 0, T1: 1, T2: 2, T3: 3, T4: 4, T5: 5, T6: 6, T7: 7, T8: 8, T9: 9, T10: 10, T11: 11, T12: 12)
);

// Keep the simple WireId tuple implementations for backwards compatibility
impl WiresObject for (WireId, WireId) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        vec![self.0, self.1]
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        let a = iter.next()?;
        let b = iter.next()?;
        Some((a, b))
    }
}

impl WiresObject for (WireId, WireId, WireId) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        vec![self.0, self.1, self.2]
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        let a = iter.next()?;
        let b = iter.next()?;
        let c = iter.next()?;
        Some((a, b, c))
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

    /// Construct from a consuming iterator
    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self>;
}

impl WiresObject for WireId {
    fn to_wires_vec(&self) -> Vec<WireId> {
        vec![*self]
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        iter.next()
    }
}

impl WiresObject for BigIntWires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().copied().collect()
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        Some(BigIntWires::from_bits(iter))
    }
}

impl WiresObject for Vec<WireId> {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.clone()
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        Some(iter.collect())
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

    fn from_wire_iter(mut iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        Some((
            BigIntWires::from_wire_iter(&mut iter)?,
            BigIntWires::from_wire_iter(&mut iter)?,
        ))
    }
}

// Add specific tuple implementations that were removed but are needed
impl WiresObject for (Vec<WireId>, Vec<WireId>) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0.iter().chain(self.1.iter()).copied().collect()
    }

    fn from_wire_iter(_iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        // Cannot determine sizes without additional information
        None
    }
}

impl WiresObject for (BigIntWires, WireId) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0
            .iter()
            .copied()
            .chain(std::iter::once(self.1))
            .collect()
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        let big_int = BigIntWires::from_wire_iter(iter)?;
        let wire = iter.next()?;
        Some((big_int, wire))
    }
}

impl WiresObject for (BigIntWires, BigIntWires, WireId) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0
            .iter()
            .chain(self.1.iter())
            .copied()
            .chain(std::iter::once(self.2))
            .collect()
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        let big_int1 = BigIntWires::from_wire_iter(iter)?;
        let big_int2 = BigIntWires::from_wire_iter(iter)?;
        let wire = iter.next()?;
        Some((big_int1, big_int2, wire))
    }
}

impl WiresObject for (Fq, WireId) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0
            .to_wires_vec()
            .into_iter()
            .chain(std::iter::once(self.1))
            .collect()
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        let fq = Fq::from_wire_iter(iter)?;
        let wire = iter.next()?;
        Some((fq, wire))
    }
}

impl WiresObject for Vec<Fr> {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|t| t.to_wires_vec()).collect()
    }

    fn from_wire_iter(_iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        // Cannot determine size without additional information
        None
    }
}

// Note: (Vec<Fr>, Fq, WireId, Fq, WireId) is handled by the generic tuple macro

impl WiresObject for (Vec<Fr>, G1Projective, G1Projective) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.to_wires_vec());
        wires.extend(self.1.to_wires_vec());
        wires.extend(self.2.to_wires_vec());
        wires
    }

    fn from_wire_iter(_iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        // Cannot construct Vec<Fr> without knowing size
        None
    }
}

impl WiresObject for Vec<G1Projective> {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|g| g.to_wires_vec()).collect()
    }

    fn from_wire_iter(_iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        // Cannot determine size without additional information
        None
    }
}

impl WiresObject for (Vec<BigIntWires>, Vec<WireId>) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.iter().flat_map(|b| b.to_wires_vec()));
        wires.extend(self.1.iter().copied());
        wires
    }

    fn from_wire_iter(_iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        // Cannot determine sizes without additional information
        None
    }
}

impl WiresObject for (G1Projective, G1Projective) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.to_wires_vec());
        wires.extend(self.1.to_wires_vec());
        wires
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        let g1 = G1Projective::from_wire_iter(iter)?;
        let g2 = G1Projective::from_wire_iter(iter)?;
        Some((g1, g2))
    }
}

impl WiresObject for (G2Projective, G2Projective) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.to_wires_vec());
        wires.extend(self.1.to_wires_vec());
        wires
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        let g1 = G2Projective::from_wire_iter(iter)?;
        let g2 = G2Projective::from_wire_iter(iter)?;
        Some((g1, g2))
    }
}

impl WiresObject for (Vec<G1Projective>, Vec<WireId>) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.iter().flat_map(|g| g.to_wires_vec()));
        wires.extend(self.1.iter().copied());
        wires
    }

    fn from_wire_iter(_iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        // Cannot determine sizes without additional information
        None
    }
}

impl WiresObject for (Vec<G2Projective>, Vec<WireId>) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.iter().flat_map(|g| g.to_wires_vec()));
        wires.extend(self.1.iter().copied());
        wires
    }

    fn from_wire_iter(_iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        // Cannot determine sizes without additional information
        None
    }
}

impl WiresObject for (Fq12, Fq2, Fq2) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.to_wires_vec());
        wires.extend(self.1.to_wires_vec());
        wires.extend(self.2.to_wires_vec());
        wires
    }

    fn from_wire_iter(iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        let fq12 = Fq12::from_wire_iter(iter)?;
        let fq2_1 = Fq2::from_wire_iter(iter)?;
        let fq2_2 = Fq2::from_wire_iter(iter)?;
        Some((fq12, fq2_1, fq2_2))
    }
}

impl<const N: usize> WiresObject for [BigIntWires; N] {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|bn| bn.to_wires_vec()).collect()
    }

    fn from_wire_iter(mut iter: &mut impl Iterator<Item = WireId>) -> Option<Self> {
        let mut result = Vec::with_capacity(N);

        for _ in 0..N {
            result.push(BigIntWires::from_wire_iter(&mut iter)?);
        }

        result.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_id_wires_object() {
        let wire = WireId(42);
        assert_eq!(wire.to_wires_vec(), vec![WireId(42)]);
        let mut iter = [WireId(42)].into_iter();
        assert_eq!(WireId::from_wire_iter(&mut iter), Some(WireId(42)));
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
        let mut iter = [WireId(1), WireId(2), WireId(3)].into_iter();
        assert_eq!(
            <[WireId; 3]>::from_wire_iter(&mut iter),
            Some([WireId(1), WireId(2), WireId(3)])
        );
    }

    #[test]
    fn test_tuple_wires_object() {
        let tuple = (WireId(1), WireId(2));
        assert_eq!(tuple.to_wires_vec(), vec![WireId(1), WireId(2)]);
        let mut iter = [WireId(1), WireId(2)].into_iter();
        assert_eq!(
            <(WireId, WireId)>::from_wire_iter(&mut iter),
            Some((WireId(1), WireId(2)))
        );
    }
}
