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

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        std::array::from_fn(|_| wire_gen())
    }
}

impl<const N: usize> FromWires for [WireId; N] {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        if wires.len() >= N {
            let mut array = [WireId(0); N];
            array[..N].copy_from_slice(&wires[..N]);
            Some(array)
        } else {
            None
        }
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

                fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
                    ($(self.$idx.clone_from(wire_gen),)*)
                }
            }

            impl<$($T: FromWires),*> FromWires for ($($T,)*) {
                #[allow(unused_assignments)]
                fn from_wires(wires: &[WireId]) -> Option<Self> {
                    let mut offset = 0;
                    $(
                        let $T = $T::from_wires(&wires[offset..])?;
                        offset += $T.to_wires_vec().len();
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

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (wire_gen(), wire_gen())
    }
}

impl FromWires for (WireId, WireId) {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        if wires.len() >= 2 {
            Some((wires[0], wires[1]))
        } else {
            None
        }
    }
}

impl WiresObject for (WireId, WireId, WireId) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        vec![self.0, self.1, self.2]
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (wire_gen(), wire_gen(), wire_gen())
    }
}

impl FromWires for (WireId, WireId, WireId) {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        if wires.len() >= 3 {
            Some((wires[0], wires[1], wires[2]))
        } else {
            None
        }
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

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self;
}

pub trait FromWires: WiresObject {
    fn from_wires(wires: &[WireId]) -> Option<Self>;
}

impl WiresObject for WireId {
    fn to_wires_vec(&self) -> Vec<WireId> {
        vec![*self]
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        wire_gen()
    }
}

impl FromWires for WireId {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        wires.first().copied()
    }
}

impl WiresObject for BigIntWires {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().copied().collect()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        BigIntWires::from_bits((0..self.len()).map(|_| wire_gen()))
    }
}

impl FromWires for BigIntWires {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        Some(BigIntWires::from_bits(wires.iter().copied()))
    }
}

impl WiresObject for Vec<WireId> {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.clone()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (0..self.len()).map(|_| wire_gen()).collect()
    }
}

impl FromWires for Vec<WireId> {
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

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (self.0.clone_from(wire_gen), self.1.clone_from(wire_gen))
    }
}

impl FromWires for (BigIntWires, BigIntWires) {
    fn from_wires(wires: &[WireId]) -> Option<Self> {
        let mid = wires.len() / 2;
        let bigint1 = BigIntWires::from_wires(&wires[..mid])?;
        let bigint2 = BigIntWires::from_wires(&wires[mid..])?;
        Some((bigint1, bigint2))
    }
}

// Add specific tuple implementations that were removed but are needed
impl WiresObject for (Vec<WireId>, Vec<WireId>) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.0.iter().chain(self.1.iter()).copied().collect()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (self.0.clone_from(wire_gen), self.1.clone_from(wire_gen))
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

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (self.0.clone_from(wire_gen), self.1.clone_from(wire_gen))
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

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (
            self.0.clone_from(wire_gen),
            self.1.clone_from(wire_gen),
            self.2.clone_from(wire_gen),
        )
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

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (self.0.clone_from(wire_gen), self.1.clone_from(wire_gen))
    }
}

impl WiresObject for Vec<Fr> {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|t| t.to_wires_vec()).collect()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        self.iter().map(move |fr| fr.clone_from(wire_gen)).collect()
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

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (
            self.0.clone_from(wire_gen),
            self.1.clone_from(wire_gen),
            self.2.clone_from(wire_gen),
        )
    }
}

impl WiresObject for Vec<G1Projective> {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|g| g.to_wires_vec()).collect()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        self.iter().map(|g| g.clone_from(wire_gen)).collect()
    }
}

impl WiresObject for (Vec<BigIntWires>, Vec<WireId>) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.iter().flat_map(|b| b.to_wires_vec()));
        wires.extend(self.1.iter().copied());
        wires
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (
            self.0.iter().map(|b| b.clone_from(wire_gen)).collect(),
            self.1.clone_from(wire_gen),
        )
    }
}

impl WiresObject for (G1Projective, G1Projective) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.to_wires_vec());
        wires.extend(self.1.to_wires_vec());
        wires
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (self.0.clone_from(wire_gen), self.1.clone_from(wire_gen))
    }
}

impl WiresObject for (G2Projective, G2Projective) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.to_wires_vec());
        wires.extend(self.1.to_wires_vec());
        wires
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (self.0.clone_from(wire_gen), self.1.clone_from(wire_gen))
    }
}

impl WiresObject for (Vec<G1Projective>, Vec<WireId>) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.iter().flat_map(|g| g.to_wires_vec()));
        wires.extend(self.1.iter().copied());
        wires
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (
            self.0.iter().map(|g| g.clone_from(wire_gen)).collect(),
            self.1.clone_from(wire_gen),
        )
    }
}

impl WiresObject for (Vec<G2Projective>, Vec<WireId>) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.iter().flat_map(|g| g.to_wires_vec()));
        wires.extend(self.1.iter().copied());
        wires
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (
            self.0.iter().map(|g| g.clone_from(wire_gen)).collect(),
            self.1.clone_from(wire_gen),
        )
    }
}

impl WiresObject for (Fq12, Fq6) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.to_wires_vec());
        wires.extend(self.1.to_wires_vec());
        wires
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (self.0.clone_from(wire_gen), self.1.clone_from(wire_gen))
    }
}

impl WiresObject for (Fq12, Fq12) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.to_wires_vec());
        wires.extend(self.1.to_wires_vec());
        wires
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (self.0.clone_from(wire_gen), self.1.clone_from(wire_gen))
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

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (
            self.0.clone_from(wire_gen),
            self.1.clone_from(wire_gen),
            self.2.clone_from(wire_gen),
        )
    }
}

// Specific pair needed by tests using (G2Projective, Fq6)
impl WiresObject for (G2Projective, Fq6) {
    fn to_wires_vec(&self) -> Vec<WireId> {
        let mut wires = Vec::new();
        wires.extend(self.0.to_wires_vec());
        wires.extend(self.1.to_wires_vec());
        wires
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        (self.0.clone_from(wire_gen), self.1.clone_from(wire_gen))
    }
}

impl<const N: usize> WiresObject for [BigIntWires; N] {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.iter().flat_map(|bn| bn.to_wires_vec()).collect()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        let mut result = Vec::with_capacity(N);
        for bigint in self {
            result.push(bigint.clone_from(wire_gen));
        }
        result.try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vec_wires_object() {
        let wires = vec![WireId(1), WireId(2), WireId(3)];
        assert_eq!(wires.to_wires_vec(), vec![WireId(1), WireId(2), WireId(3)]);
    }

    #[test]
    fn test_array_wires_object() {
        let array = [WireId(1), WireId(2), WireId(3)];
        assert_eq!(array.to_wires_vec(), vec![WireId(1), WireId(2), WireId(3)]);
        let wires = [WireId(1), WireId(2), WireId(3)];
        assert_eq!(
            <[WireId; 3]>::from_wires(&wires),
            Some([WireId(1), WireId(2), WireId(3)])
        );
    }

    #[test]
    fn test_tuple_wires_object() {
        let tuple = (WireId(1), WireId(2));
        assert_eq!(tuple.to_wires_vec(), vec![WireId(1), WireId(2)]);
        let wires = [WireId(1), WireId(2)];
        assert_eq!(
            <(WireId, WireId)>::from_wires(&wires),
            Some((WireId(1), WireId(2)))
        );
    }
}
