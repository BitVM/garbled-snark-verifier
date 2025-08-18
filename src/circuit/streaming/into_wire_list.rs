#![allow(non_snake_case)]
use crate::{
    WireId,
    gadgets::{
        bigint::BigIntWires,
        bn254::{Fq, Fq12, G1Projective, G2Projective, fq2::Fq2, fq6::Fq6, fr::Fr},
    },
};

/// Trait for types that can be converted into a list of wire IDs.
/// This trait is used by the `#[component]` procedural macro to automatically
/// collect function parameters into input wire lists.
pub trait IntoWireList {
    fn into_wire_list(self) -> Vec<WireId>;
}

impl IntoWireList for WireId {
    fn into_wire_list(self) -> Vec<WireId> {
        vec![self]
    }
}

impl IntoWireList for &WireId {
    fn into_wire_list(self) -> Vec<WireId> {
        vec![*self]
    }
}

impl IntoWireList for Vec<WireId> {
    fn into_wire_list(self) -> Vec<WireId> {
        self
    }
}

impl IntoWireList for &Vec<WireId> {
    fn into_wire_list(self) -> Vec<WireId> {
        self.to_vec()
    }
}

impl<const N: usize> IntoWireList for [WireId; N] {
    fn into_wire_list(self) -> Vec<WireId> {
        self.to_vec()
    }
}

impl<const N: usize> IntoWireList for &[WireId; N] {
    fn into_wire_list(self) -> Vec<WireId> {
        self.to_vec()
    }
}

impl<T: Clone + IntoWireList> IntoWireList for &[T] {
    fn into_wire_list(self) -> Vec<WireId> {
        self.iter()
            .cloned()
            .flat_map(|t| t.into_wire_list())
            .collect()
    }
}

/// Macro to generate IntoWireList implementations for tuples up to 16 elements.
/// This supports both owned and borrowed tuples with nested combinations.
macro_rules! impl_tuple {
    // Base case: single element tuple
    ($($T:ident),+) => {
        impl<$($T: IntoWireList),+> IntoWireList for ($($T,)+) {
            fn into_wire_list(self) -> Vec<WireId> {
                let ($($T,)+) = self;
                let mut result = Vec::new();
                $(
                    result.extend($T.into_wire_list());
                )+
                result
            }
        }

        impl<$($T: IntoWireList + Clone),+> IntoWireList for &($($T,)+) {
            fn into_wire_list(self) -> Vec<WireId> {
                let ($($T,)+) = self;
                let mut result = Vec::new();
                $(
                    result.extend($T.clone().into_wire_list());
                )+
                result
            }
        }
    };
}

// Generate implementations for tuples of size 1 to 16
impl_tuple!(T1);
impl_tuple!(T1, T2);
impl_tuple!(T1, T2, T3);
impl_tuple!(T1, T2, T3, T4);
impl_tuple!(T1, T2, T3, T4, T5);
impl_tuple!(T1, T2, T3, T4, T5, T6);
impl_tuple!(T1, T2, T3, T4, T5, T6, T7);
impl_tuple!(T1, T2, T3, T4, T5, T6, T7, T8);
impl_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9);
impl_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10);
impl_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11);
impl_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12);
impl_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13);
impl_tuple!(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14);
impl_tuple!(
    T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15
);
impl_tuple!(
    T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16
);

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
    const ARITY: usize = 254;
}

impl WiresArity for Fr {
    const ARITY: usize = 254;
}

impl WiresArity for Fq2 {
    const ARITY: usize = 508; // 2 * 254
}

impl WiresArity for Fq6 {
    const ARITY: usize = 1524; // 3 * 508
}

impl WiresArity for Fq12 {
    const ARITY: usize = 3048; // 2 * 1524
}

impl WiresArity for G1Projective {
    const ARITY: usize = 762; // 3 * 254
}

impl WiresArity for G2Projective {
    const ARITY: usize = 1524; // 3 * 508
}

pub trait WiresObject: Sized {
    fn get_wires_vec(&self) -> Vec<WireId>;

    fn from_wires(wires: &[WireId]) -> Option<Self>;
}

impl WiresObject for WireId {
    fn get_wires_vec(&self) -> Vec<WireId> {
        vec![*self]
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        match wires {
            [wire_id] => Some(*wire_id),
            _ => None,
        }
    }
}

impl WiresObject for BigIntWires {
    fn get_wires_vec(&self) -> Vec<WireId> {
        self.iter().copied().collect()
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        Some(BigIntWires::from_bits(wires.iter().copied()))
    }
}

impl WiresObject for Vec<WireId> {
    fn get_wires_vec(&self) -> Vec<WireId> {
        self.clone()
    }

    fn from_wires(wires: &[WireId]) -> Option<Self> {
        Some(wires.to_vec())
    }
}

impl WiresObject for (BigIntWires, BigIntWires) {
    fn get_wires_vec(&self) -> Vec<WireId> {
        self.0
            .get_wires_vec()
            .into_iter()
            .chain(self.1.get_wires_vec())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_id_conversion() {
        let wire = WireId(42);
        assert_eq!(wire.into_wire_list(), vec![WireId(42)]);
    }

    #[test]
    fn test_wire_id_ref_conversion() {
        let wire = WireId(42);
        assert_eq!((&wire).into_wire_list(), vec![WireId(42)]);
    }

    #[test]
    fn test_tuple_conversion() {
        let tuple = (WireId(1), WireId(2), WireId(3));
        assert_eq!(
            tuple.into_wire_list(),
            vec![WireId(1), WireId(2), WireId(3)]
        );
    }

    #[test]
    fn test_nested_tuple_conversion() {
        let nested = ((WireId(1), WireId(2)), WireId(3));
        assert_eq!(
            nested.into_wire_list(),
            vec![WireId(1), WireId(2), WireId(3)]
        );
    }

    #[test]
    fn test_mixed_types() {
        let mixed = (WireId(1), vec![WireId(2), WireId(3)], WireId(4));
        assert_eq!(
            mixed.into_wire_list(),
            vec![WireId(1), WireId(2), WireId(3), WireId(4)]
        );
    }

    #[test]
    fn test_sixteen_elements() {
        let sixteen = (
            WireId(1),
            WireId(2),
            WireId(3),
            WireId(4),
            WireId(5),
            WireId(6),
            WireId(7),
            WireId(8),
            WireId(9),
            WireId(10),
            WireId(11),
            WireId(12),
            WireId(13),
            WireId(14),
            WireId(15),
            WireId(16),
        );
        let expected: Vec<WireId> = (1..=16).map(WireId).collect();
        assert_eq!(sixteen.into_wire_list(), expected);
    }
}
