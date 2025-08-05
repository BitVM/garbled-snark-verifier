#![allow(non_snake_case)]
use crate::WireId;

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

impl IntoWireList for &[WireId] {
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
