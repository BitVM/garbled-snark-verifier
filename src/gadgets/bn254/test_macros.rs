//! Shared test macros for BN254 field operations
//!
//! This module provides reusable test macro patterns that can be used across
//! all BN254 field types (Fq, Fq2, Fq6, Fq12, Fr) to reduce code duplication
//! and ensure consistent testing patterns.

/// Generic test macro system for field operations
macro_rules! test_field {
    // Unary operation: test_field!(FieldType, unary test_name, FieldType::op, random_fn, |a| expected)
    ($field_type:ident, unary $name:ident, $op:expr, $random_fn:expr, $ark_op:expr) => {
        #[test_log::test]
        fn $name() {
            let mut circuit = Circuit::default();
            let a = $field_type::new(&mut circuit, true, false);
            let c = $op(&mut circuit, &a);
            c.mark_as_output(&mut circuit);

            let a_v = $random_fn();
            let expected = $ark_op(a_v);

            let a_input = $field_type::get_wire_bits_fn(&a, &a_v).unwrap();
            let c_output = $field_type::get_wire_bits_fn(&c, &expected).unwrap();
            circuit
                .simple_evaluate(|wire_id| (a_input)(wire_id))
                .unwrap()
                .for_each(|(wire_id, value)| {
                    assert_eq!((c_output)(wire_id), Some(value));
                });
        }
    };

    // Binary operation: test_field!(FieldType, binary test_name, FieldType::op, random_fn, |a, b| expected)
    ($field_type:ident, binary $name:ident, $op:expr, $random_fn:expr, $ark_op:expr) => {
        #[test_log::test]
        fn $name() {
            let mut circuit = Circuit::default();
            let a = $field_type::new(&mut circuit, true, false);
            let b = $field_type::new(&mut circuit, true, false);
            let c = $op(&mut circuit, &a, &b);
            c.mark_as_output(&mut circuit);

            let a_v = $random_fn();
            let b_v = $random_fn();
            let expected = $ark_op(a_v, b_v);

            let a_input = $field_type::get_wire_bits_fn(&a, &a_v).unwrap();
            let b_input = $field_type::get_wire_bits_fn(&b, &b_v).unwrap();
            let c_output = $field_type::get_wire_bits_fn(&c, &expected).unwrap();

            circuit
                .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
                .unwrap()
                .for_each(|(wire_id, value)| {
                    assert_eq!((c_output)(wire_id), Some(value));
                });
        }
    };

    // Constant operation: test_field!(FieldType, constant test_name, FieldType::op, random_fn, |a, b| expected)
    ($field_type:ident, constant $name:ident, $op:expr, $random_fn:expr, $ark_op:expr) => {
        #[test_log::test]
        fn $name() {
            let mut circuit = Circuit::default();
            let a = $field_type::new(&mut circuit, true, false);
            let b_v = $random_fn();
            let c = $op(&mut circuit, &a, &b_v);
            c.mark_as_output(&mut circuit);

            let a_v = $random_fn();
            let expected = $ark_op(a_v, b_v);

            let a_input = $field_type::get_wire_bits_fn(&a, &a_v).unwrap();
            let c_output = $field_type::get_wire_bits_fn(&c, &expected).unwrap();

            circuit
                .simple_evaluate(|wire_id| (a_input)(wire_id))
                .unwrap()
                .for_each(|(wire_id, value)| {
                    assert_eq!((c_output)(wire_id), Some(value));
                });
        }
    };

    // Montgomery unary operation: test_field!(FieldType, montgomery_unary test_name, FieldType::op, random_fn, as_montgomery_fn, from_montgomery_fn, |a| expected)
    ($field_type:ident, montgomery_unary $name:ident, $op:expr, $random_fn:expr, $as_montgomery:expr, $ark_op:expr) => {
        #[test_log::test]
        fn $name() {
            let mut circuit = Circuit::default();
            let a = $field_type::new(&mut circuit, true, false);
            let c = $op(&mut circuit, &a);
            c.mark_as_output(&mut circuit);

            let a_v = $random_fn();
            let a_mont = $as_montgomery(a_v);
            let expected = $as_montgomery($ark_op(a_v));

            let a_input = $field_type::get_wire_bits_fn(&a, &a_mont).unwrap();
            let c_output = $field_type::get_wire_bits_fn(&c, &expected).unwrap();
            circuit
                .simple_evaluate(|wire_id| (a_input)(wire_id))
                .unwrap()
                .for_each(|(wire_id, value)| {
                    assert_eq!((c_output)(wire_id), Some(value));
                });
        }
    };

    // Montgomery binary operation: test_field!(FieldType, montgomery_binary test_name, FieldType::op, random_fn, as_montgomery_fn, |a, b| expected)
    ($field_type:ident, montgomery_binary $name:ident, $op:expr, $random_fn:expr, $as_montgomery:expr, $ark_op:expr) => {
        #[test_log::test]
        fn $name() {
            let mut circuit = Circuit::default();
            let a = $field_type::new(&mut circuit, true, false);
            let b = $field_type::new(&mut circuit, true, false);
            let c = $op(&mut circuit, &a, &b);
            c.mark_as_output(&mut circuit);

            let a_v = $random_fn();
            let b_v = $random_fn();
            let a_mont = $as_montgomery(a_v);
            let b_mont = $as_montgomery(b_v);
            let expected = $as_montgomery($ark_op(a_v, b_v));

            let a_input = $field_type::get_wire_bits_fn(&a, &a_mont).unwrap();
            let b_input = $field_type::get_wire_bits_fn(&b, &b_mont).unwrap();
            let c_output = $field_type::get_wire_bits_fn(&c, &expected).unwrap();

            circuit
                .simple_evaluate(|wire_id| (a_input)(wire_id).or((b_input)(wire_id)))
                .unwrap()
                .for_each(|(wire_id, value)| {
                    assert_eq!((c_output)(wire_id), Some(value));
                });
        }
    };

    // Property-based test: test_field!(FieldType, property test_name, random_fn, |a, b, c| property)
    ($field_type:ident, property $name:ident, $random_fn:expr, $property:expr) => {
        #[test_log::test]
        fn $name() {
            for _ in 0..10 {
                let a = $random_fn();
                let b = $random_fn();
                let c = $random_fn();
                assert!($property(a, b, c));
            }
        }
    };

    // Montgomery property test: test_field!(FieldType, montgomery_property test_name, random_fn, |a| property)
    ($field_type:ident, montgomery_property $name:ident, $random_fn:expr, $property:expr) => {
        #[test_log::test]
        fn $name() {
            for _ in 0..10 {
                let a = $random_fn();
                assert!($property(a));
            }
        }
    };
}

pub(crate) use test_field;
