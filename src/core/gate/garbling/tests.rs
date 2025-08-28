use super::{super::GateId, *};
use crate::{Delta, EvaluatedWire, GarbledWire, GateType, S, test_utils::trng};

const GATE_ID: GateId = 0;

const TEST_CASES: [(bool, bool); 4] = [(false, false), (false, true), (true, false), (true, true)];

fn garble_consistency(gt: GateType) {
    let delta = Delta::generate(&mut trng());

    #[derive(Debug, PartialEq, Eq)]
    struct FailedCase {
        a_value: bool,
        b_value: bool,
        c_value: bool,
        c: GarbledWire,
        evaluated: S,
        expected: S,
    }
    let mut failed_cases = Vec::new();

    // Create wires with specific LSB patterns
    let mut rng = trng();
    let a_label0 = S::random(&mut rng);
    let b_label0 = S::random(&mut rng);
    let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
    let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

    // Test all combinations of LSB patterns for label0

    // Create bitmask visualization (16 cases total: 2×2×4)
    let mut bitmask = String::with_capacity(16);

    let (ct, c) = garble::<Blake3Hasher>(GATE_ID, gt, &a, &b, &delta);
    let c = GarbledWire::new(c, c ^ &delta);

    for (a_vl, b_vl) in TEST_CASES {
        let evaluated = degarble::<Blake3Hasher>(
            GATE_ID,
            gt,
            &ct,
            &EvaluatedWire::new_from_garbled(&a, a_vl),
            &EvaluatedWire::new_from_garbled(&b, b_vl),
        );

        let expected = EvaluatedWire::new_from_garbled(&c, (gt.f())(a_vl, b_vl)).active_label;

        if evaluated != expected {
            bitmask.push('0');
            failed_cases.push(FailedCase {
                c: c.clone(),
                a_value: a_vl,
                b_value: b_vl,
                c_value: (gt.f())(a_vl, b_vl),
                evaluated,
                expected,
            });
        } else {
            bitmask.push('1');
        }
    }

    let mut error = String::new();
    error.push_str(&format!("{:?}\n", gt.alphas()));
    error.push_str(&format!(
        "Bitmask: {} ({}/4 failed)\n",
        bitmask,
        failed_cases.len()
    ));
    error.push_str("Order: wire_a_lsb0,wire_b_lsb0,a_value,b_value\n");
    for case in failed_cases.iter() {
        error.push_str(&format!("{case:#?}\n"));
    }

    assert_eq!(&failed_cases, &[], "{error}");
}

macro_rules! garble_consistency_tests {
    ($($gate_type:ident => $test_name:ident),*) => {
        $(
            #[test]
            fn $test_name() {
                garble_consistency(GateType::$gate_type);
            }
        )*
    };
}

garble_consistency_tests!(
    And => garble_consistency_and,
    Nand => garble_consistency_nand,
    Nimp => garble_consistency_nimp,
    Imp => garble_consistency_imp,
    Ncimp => garble_consistency_ncimp,
    Cimp => garble_consistency_cimp,
    Nor => garble_consistency_nor,
    Or => garble_consistency_or
);

#[test]
fn test_blake3_hasher() {
    let delta = Delta::generate(&mut trng());
    let mut rng = trng();

    let a_label0 = S::random(&mut rng);
    let b_label0 = S::random(&mut rng);
    let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
    let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

    // Test with Blake3
    let (ct_blake3, _) = garble::<Blake3Hasher>(GATE_ID, GateType::And, &a, &b, &delta);

    // Should produce consistent results
    let (ct_blake3_2, _) = garble::<Blake3Hasher>(GATE_ID, GateType::And, &a, &b, &delta);
    assert_eq!(ct_blake3, ct_blake3_2);
}

#[test]
fn test_aes_ni_hasher() {
    use super::hashers::AesNiHasher;

    let delta = Delta::generate(&mut trng());
    let mut rng = trng();

    let a_label0 = S::random(&mut rng);
    let b_label0 = S::random(&mut rng);
    let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
    let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

    // Test with AES-NI hasher
    let (ct_aes_ni, _) = garble::<AesNiHasher>(GATE_ID, GateType::And, &a, &b, &delta);

    // Should produce consistent results
    let (ct_aes_ni_2, _) = garble::<AesNiHasher>(GATE_ID, GateType::And, &a, &b, &delta);
    assert_eq!(ct_aes_ni, ct_aes_ni_2);
}

#[test]
fn test_aes_ni_hasher_different_gate_ids() {
    use super::hashers::AesNiHasher;

    let delta = Delta::generate(&mut trng());
    let mut rng = trng();

    let a_label0 = S::random(&mut rng);
    let b_label0 = S::random(&mut rng);
    let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
    let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

    // Test with different gate IDs - should produce different results
    let (ct1, _) = garble::<AesNiHasher>(0, GateType::And, &a, &b, &delta);
    let (ct2, _) = garble::<AesNiHasher>(1, GateType::And, &a, &b, &delta);
    let (ct3, _) = garble::<AesNiHasher>(1000, GateType::And, &a, &b, &delta);

    // All should be different due to different gate IDs (used as keys)
    assert_ne!(ct1, ct2);
    assert_ne!(ct2, ct3);
    assert_ne!(ct1, ct3);
}

fn aes_ni_garble_consistency(gt: GateType) {
    use super::hashers::AesNiHasher;

    let delta = Delta::generate(&mut trng());

    #[derive(Debug, PartialEq, Eq)]
    struct FailedCase {
        a_value: bool,
        b_value: bool,
        c_value: bool,
        c: GarbledWire,
        evaluated: S,
        expected: S,
    }
    let mut failed_cases = Vec::new();

    // Create wires with specific LSB patterns
    let mut rng = trng();
    let a_label0 = S::random(&mut rng);
    let b_label0 = S::random(&mut rng);
    let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
    let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

    // Test all combinations of LSB patterns for label0

    // Create bitmask visualization (16 cases total: 2×2×4)
    let mut bitmask = String::with_capacity(16);

    let (ct, c) = garble::<AesNiHasher>(GATE_ID, gt, &a, &b, &delta);
    let c = GarbledWire::new(c, c ^ &delta);

    for (a_vl, b_vl) in TEST_CASES {
        let evaluated = degarble::<AesNiHasher>(
            GATE_ID,
            gt,
            &ct,
            &EvaluatedWire::new_from_garbled(&a, a_vl),
            &EvaluatedWire::new_from_garbled(&b, b_vl),
        );

        let expected = EvaluatedWire::new_from_garbled(&c, (gt.f())(a_vl, b_vl)).active_label;

        if evaluated != expected {
            bitmask.push('0');
            failed_cases.push(FailedCase {
                c: c.clone(),
                a_value: a_vl,
                b_value: b_vl,
                c_value: (gt.f())(a_vl, b_vl),
                evaluated,
                expected,
            });
        } else {
            bitmask.push('1');
        }
    }

    let mut error = String::new();
    error.push_str(&format!("{:?}\n", gt.alphas()));
    error.push_str(&format!(
        "AES-NI Bitmask: {} ({}/4 failed)\n",
        bitmask,
        failed_cases.len()
    ));
    error.push_str("Order: wire_a_lsb0,wire_b_lsb0,a_value,b_value\n");
    for case in failed_cases.iter() {
        error.push_str(&format!("{case:#?}\n"));
    }

    assert_eq!(&failed_cases, &[], "{error}");
}

macro_rules! aes_ni_garble_consistency_tests {
    ($($gate_type:ident => $test_name:ident),*) => {
        $(
            #[test]
            fn $test_name() {
                aes_ni_garble_consistency(GateType::$gate_type);
            }
        )*
    };
}

aes_ni_garble_consistency_tests!(
    And => aes_ni_garble_consistency_and,
    Nand => aes_ni_garble_consistency_nand,
    Nimp => aes_ni_garble_consistency_nimp,
    Imp => aes_ni_garble_consistency_imp,
    Ncimp => aes_ni_garble_consistency_ncimp,
    Cimp => aes_ni_garble_consistency_cimp,
    Nor => aes_ni_garble_consistency_nor,
    Or => aes_ni_garble_consistency_or
);
