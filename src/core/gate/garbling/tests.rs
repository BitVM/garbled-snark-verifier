use super::super::GateId;
use super::*;
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
