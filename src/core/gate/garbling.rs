use digest::Digest;

use super::{GateId, GateType};
use crate::{Delta, EvaluatedWire, GarbledWire, S, core::s::S_SIZE};

/// Generic hash function with unique tweak per gate using any digest implementation
fn hash_gate_with_tweak<D: Digest + Default>(x: &S, tweak: GateId) -> S {
    assert!(<D as Digest>::output_size() >= S_SIZE);
    let mut result = [0u8; S_SIZE];

    let hash_output = D::default()
        .chain_update(x.0)
        .chain_update(tweak.to_le_bytes())
        .finalize();
    
    result.copy_from_slice(&hash_output[..S_SIZE]);

    S(result)
}

pub(super) fn garble<H: digest::Digest + Default + Clone>(
    gate_id: GateId,
    gate_type: GateType,
    a: &GarbledWire,
    b: &GarbledWire,
    delta: &Delta,
) -> (S, S) {
    let (alpha_a, alpha_b, alpha_c) = gate_type.alphas();

    let h_a0 = hash_gate_with_tweak::<H>(&a.select(alpha_a), gate_id);
    let h_a1 = hash_gate_with_tweak::<H>(&a.select(!alpha_a), gate_id);

    let ct = h_a0 ^ &h_a1 ^ &b.select(alpha_b);

    let w = if alpha_c { h_a0 ^ delta } else { h_a0 };

    (ct, w)
}

pub(super) fn degarble<H: digest::Digest + Default + Clone>(
    gate_id: GateId,
    gate_type: GateType,
    ciphertext: &S,
    a: &EvaluatedWire,
    b: &EvaluatedWire,
) -> S {
    let h_a = hash_gate_with_tweak::<H>(&a.active_label, gate_id);

    let (alpha_a, _alpha_b, _alpha_c) = gate_type.alphas();

    if a.value() != alpha_a {
        ciphertext ^ &h_a ^ &b.active_label
    } else {
        h_a // h_a0
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{Delta, GarbledWire, GateType, S, core::gate::GateId, test_utils::trng};

    const GATE_ID: GateId = 0;

    const TEST_CASES: [(bool, bool); 4] =
        [(false, false), (false, true), (true, false), (true, true)];

    fn garble_consistency(gt: GateType) {
        let delta = Delta::generate();

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

        let (ct, c) = garble::<blake3::Hasher>(GATE_ID, gt, &a, &b, &delta);
        let c = GarbledWire::new(c, c ^ &delta);

        for (a_vl, b_vl) in TEST_CASES {
            let evaluated = degarble::<blake3::Hasher>(
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
    fn test_different_hash_functions() {
        use sha2::Sha256;

        let delta = Delta::generate();
        let mut rng = trng();

        let a_label0 = S::random(&mut rng);
        let b_label0 = S::random(&mut rng);
        let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
        let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

        // Test with Blake3
        let (ct_blake3, _) = garble::<blake3::Hasher>(GATE_ID, GateType::And, &a, &b, &delta);

        // Test with SHA256
        let (ct_sha256, _) = garble::<Sha256>(GATE_ID, GateType::And, &a, &b, &delta);

        // Different hash functions should produce different ciphertexts
        assert_ne!(ct_blake3, ct_sha256);
    }
}
