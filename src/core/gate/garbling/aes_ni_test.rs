//! Focused AES-NI garble/degarble test module
//!
//! This module contains specific tests for AES-NI hash function implementation
//! in garbled circuit construction and evaluation.

#[cfg(test)]
mod aes_ni_focused_tests {
    use super::super::{GateId, GateType, degarble, garble, hashers::AesNiHasher};
    use crate::{Delta, EvaluatedWire, GarbledWire, S, test_utils::trng};

    /// Test AES-NI hasher with known gate ID and wire values
    #[test]
    fn test_aes_ni_garble_degarble_known_values() {
        // Use fixed gate ID for reproducible testing
        const TEST_GATE_ID: GateId = 0x12345678;
        let gate_type = GateType::And;

        let delta = Delta::generate(&mut trng());
        let mut rng = trng();

        // Create test wires with known patterns
        let a_label0 = S::random(&mut rng);
        let b_label0 = S::random(&mut rng);
        let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
        let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

        // Garble with AES-NI hasher
        let (ciphertext, c_wire) = garble::<AesNiHasher>(TEST_GATE_ID, gate_type, &a, &b, &delta);
        let c = GarbledWire::new(c_wire, c_wire ^ &delta);

        println!("🔧 AES-NI Garble Test:");
        println!("  Gate ID: 0x{:X}", TEST_GATE_ID);
        println!("  Gate Type: {:?}", gate_type);
        println!("  Ciphertext: {:?}", ciphertext);

        // Test all input combinations
        let test_cases = [
            (false, false, false), // AND(0,0) = 0
            (false, true, false),  // AND(0,1) = 0
            (true, false, false),  // AND(1,0) = 0
            (true, true, true),    // AND(1,1) = 1
        ];

        for (i, (a_val, b_val, expected_c_val)) in test_cases.iter().enumerate() {
            println!(
                "  Test case {}: AND({}, {}) = {}",
                i + 1,
                a_val,
                b_val,
                expected_c_val
            );

            // Create evaluated wires
            let eval_a = EvaluatedWire::new_from_garbled(&a, *a_val);
            let eval_b = EvaluatedWire::new_from_garbled(&b, *b_val);

            // Degarble with AES-NI hasher
            let result_label =
                degarble::<AesNiHasher>(TEST_GATE_ID, gate_type, &ciphertext, &eval_a, &eval_b);

            // Get expected label
            let expected_label = EvaluatedWire::new_from_garbled(&c, *expected_c_val).active_label;

            println!("    Result:   {:?}", result_label);
            println!("    Expected: {:?}", expected_label);
            println!("    Match: {}", result_label == expected_label);

            assert_eq!(
                result_label, expected_label,
                "AES-NI degarble failed for inputs ({}, {})",
                a_val, b_val
            );
        }

        println!("✅ AES-NI Garble/Degarble test passed!");
    }

    /// Test AES-NI hasher performance comparison with different gate IDs
    #[test]
    fn test_aes_ni_different_gate_ids() {
        let delta = Delta::generate(&mut trng());
        let mut rng = trng();

        let a_label0 = S::random(&mut rng);
        let b_label0 = S::random(&mut rng);
        let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
        let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

        // Test with different gate IDs to ensure proper domain separation
        let gate_ids = [0, 1, 0xFF, 0x1234, 0xDEADBEEF];
        let mut ciphertexts = Vec::new();

        println!("🔧 AES-NI Gate ID Domain Separation Test:");

        for &gate_id in &gate_ids {
            let (ct, _) = garble::<AesNiHasher>(gate_id, GateType::And, &a, &b, &delta);
            ciphertexts.push((gate_id, ct));
            println!("  Gate ID: 0x{:X} -> Ciphertext: {:?}", gate_id, ct);
        }

        // Verify all ciphertexts are different (domain separation working)
        for (i, (id1, ct1)) in ciphertexts.iter().enumerate() {
            for (id2, ct2) in ciphertexts.iter().skip(i + 1) {
                assert_ne!(
                    ct1, ct2,
                    "Gate IDs 0x{:X} and 0x{:X} produced identical ciphertexts! Domain separation failed.",
                    id1, id2
                );
            }
        }

        println!("✅ AES-NI domain separation test passed!");
    }

    /// Test AES-NI hasher with multiple gate types
    #[test]
    fn test_aes_ni_all_gate_types() {
        let delta = Delta::generate(&mut trng());
        let mut rng = trng();

        let a_label0 = S::random(&mut rng);
        let b_label0 = S::random(&mut rng);
        let a = GarbledWire::new(a_label0, a_label0 ^ &delta);
        let b = GarbledWire::new(b_label0, b_label0 ^ &delta);

        let gate_types = [
            GateType::And,
            GateType::Nand,
            GateType::Or,
            GateType::Nor,
            GateType::Imp,
            GateType::Nimp,
            GateType::Cimp,
            GateType::Ncimp,
        ];

        println!("🔧 AES-NI All Gate Types Test:");

        for gate_type in gate_types {
            println!("  Testing gate type: {:?}", gate_type);

            let (ct, c_wire) = garble::<AesNiHasher>(0, gate_type, &a, &b, &delta);
            let c = GarbledWire::new(c_wire, c_wire ^ &delta);

            // Test one case to verify basic functionality
            let eval_a = EvaluatedWire::new_from_garbled(&a, true);
            let eval_b = EvaluatedWire::new_from_garbled(&b, true);

            let result_label = degarble::<AesNiHasher>(0, gate_type, &ct, &eval_a, &eval_b);
            let expected_output = (gate_type.f())(true, true);
            let expected_label = EvaluatedWire::new_from_garbled(&c, expected_output).active_label;

            assert_eq!(
                result_label, expected_label,
                "AES-NI failed for gate type {:?}",
                gate_type
            );

            println!("    ✅ Gate {:?} passed", gate_type);
        }

        println!("✅ AES-NI all gate types test passed!");
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "aes",
        target_feature = "sse2"
    ))]
    #[test]
    fn test_aes_ni_compile_time_and_runtime_support() {
        println!("🔧 AES-NI Compile-Time & Runtime Support Test:");
        println!("  ✅ AES-NI target feature enabled at compile time");
        println!("  ✅ SSE2 target feature enabled at compile time");

        if is_x86_feature_detected!("aes") {
            println!("  ✅ AES-NI instructions detected at runtime");

            // Test the actual AES-NI implementation
            use super::super::aes_ni::aes128_encrypt_block;
            let key = [0u8; 16];
            let plaintext = [0u8; 16];

            let result = aes128_encrypt_block(key, plaintext);
            assert!(
                result.is_some(),
                "AES-NI encryption should work when both compile-time and runtime support available"
            );
            println!("  ✅ AES-NI encryption successful");
        } else {
            panic!(
                "Runtime AES-NI detection failed despite compile-time target feature being enabled"
            );
        }
    }

    // No fallback mode test: AesNiHasher is unavailable without AES-NI and should not be used.

    // Additional coverage to exercise AES-NI helpers considered "unused" by clippy
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "aes",
        target_feature = "sse2"
    ))]
    #[test]
    fn test_aes_ni_dual_lane_and_xor_variants() {
        use super::super::aes_ni::{
            Aes128, aes128_encrypt_block, aes128_encrypt_block_static,
            aes128_encrypt_block_static_xor, aes128_encrypt2_blocks, aes128_encrypt2_blocks_static,
            aes128_encrypt2_blocks_static_xor,
        };

        // Known key and blocks for deterministic assertions
        let key = [0x11u8; 16];
        let b0 = [0x22u8; 16];
        let b1 = [0x33u8; 16];
        let mask = [0xAAu8; 16];

        // Aes128::new and dual-lane encrypt should work and match two single-block encrypts
        let cipher = Aes128::new(key).expect("AES-NI required");
        let c0_single = unsafe { cipher.encrypt_block(b0) };
        let c1_single = unsafe { cipher.encrypt_block(b1) };
        let (c0_dual, c1_dual) = unsafe { cipher.encrypt2_blocks(b0, b1) };
        assert_eq!(c0_single, c0_dual);
        assert_eq!(c1_single, c1_dual);

        // encrypt_block_xor is equivalent to encrypting (block XOR mask)
        let bx = array_xor(b0, mask);
        let cy_expected = unsafe { cipher.encrypt_block(bx) };
        let cy_xor = unsafe { cipher.encrypt_block_xor(b0, mask) };
        assert_eq!(cy_expected, cy_xor);

        // encrypt2_blocks_xor matches per-lane encrypt of (block XOR mask)
        let b0x = array_xor(b0, mask);
        let b1x = array_xor(b1, mask);
        let (d0_expected, d1_expected) = (unsafe { cipher.encrypt_block(b0x) }, unsafe {
            cipher.encrypt_block(b1x)
        });
        let (d0, d1) = unsafe { cipher.encrypt2_blocks_xor(b0, b1, mask) };
        assert_eq!(d0_expected, d0);
        assert_eq!(d1_expected, d1);

        // Public helpers are exercised as well
        let _ = aes128_encrypt_block(key, b0).expect("AES-NI required");
        let _ = aes128_encrypt2_blocks(key, b0, b1).expect("AES-NI required");
        let _ = aes128_encrypt_block_static(b0).expect("AES-NI required");
        let _ = aes128_encrypt2_blocks_static(b0, b1).expect("AES-NI required");
        let _ = aes128_encrypt_block_static_xor(b0, mask).expect("AES-NI required");
        let _ = aes128_encrypt2_blocks_static_xor(b0, b1, mask).expect("AES-NI required");
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "aes",
        target_feature = "sse2"
    ))]
    #[inline]
    fn array_xor(mut a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
        for i in 0..16 {
            a[i] ^= b[i];
        }
        a
    }
}
