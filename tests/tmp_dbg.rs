// Integration test to print a single deterministic AES-based hash and then panic.
// Purpose: run this test with different RUSTFLAGS to compare hardware vs fallback
// implementations and verify the printed hash is identical.

use garbled_snark_verifier::{AesNiHasher, GateHasher, S};

// Mark ignored so it never runs in CI by default.
#[test]
#[ignore]
fn tmp_dbg_hash_print() {
    // Fixed input label bytes (big-endian inside S): 00..0F
    let label = S::from_bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ]);

    // Fixed gate id to act as tweak in AesNiHasher
    let gate_id = 0x12_34_56_78usize;

    // Compute single-lane AES hash used by garbling/degarbling
    let h = AesNiHasher::hash_for_degarbling(&label, gate_id);

    // Print in hex. Because the test deliberately panics, stdout is always shown.
    let compiled_hw_aes = cfg!(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "aes",
        target_feature = "sse2"
    ));
    println!(
        "tmp-dbg compiled_hw_aes={}, aes hash (label=000102..0f, gate_id=0x12345678): {}",
        compiled_hw_aes,
        h.to_hex()
    );

    // Always panic so output is visible without --nocapture and to keep this test opt-in only.
    panic!("tmp-dbg done");
}
