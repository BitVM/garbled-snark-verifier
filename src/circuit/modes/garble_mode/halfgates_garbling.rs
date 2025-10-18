use super::*;
use crate::{
    GateType,
    hashers::{GateHasher, aes_ni, to_tweak},
};

#[inline(always)]
pub fn garble_gate<H: GateHasher>(
    gate_type: GateType,
    a_label0: S,
    b_label0: S,
    delta: &Delta,
    gate_id: usize,
) -> (S, Option<S>) {
    match gate_type {
        GateType::Xor => (a_label0 ^ &b_label0, None),
        GateType::Xnor => (a_label0 ^ &b_label0 ^ delta, None),
        GateType::Not => (a_label0 ^ delta, None),
        _ => {
            // Use const alphas mapping to avoid runtime truth-table work
            let (alpha_a, alpha_b, alpha_c) = gate_type.alphas_const();

            let (selected_a, other_a) = if alpha_a {
                (a_label0 ^ delta, a_label0)
            } else {
                (a_label0, a_label0 ^ delta)
            };

            let [h_a0, h_a1] = H::hash_with_gate(&[selected_a, other_a], gate_id);

            let b_sel = if alpha_b { b_label0 ^ delta } else { b_label0 };

            let ct = h_a0 ^ &h_a1 ^ &b_sel;

            let w0 = if alpha_c { h_a0 ^ delta } else { h_a0 };

            (w0, Some(ct))
        }
    }
}

#[inline(always)]
pub fn garble_gate_batch<const N: usize>(
    gate_type: GateType,
    a_label0: [S; N],
    b_label0: [S; N],
    deltas: &[Delta; N],
    gate_id: usize,
) -> ([S; N], Option<[S; N]>) {
    match gate_type {
        GateType::Xor => {
            let mut c = [S::ZERO; N];
            for i in 0..N {
                c[i] = a_label0[i] ^ &b_label0[i];
            }
            (c, None)
        }
        GateType::Xnor => {
            let mut c = [S::ZERO; N];
            for i in 0..N {
                c[i] = a_label0[i] ^ &b_label0[i] ^ &deltas[i];
            }
            (c, None)
        }
        GateType::Not => {
            let mut c = [S::ZERO; N];
            for i in 0..N {
                c[i] = a_label0[i] ^ &deltas[i];
            }
            (c, None)
        }
        _ => {
            let (alpha_a, alpha_b, alpha_c) = gate_type.alphas_const();
            let tweak = to_tweak(gate_id);

            let mut h_sel = [S::ZERO; N];
            let mut h_oth = [S::ZERO; N];

            match N {
                16 => {
                    let mut blocks1 = [[0u8; 16]; 16];
                    let mut blocks2 = [[0u8; 16]; 16];
                    for k in 0..8 {
                        let a = if alpha_a {
                            a_label0[k] ^ &deltas[k]
                        } else {
                            a_label0[k]
                        };
                        let o = if alpha_a {
                            a_label0[k]
                        } else {
                            a_label0[k] ^ &deltas[k]
                        };
                        blocks1[k * 2] = a.to_bytes();
                        blocks1[k * 2 + 1] = o.to_bytes();
                    }
                    for k in 8..16 {
                        let a = if alpha_a {
                            a_label0[k] ^ &deltas[k]
                        } else {
                            a_label0[k]
                        };
                        let o = if alpha_a {
                            a_label0[k]
                        } else {
                            a_label0[k] ^ &deltas[k]
                        };
                        blocks2[(k - 8) * 2] = a.to_bytes();
                        blocks2[(k - 8) * 2 + 1] = o.to_bytes();
                    }
                    let out1 = aes_ni::aes128_encrypt16_blocks_static_xor(blocks1, tweak).unwrap();
                    let out2 = aes_ni::aes128_encrypt16_blocks_static_xor(blocks2, tweak).unwrap();
                    for k in 0..8 {
                        h_sel[k] = S::from_bytes(out1[k * 2]);
                        h_oth[k] = S::from_bytes(out1[k * 2 + 1]);
                    }
                    for k in 8..16 {
                        h_sel[k] = S::from_bytes(out2[(k - 8) * 2]);
                        h_oth[k] = S::from_bytes(out2[(k - 8) * 2 + 1]);
                    }
                }
                8 => {
                    let mut blocks = [[0u8; 16]; 16];
                    for k in 0..8 {
                        let a = if alpha_a {
                            a_label0[k] ^ &deltas[k]
                        } else {
                            a_label0[k]
                        };
                        let o = if alpha_a {
                            a_label0[k]
                        } else {
                            a_label0[k] ^ &deltas[k]
                        };
                        blocks[k * 2] = a.to_bytes();
                        blocks[k * 2 + 1] = o.to_bytes();
                    }
                    let out = aes_ni::aes128_encrypt16_blocks_static_xor(blocks, tweak).unwrap();
                    for k in 0..8 {
                        h_sel[k] = S::from_bytes(out[k * 2]);
                        h_oth[k] = S::from_bytes(out[k * 2 + 1]);
                    }
                }
                4 => {
                    let mut blocks = [[0u8; 16]; 8];
                    for k in 0..4 {
                        let a = if alpha_a {
                            a_label0[k] ^ &deltas[k]
                        } else {
                            a_label0[k]
                        };
                        let o = if alpha_a {
                            a_label0[k]
                        } else {
                            a_label0[k] ^ &deltas[k]
                        };
                        blocks[k * 2] = a.to_bytes();
                        blocks[k * 2 + 1] = o.to_bytes();
                    }
                    let out = aes_ni::aes128_encrypt8_blocks_static_xor(blocks, tweak).unwrap();
                    for k in 0..4 {
                        h_sel[k] = S::from_bytes(out[k * 2]);
                        h_oth[k] = S::from_bytes(out[k * 2 + 1]);
                    }
                }
                2 => {
                    let mut blocks = [[0u8; 16]; 4];
                    for k in 0..2 {
                        let a = if alpha_a {
                            a_label0[k] ^ &deltas[k]
                        } else {
                            a_label0[k]
                        };
                        let o = if alpha_a {
                            a_label0[k]
                        } else {
                            a_label0[k] ^ &deltas[k]
                        };
                        blocks[k * 2] = a.to_bytes();
                        blocks[k * 2 + 1] = o.to_bytes();
                    }
                    let out = aes_ni::aes128_encrypt4_blocks_static_xor(blocks, tweak).unwrap();
                    for k in 0..2 {
                        h_sel[k] = S::from_bytes(out[k * 2]);
                        h_oth[k] = S::from_bytes(out[k * 2 + 1]);
                    }
                }
                _ => {
                    let mut i = 0usize;
                    while i + 16 <= N {
                        let mut blocks1 = [[0u8; 16]; 16];
                        let mut blocks2 = [[0u8; 16]; 16];
                        for k in 0..8 {
                            let idx = i + k;
                            let a = if alpha_a {
                                a_label0[idx] ^ &deltas[idx]
                            } else {
                                a_label0[idx]
                            };
                            let o = if alpha_a {
                                a_label0[idx]
                            } else {
                                a_label0[idx] ^ &deltas[idx]
                            };
                            blocks1[k * 2] = a.to_bytes();
                            blocks1[k * 2 + 1] = o.to_bytes();
                        }
                        for k in 8..16 {
                            let idx = i + k;
                            let a = if alpha_a {
                                a_label0[idx] ^ &deltas[idx]
                            } else {
                                a_label0[idx]
                            };
                            let o = if alpha_a {
                                a_label0[idx]
                            } else {
                                a_label0[idx] ^ &deltas[idx]
                            };
                            blocks2[(k - 8) * 2] = a.to_bytes();
                            blocks2[(k - 8) * 2 + 1] = o.to_bytes();
                        }
                        let out1 =
                            aes_ni::aes128_encrypt16_blocks_static_xor(blocks1, tweak).unwrap();
                        let out2 =
                            aes_ni::aes128_encrypt16_blocks_static_xor(blocks2, tweak).unwrap();
                        for k in 0..8 {
                            h_sel[i + k] = S::from_bytes(out1[k * 2]);
                            h_oth[i + k] = S::from_bytes(out1[k * 2 + 1]);
                        }
                        for k in 8..16 {
                            h_sel[i + k] = S::from_bytes(out2[(k - 8) * 2]);
                            h_oth[i + k] = S::from_bytes(out2[(k - 8) * 2 + 1]);
                        }
                        i += 16;
                    }
                    while i + 8 <= N {
                        let mut blocks = [[0u8; 16]; 16];
                        for k in 0..8 {
                            let idx = i + k;
                            let a = if alpha_a {
                                a_label0[idx] ^ &deltas[idx]
                            } else {
                                a_label0[idx]
                            };
                            let o = if alpha_a {
                                a_label0[idx]
                            } else {
                                a_label0[idx] ^ &deltas[idx]
                            };
                            blocks[k * 2] = a.to_bytes();
                            blocks[k * 2 + 1] = o.to_bytes();
                        }
                        let out =
                            aes_ni::aes128_encrypt16_blocks_static_xor(blocks, tweak).unwrap();
                        for k in 0..8 {
                            h_sel[i + k] = S::from_bytes(out[k * 2]);
                            h_oth[i + k] = S::from_bytes(out[k * 2 + 1]);
                        }
                        i += 8;
                    }
                    while i + 4 <= N {
                        let mut blocks = [[0u8; 16]; 8];
                        for k in 0..4 {
                            let idx = i + k;
                            let a = if alpha_a {
                                a_label0[idx] ^ &deltas[idx]
                            } else {
                                a_label0[idx]
                            };
                            let o = if alpha_a {
                                a_label0[idx]
                            } else {
                                a_label0[idx] ^ &deltas[idx]
                            };
                            blocks[k * 2] = a.to_bytes();
                            blocks[k * 2 + 1] = o.to_bytes();
                        }
                        let out = aes_ni::aes128_encrypt8_blocks_static_xor(blocks, tweak).unwrap();
                        for k in 0..4 {
                            h_sel[i + k] = S::from_bytes(out[k * 2]);
                            h_oth[i + k] = S::from_bytes(out[k * 2 + 1]);
                        }
                        i += 4;
                    }
                    while i + 2 <= N {
                        let mut blocks = [[0u8; 16]; 4];
                        for k in 0..2 {
                            let idx = i + k;
                            let a = if alpha_a {
                                a_label0[idx] ^ &deltas[idx]
                            } else {
                                a_label0[idx]
                            };
                            let o = if alpha_a {
                                a_label0[idx]
                            } else {
                                a_label0[idx] ^ &deltas[idx]
                            };
                            blocks[k * 2] = a.to_bytes();
                            blocks[k * 2 + 1] = o.to_bytes();
                        }
                        let out = aes_ni::aes128_encrypt4_blocks_static_xor(blocks, tweak).unwrap();
                        for k in 0..2 {
                            h_sel[i + k] = S::from_bytes(out[k * 2]);
                            h_oth[i + k] = S::from_bytes(out[k * 2 + 1]);
                        }
                        i += 2;
                    }
                    if i < N {
                        let a = if alpha_a {
                            a_label0[i] ^ &deltas[i]
                        } else {
                            a_label0[i]
                        };
                        let o = if alpha_a {
                            a_label0[i]
                        } else {
                            a_label0[i] ^ &deltas[i]
                        };
                        let (s0, t0) = aes_ni::aes128_encrypt2_blocks_static_xor(
                            a.to_bytes(),
                            o.to_bytes(),
                            tweak,
                        )
                        .unwrap();
                        h_sel[i] = S::from_bytes(s0);
                        h_oth[i] = S::from_bytes(t0);
                    }
                }
            }

            let mut w0 = [S::ZERO; N];
            let mut ct = [S::ZERO; N];
            for i in 0..N {
                let b_sel = if alpha_b {
                    b_label0[i] ^ &deltas[i]
                } else {
                    b_label0[i]
                };
                ct[i] = h_sel[i] ^ &h_oth[i] ^ &b_sel;
                w0[i] = if alpha_c {
                    h_sel[i] ^ &deltas[i]
                } else {
                    h_sel[i]
                };
            }

            (w0, Some(ct))
        }
    }
}

#[inline(always)]
pub fn degarble_gate<H: GateHasher>(
    gate_type: GateType,
    lazy_ciphertext: impl FnOnce() -> S,
    a_active_label: S,
    a_value: bool,
    b_active_label: S,
    gate_id: usize,
) -> S {
    match gate_type {
        GateType::Xor => a_active_label ^ &b_active_label,
        GateType::Xnor => a_active_label ^ &b_active_label,
        GateType::Not => {
            // For NOT gates, all wires are the same, so return the input
            a_active_label
        }
        _ => {
            let ct = lazy_ciphertext();
            let [h_a] = H::hash_with_gate(&[a_active_label], gate_id);

            let (alpha_a, _alpha_b, _alpha_c) = gate_type.alphas_const();

            if a_value != alpha_a {
                ct ^ &h_a ^ &b_active_label
            } else {
                h_a
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{degarble_gate, garble_gate};
    use crate::{AesNiHasher, Blake3Hasher, Delta, GateHasher, GateType, S, test_utils::trng};

    const GATE_ID: usize = 0;

    const TEST_CASES: [(bool, bool); 4] =
        [(false, false), (false, true), (true, false), (true, true)];

    fn garble_consistency<H: GateHasher>(gt: GateType) {
        let mut rng = trng();
        let delta = Delta::generate(&mut rng);

        #[derive(Debug, PartialEq, Eq)]
        struct FailedCase {
            a_value: bool,
            b_value: bool,
            c_value: bool,
            c_label0: S,
            c_label1: S,
            evaluated: S,
            expected: S,
        }
        let mut failed_cases = Vec::new();

        // Create wires with specific LSB patterns
        let a_label0 = S::random(&mut rng);
        let b_label0 = S::random(&mut rng);

        // Test all combinations of LSB patterns for label0

        // Create bitmask visualization (16 cases total: 2×2×4)
        let mut bitmask = String::with_capacity(16);

        let (c_label0, ct) = garble_gate::<H>(gt, a_label0, b_label0, &delta, GATE_ID);

        for (a_vl, b_vl) in TEST_CASES {
            let a_active_label = if a_vl { a_label0 ^ &delta } else { a_label0 };
            let b_active_label = if b_vl { b_label0 ^ &delta } else { b_label0 };

            let evaluated = degarble_gate::<H>(
                gt,
                || ct.unwrap(),
                a_active_label,
                a_vl,
                b_active_label,
                GATE_ID,
            );
            let evaluated_value = (gt.f())(a_vl, b_vl);

            let expected_c_active_label = if evaluated_value {
                c_label0 ^ &delta
            } else {
                c_label0
            };

            if evaluated != expected_c_active_label {
                bitmask.push('0');
                failed_cases.push(FailedCase {
                    c_label1: c_label0 ^ &delta,
                    c_label0,
                    a_value: a_vl,
                    b_value: b_vl,
                    c_value: (gt.f())(a_vl, b_vl),
                    evaluated,
                    expected: expected_c_active_label,
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
        ($($gate_type:ident => $test_name:ident),* $(,)?) => {
            mod blake3 {
                use super::*;
                $(
                    #[test]
                    fn $test_name() {
                        garble_consistency::<Blake3Hasher>(GateType::$gate_type);
                    }
                )*
            }
            mod aesni {
                use super::*;
                $(
                    #[test]
                    fn $test_name() {
                        garble_consistency::<AesNiHasher>(GateType::$gate_type);
                    }
                )*
            }
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
}
