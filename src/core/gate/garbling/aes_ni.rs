#![allow(clippy::needless_return)]

// AES-NI implementation is available when the target provides the required
// instruction set at compile-time.
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
))]
pub(crate) mod aes_ni_impl {
    use core::{arch::x86_64::*, mem::MaybeUninit};
    use std::sync::OnceLock;

    /// AES-128 round keys (11 x 128-bit)
    pub struct Aes128 {
        round_keys: [__m128i; 11],
    }

    impl Aes128 {
        /// Build from a 128-bit key (uses AES-NI key schedule).
        pub fn new(key: [u8; 16]) -> Option<Self> {
            if !is_x86_feature_detected!("aes") {
                return None;
            }
            // Safety: guarded by is_x86_feature_detected!("aes")
            let round_keys = unsafe { expand_key_128(key) };
            Some(Self { round_keys })
        }

        /// Encrypt a single 16-byte block with AES-NI.
        /// Safety: requires AES-NI (the constructor enforces this).
        #[inline]
        #[target_feature(enable = "aes,sse2")]
        pub unsafe fn encrypt_block(&self, block: [u8; 16]) -> [u8; 16] {
            unsafe {
                let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
                state = _mm_xor_si128(state, self.round_keys[0]);
                // Rounds 1..=9
                for r in 1..10 {
                    state = _mm_aesenc_si128(state, self.round_keys[r]);
                }
                // Final round
                state = _mm_aesenclast_si128(state, self.round_keys[10]);

                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, state);
                out
            }
        }

        /// Encrypt two 16-byte blocks in parallel.
        ///
        /// This issues AESENC/AESENCLAST for both blocks per round so the CPU can
        /// pipeline them concurrently (great for CTR/ECB where blocks are independent).
        /// Safety: requires AES-NI (the constructor enforces this).
        #[inline]
        #[target_feature(enable = "aes,sse2")]
        pub unsafe fn encrypt2_blocks(&self, b0: [u8; 16], b1: [u8; 16]) -> ([u8; 16], [u8; 16]) {
            unsafe {
                let mut s0 = _mm_loadu_si128(b0.as_ptr() as *const __m128i);
                let mut s1 = _mm_loadu_si128(b1.as_ptr() as *const __m128i);

                let rk0 = self.round_keys[0];
                s0 = _mm_xor_si128(s0, rk0);
                s1 = _mm_xor_si128(s1, rk0);

                // Rounds 1..=9 (interleaved)
                for r in 1..10 {
                    let rk = self.round_keys[r];
                    s0 = _mm_aesenc_si128(s0, rk);
                    s1 = _mm_aesenc_si128(s1, rk);
                }

                let rk_last = self.round_keys[10];
                s0 = _mm_aesenclast_si128(s0, rk_last);
                s1 = _mm_aesenclast_si128(s1, rk_last);

                let mut out0 = [0u8; 16];
                let mut out1 = [0u8; 16];
                _mm_storeu_si128(out0.as_mut_ptr() as *mut __m128i, s0);
                _mm_storeu_si128(out1.as_mut_ptr() as *mut __m128i, s1);
                (out0, out1)
            }
        }

        /// Encrypt a single block with an extra 128-bit XOR mask (tweak) applied before the first round.
        /// This folds the tweak into the initial AddRoundKey for fewer instructions overall.
        #[inline]
        #[target_feature(enable = "aes,sse2")]
        pub unsafe fn encrypt_block_xor(&self, block: [u8; 16], xor_mask: [u8; 16]) -> [u8; 16] {
            unsafe {
                let mut state = _mm_loadu_si128(block.as_ptr() as *const __m128i);
                let mask = _mm_loadu_si128(xor_mask.as_ptr() as *const __m128i);
                let rk0 = _mm_xor_si128(self.round_keys[0], mask);
                state = _mm_xor_si128(state, rk0);
                for r in 1..10 {
                    state = _mm_aesenc_si128(state, self.round_keys[r]);
                }
                state = _mm_aesenclast_si128(state, self.round_keys[10]);
                let mut out = [0u8; 16];
                _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, state);
                out
            }
        }

        /// Encrypt two blocks in parallel with an extra 128-bit XOR mask (tweak) applied.
        /// The mask is folded into the initial AddRoundKey to minimize total XORs.
        #[cfg(test)]
        #[inline]
        #[target_feature(enable = "aes,sse2")]
        pub unsafe fn encrypt2_blocks_xor(
            &self,
            b0: [u8; 16],
            b1: [u8; 16],
            xor_mask: [u8; 16],
        ) -> ([u8; 16], [u8; 16]) {
            unsafe {
                let mut s0 = _mm_loadu_si128(b0.as_ptr() as *const __m128i);
                let mut s1 = _mm_loadu_si128(b1.as_ptr() as *const __m128i);
                let mask = _mm_loadu_si128(xor_mask.as_ptr() as *const __m128i);
                let rk0 = _mm_xor_si128(self.round_keys[0], mask);
                s0 = _mm_xor_si128(s0, rk0);
                s1 = _mm_xor_si128(s1, rk0);
                for r in 1..10 {
                    let rk = self.round_keys[r];
                    s0 = _mm_aesenc_si128(s0, rk);
                    s1 = _mm_aesenc_si128(s1, rk);
                }
                let rk_last = self.round_keys[10];
                s0 = _mm_aesenclast_si128(s0, rk_last);
                s1 = _mm_aesenclast_si128(s1, rk_last);
                let mut out0 = [0u8; 16];
                let mut out1 = [0u8; 16];
                _mm_storeu_si128(out0.as_mut_ptr() as *mut __m128i, s0);
                _mm_storeu_si128(out1.as_mut_ptr() as *mut __m128i, s1);
                (out0, out1)
            }
        }
    }

    // Global, lazily-initialized AES-128 cipher for fast, repeated use
    static AES128_STATIC: OnceLock<Aes128> = OnceLock::new();
    const DEFAULT_STATIC_KEY: [u8; 16] = [0x42; 16];

    #[inline(always)]
    fn get_or_init_static_cipher() -> &'static Aes128 {
        // Compiled only when target features include AES+SSE2; avoid runtime checks.
        AES128_STATIC.get_or_init(|| {
            Aes128::new(DEFAULT_STATIC_KEY)
                .expect("AES-NI unavailable despite compile-time target features")
        })
    }

    /// Expand AES-128 key into 11 round keys using AES-NI.
    /// Safety: requires AES-NI.
    #[target_feature(enable = "aes,sse2")]
    unsafe fn expand_key_128(key_bytes: [u8; 16]) -> [__m128i; 11] {
        unsafe {
            // Initialize array without Default (since __m128i isn't Default)
            let mut rk: [MaybeUninit<__m128i>; 11] = MaybeUninit::uninit().assume_init();

            let mut tmp = _mm_loadu_si128(key_bytes.as_ptr() as *const __m128i);
            rk[0].as_mut_ptr().write(tmp);

            macro_rules! expand_round {
                ($idx:expr, $rcon:expr) => {{
                    let mut keygen = _mm_aeskeygenassist_si128(tmp, $rcon);
                    keygen = _mm_shuffle_epi32(keygen, 0xff);
                    let mut t = _mm_slli_si128(tmp, 4);
                    tmp = _mm_xor_si128(tmp, t);
                    t = _mm_slli_si128(t, 4);
                    tmp = _mm_xor_si128(tmp, t);
                    t = _mm_slli_si128(t, 4);
                    tmp = _mm_xor_si128(tmp, t);
                    tmp = _mm_xor_si128(tmp, keygen);
                    rk[$idx].as_mut_ptr().write(tmp);
                }};
            }

            expand_round!(1, 0x01);
            expand_round!(2, 0x02);
            expand_round!(3, 0x04);
            expand_round!(4, 0x08);
            expand_round!(5, 0x10);
            expand_round!(6, 0x20);
            expand_round!(7, 0x40);
            expand_round!(8, 0x80);
            expand_round!(9, 0x1B);
            expand_round!(10, 0x36);

            // Transmute MaybeUninit<__m128i> -> __m128i safely
            core::mem::transmute::<_, [__m128i; 11]>(rk)
        }
    }

    /// Safe wrapper: single block encryption with runtime AES-NI detection.
    #[cfg(test)]
    pub fn aes128_encrypt_block(key: [u8; 16], block: [u8; 16]) -> Option<[u8; 16]> {
        let cipher = Aes128::new(key)?;
        // Safety: Aes128::new guarantees AES-NI availability
        Some(unsafe { cipher.encrypt_block(block) })
    }

    /// Safe wrapper: two blocks in parallel with runtime AES-NI detection.
    #[cfg(test)]
    pub fn aes128_encrypt2_blocks(
        key: [u8; 16],
        b0: [u8; 16],
        b1: [u8; 16],
    ) -> Option<([u8; 16], [u8; 16])> {
        let cipher = Aes128::new(key)?;
        Some(unsafe { cipher.encrypt2_blocks(b0, b1) })
    }

    /// Encrypt a single 16-byte block using a static, shared AES-128 key.
    /// Avoids per-call key schedule for maximum throughput.
    #[inline(always)]
    pub fn aes128_encrypt_block_static(block: [u8; 16]) -> Option<[u8; 16]> {
        let cipher = get_or_init_static_cipher();
        // Safety: cipher constructed only when AES-NI is available
        Some(unsafe { cipher.encrypt_block(block) })
    }

    /// Encrypt two 16-byte blocks using a static, shared AES-128 key.
    /// Avoids per-call key schedule and exploits instruction-level parallelism.
    #[inline(always)]
    #[cfg(test)]
    pub fn aes128_encrypt2_blocks_static(
        b0: [u8; 16],
        b1: [u8; 16],
    ) -> Option<([u8; 16], [u8; 16])> {
        let cipher = get_or_init_static_cipher();
        // Safety: cipher constructed only when AES-NI is available
        Some(unsafe { cipher.encrypt2_blocks(b0, b1) })
    }

    /// Encrypt a single block using the static key, applying a 128-bit XOR mask before the rounds.
    #[inline(always)]
    pub fn aes128_encrypt_block_static_xor(
        block: [u8; 16],
        xor_mask: [u8; 16],
    ) -> Option<[u8; 16]> {
        let cipher = get_or_init_static_cipher();
        Some(unsafe { cipher.encrypt_block_xor(block, xor_mask) })
    }

    /// Encrypt two blocks using the static key, applying a 128-bit XOR mask before the rounds.
    #[inline(always)]
    pub fn aes128_encrypt2_blocks_static_xor(
        mut b0: [u8; 16],
        mut b1: [u8; 16],
        xor_mask: [u8; 16],
    ) -> Option<([u8; 16], [u8; 16])> {
        for i in 0..16 {
            b0[i] ^= xor_mask[i];
            b1[i] ^= xor_mask[i];
        }
        let cipher = get_or_init_static_cipher();
        Some(unsafe { cipher.encrypt2_blocks(b0, b1) })
    }

    /// u64 tweak variants: removed (use byte-mask helpers instead)
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn aes128_fips197_known_answer() {
            if !is_x86_feature_detected!("aes") {
                eprintln!("AES-NI not detected on this machine; skipping test.");
                return;
            }
            // FIPS-197 Appendix C.1
            let key = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F,
            ];
            let pt = [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF,
            ];
            let expected = [
                0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4,
                0xC5, 0x5A,
            ];

            let got = aes128_encrypt_block(key, pt).expect("AES-NI required");
            assert_eq!(got, expected);

            // Dual-lane: encrypt the same PT twice and expect same CT on both lanes
            let (c0, c1) = aes128_encrypt2_blocks(key, pt, pt).expect("AES-NI required");
            assert_eq!(c0, expected);
            assert_eq!(c1, expected);
        }
    }
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
))]
pub use aes_ni_impl::*;

// Fallback: stubs to keep compilation working when AES-NI is not available at
// compile-time (or on non-x86 targets) or the feature is disabled.
#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
)))]
pub mod aes_ni_unavailable {
    // Minimal stub API: only what non-AES builds reference.
    pub fn aes128_encrypt_block_static(_block: [u8; 16]) -> Option<[u8; 16]> {
        None
    }
}

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
)))]
pub use aes_ni_unavailable::*;
