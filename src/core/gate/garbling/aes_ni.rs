#![allow(clippy::needless_return)]

// AES-NI module - only available when AES and SSE2 target features are enabled at compile time
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
))]
pub(crate) mod aes_ni_impl {
    use core::{arch::x86_64::*, mem::MaybeUninit};

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
    pub fn aes128_encrypt_block(key: [u8; 16], block: [u8; 16]) -> Option<[u8; 16]> {
        let cipher = Aes128::new(key)?;
        // Safety: Aes128::new guarantees AES-NI availability
        Some(unsafe { cipher.encrypt_block(block) })
    }

    /// Safe wrapper: two blocks in parallel with runtime AES-NI detection.
    pub fn aes128_encrypt2_blocks(
        key: [u8; 16],
        b0: [u8; 16],
        b1: [u8; 16],
    ) -> Option<([u8; 16], [u8; 16])> {
        let cipher = Aes128::new(key)?;
        Some(unsafe { cipher.encrypt2_blocks(b0, b1) })
    }

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

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
)))]
pub mod aes_ni_unavailable {
    // Non-x86 platforms: stub module to keep compilation happy
    pub fn aes128_encrypt_block(_key: [u8; 16], _block: [u8; 16]) -> Option<[u8; 16]> {
        None
    }

    pub fn aes128_encrypt2_blocks(
        _key: [u8; 16],
        _b0: [u8; 16],
        _b1: [u8; 16],
    ) -> Option<([u8; 16], [u8; 16])> {
        None
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
pub use aes_ni_unavailable::*;
