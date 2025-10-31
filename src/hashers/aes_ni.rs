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
        ///
        /// # Safety
        ///
        /// This function is unsafe because it directly uses x86_64 intrinsics that require
        /// the AES-NI and SSE2 instruction sets to be available. The constructor ensures
        /// these features are available, but the caller must ensure this invariant is maintained.
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
        ///
        /// # Safety
        ///
        /// This function is unsafe because it directly uses x86_64 intrinsics that require
        /// the AES-NI and SSE2 instruction sets to be available. The constructor ensures
        /// these features are available, but the caller must ensure this invariant is maintained.
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

        /// Encrypt four independent 16-byte blocks by interleaving AES rounds across 4 states.
        #[inline]
        #[target_feature(enable = "aes,sse2")]
        pub unsafe fn encrypt4_blocks(&self, b: [[u8; 16]; 4]) -> [[u8; 16]; 4] {
            unsafe {
                let mut s0 = _mm_loadu_si128(b[0].as_ptr() as *const __m128i);
                let mut s1 = _mm_loadu_si128(b[1].as_ptr() as *const __m128i);
                let mut s2 = _mm_loadu_si128(b[2].as_ptr() as *const __m128i);
                let mut s3 = _mm_loadu_si128(b[3].as_ptr() as *const __m128i);

                let rk0 = self.round_keys[0];
                s0 = _mm_xor_si128(s0, rk0);
                s1 = _mm_xor_si128(s1, rk0);
                s2 = _mm_xor_si128(s2, rk0);
                s3 = _mm_xor_si128(s3, rk0);

                for r in 1..10 {
                    let rk = self.round_keys[r];
                    s0 = _mm_aesenc_si128(s0, rk);
                    s1 = _mm_aesenc_si128(s1, rk);
                    s2 = _mm_aesenc_si128(s2, rk);
                    s3 = _mm_aesenc_si128(s3, rk);
                }

                let rk_last = self.round_keys[10];
                s0 = _mm_aesenclast_si128(s0, rk_last);
                s1 = _mm_aesenclast_si128(s1, rk_last);
                s2 = _mm_aesenclast_si128(s2, rk_last);
                s3 = _mm_aesenclast_si128(s3, rk_last);

                let mut out = [[0u8; 16]; 4];
                _mm_storeu_si128(out[0].as_mut_ptr() as *mut __m128i, s0);
                _mm_storeu_si128(out[1].as_mut_ptr() as *mut __m128i, s1);
                _mm_storeu_si128(out[2].as_mut_ptr() as *mut __m128i, s2);
                _mm_storeu_si128(out[3].as_mut_ptr() as *mut __m128i, s3);
                out
            }
        }

        /// Encrypt eight independent 16-byte blocks by interleaving AES rounds across 8 states.
        #[inline]
        #[target_feature(enable = "aes,sse2")]
        pub unsafe fn encrypt8_blocks(&self, b: [[u8; 16]; 8]) -> [[u8; 16]; 8] {
            unsafe {
                let mut s0 = _mm_loadu_si128(b[0].as_ptr() as *const __m128i);
                let mut s1 = _mm_loadu_si128(b[1].as_ptr() as *const __m128i);
                let mut s2 = _mm_loadu_si128(b[2].as_ptr() as *const __m128i);
                let mut s3 = _mm_loadu_si128(b[3].as_ptr() as *const __m128i);
                let mut s4 = _mm_loadu_si128(b[4].as_ptr() as *const __m128i);
                let mut s5 = _mm_loadu_si128(b[5].as_ptr() as *const __m128i);
                let mut s6 = _mm_loadu_si128(b[6].as_ptr() as *const __m128i);
                let mut s7 = _mm_loadu_si128(b[7].as_ptr() as *const __m128i);

                let rk0 = self.round_keys[0];
                s0 = _mm_xor_si128(s0, rk0);
                s1 = _mm_xor_si128(s1, rk0);
                s2 = _mm_xor_si128(s2, rk0);
                s3 = _mm_xor_si128(s3, rk0);
                s4 = _mm_xor_si128(s4, rk0);
                s5 = _mm_xor_si128(s5, rk0);
                s6 = _mm_xor_si128(s6, rk0);
                s7 = _mm_xor_si128(s7, rk0);

                for r in 1..10 {
                    let rk = self.round_keys[r];
                    s0 = _mm_aesenc_si128(s0, rk);
                    s1 = _mm_aesenc_si128(s1, rk);
                    s2 = _mm_aesenc_si128(s2, rk);
                    s3 = _mm_aesenc_si128(s3, rk);
                    s4 = _mm_aesenc_si128(s4, rk);
                    s5 = _mm_aesenc_si128(s5, rk);
                    s6 = _mm_aesenc_si128(s6, rk);
                    s7 = _mm_aesenc_si128(s7, rk);
                }

                let rk_last = self.round_keys[10];
                s0 = _mm_aesenclast_si128(s0, rk_last);
                s1 = _mm_aesenclast_si128(s1, rk_last);
                s2 = _mm_aesenclast_si128(s2, rk_last);
                s3 = _mm_aesenclast_si128(s3, rk_last);
                s4 = _mm_aesenclast_si128(s4, rk_last);
                s5 = _mm_aesenclast_si128(s5, rk_last);
                s6 = _mm_aesenclast_si128(s6, rk_last);
                s7 = _mm_aesenclast_si128(s7, rk_last);

                let mut out = [[0u8; 16]; 8];
                _mm_storeu_si128(out[0].as_mut_ptr() as *mut __m128i, s0);
                _mm_storeu_si128(out[1].as_mut_ptr() as *mut __m128i, s1);
                _mm_storeu_si128(out[2].as_mut_ptr() as *mut __m128i, s2);
                _mm_storeu_si128(out[3].as_mut_ptr() as *mut __m128i, s3);
                _mm_storeu_si128(out[4].as_mut_ptr() as *mut __m128i, s4);
                _mm_storeu_si128(out[5].as_mut_ptr() as *mut __m128i, s5);
                _mm_storeu_si128(out[6].as_mut_ptr() as *mut __m128i, s6);
                _mm_storeu_si128(out[7].as_mut_ptr() as *mut __m128i, s7);
                out
            }
        }

        /// Encrypt a single block with an extra 128-bit XOR mask (tweak) applied before the first round.
        /// This folds the tweak into the initial AddRoundKey for fewer instructions overall.
        ///
        /// # Safety
        ///
        /// This function is unsafe because it directly uses x86_64 intrinsics that require
        /// the AES-NI and SSE2 instruction sets to be available. The constructor ensures
        /// these features are available, but the caller must ensure this invariant is maintained.
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
        ///
        /// # Safety
        ///
        /// This function is unsafe because it directly uses x86_64 intrinsics that require
        /// the AES-NI and SSE2 instruction sets to be available. The constructor ensures
        /// these features are available, but the caller must ensure this invariant is maintained.
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

        /// Encrypt 4 independent blocks with a fused XOR mask folded into round key 0.
        #[inline]
        #[target_feature(enable = "aes,sse2")]
        pub unsafe fn encrypt4_blocks_xor(
            &self,
            b: [[u8; 16]; 4],
            xor_mask: [u8; 16],
        ) -> [[u8; 16]; 4] {
            unsafe {
                let mut s0 = _mm_loadu_si128(b[0].as_ptr() as *const __m128i);
                let mut s1 = _mm_loadu_si128(b[1].as_ptr() as *const __m128i);
                let mut s2 = _mm_loadu_si128(b[2].as_ptr() as *const __m128i);
                let mut s3 = _mm_loadu_si128(b[3].as_ptr() as *const __m128i);
                let mask = _mm_loadu_si128(xor_mask.as_ptr() as *const __m128i);
                let rk0 = _mm_xor_si128(self.round_keys[0], mask);
                s0 = _mm_xor_si128(s0, rk0);
                s1 = _mm_xor_si128(s1, rk0);
                s2 = _mm_xor_si128(s2, rk0);
                s3 = _mm_xor_si128(s3, rk0);
                for r in 1..10 {
                    let rk = self.round_keys[r];
                    s0 = _mm_aesenc_si128(s0, rk);
                    s1 = _mm_aesenc_si128(s1, rk);
                    s2 = _mm_aesenc_si128(s2, rk);
                    s3 = _mm_aesenc_si128(s3, rk);
                }
                let rk_last = self.round_keys[10];
                s0 = _mm_aesenclast_si128(s0, rk_last);
                s1 = _mm_aesenclast_si128(s1, rk_last);
                s2 = _mm_aesenclast_si128(s2, rk_last);
                s3 = _mm_aesenclast_si128(s3, rk_last);
                let mut out = [[0u8; 16]; 4];
                _mm_storeu_si128(out[0].as_mut_ptr() as *mut __m128i, s0);
                _mm_storeu_si128(out[1].as_mut_ptr() as *mut __m128i, s1);
                _mm_storeu_si128(out[2].as_mut_ptr() as *mut __m128i, s2);
                _mm_storeu_si128(out[3].as_mut_ptr() as *mut __m128i, s3);
                out
            }
        }

        /// Encrypt 8 independent blocks with a fused XOR mask folded into round key 0.
        #[inline]
        #[target_feature(enable = "aes,sse2")]
        pub unsafe fn encrypt8_blocks_xor(
            &self,
            b: [[u8; 16]; 8],
            xor_mask: [u8; 16],
        ) -> [[u8; 16]; 8] {
            unsafe {
                let mut s0 = _mm_loadu_si128(b[0].as_ptr() as *const __m128i);
                let mut s1 = _mm_loadu_si128(b[1].as_ptr() as *const __m128i);
                let mut s2 = _mm_loadu_si128(b[2].as_ptr() as *const __m128i);
                let mut s3 = _mm_loadu_si128(b[3].as_ptr() as *const __m128i);
                let mut s4 = _mm_loadu_si128(b[4].as_ptr() as *const __m128i);
                let mut s5 = _mm_loadu_si128(b[5].as_ptr() as *const __m128i);
                let mut s6 = _mm_loadu_si128(b[6].as_ptr() as *const __m128i);
                let mut s7 = _mm_loadu_si128(b[7].as_ptr() as *const __m128i);
                let mask = _mm_loadu_si128(xor_mask.as_ptr() as *const __m128i);
                let rk0 = _mm_xor_si128(self.round_keys[0], mask);
                s0 = _mm_xor_si128(s0, rk0);
                s1 = _mm_xor_si128(s1, rk0);
                s2 = _mm_xor_si128(s2, rk0);
                s3 = _mm_xor_si128(s3, rk0);
                s4 = _mm_xor_si128(s4, rk0);
                s5 = _mm_xor_si128(s5, rk0);
                s6 = _mm_xor_si128(s6, rk0);
                s7 = _mm_xor_si128(s7, rk0);
                for r in 1..10 {
                    let rk = self.round_keys[r];
                    s0 = _mm_aesenc_si128(s0, rk);
                    s1 = _mm_aesenc_si128(s1, rk);
                    s2 = _mm_aesenc_si128(s2, rk);
                    s3 = _mm_aesenc_si128(s3, rk);
                    s4 = _mm_aesenc_si128(s4, rk);
                    s5 = _mm_aesenc_si128(s5, rk);
                    s6 = _mm_aesenc_si128(s6, rk);
                    s7 = _mm_aesenc_si128(s7, rk);
                }
                let rk_last = self.round_keys[10];
                s0 = _mm_aesenclast_si128(s0, rk_last);
                s1 = _mm_aesenclast_si128(s1, rk_last);
                s2 = _mm_aesenclast_si128(s2, rk_last);
                s3 = _mm_aesenclast_si128(s3, rk_last);
                s4 = _mm_aesenclast_si128(s4, rk_last);
                s5 = _mm_aesenclast_si128(s5, rk_last);
                s6 = _mm_aesenclast_si128(s6, rk_last);
                s7 = _mm_aesenclast_si128(s7, rk_last);
                let mut out = [[0u8; 16]; 8];
                _mm_storeu_si128(out[0].as_mut_ptr() as *mut __m128i, s0);
                _mm_storeu_si128(out[1].as_mut_ptr() as *mut __m128i, s1);
                _mm_storeu_si128(out[2].as_mut_ptr() as *mut __m128i, s2);
                _mm_storeu_si128(out[3].as_mut_ptr() as *mut __m128i, s3);
                _mm_storeu_si128(out[4].as_mut_ptr() as *mut __m128i, s4);
                _mm_storeu_si128(out[5].as_mut_ptr() as *mut __m128i, s5);
                _mm_storeu_si128(out[6].as_mut_ptr() as *mut __m128i, s6);
                _mm_storeu_si128(out[7].as_mut_ptr() as *mut __m128i, s7);
                out
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
        b0: [u8; 16],
        b1: [u8; 16],
        xor_mask: [u8; 16],
    ) -> Option<([u8; 16], [u8; 16])> {
        let cipher = get_or_init_static_cipher();
        Some(unsafe { cipher.encrypt2_blocks_xor(b0, b1, xor_mask) })
    }

    /// Encrypt four blocks using the static key, applying a 128-bit XOR mask before the rounds.
    #[inline(always)]
    pub fn aes128_encrypt4_blocks_static_xor(
        b: [[u8; 16]; 4],
        xor_mask: [u8; 16],
    ) -> Option<[[u8; 16]; 4]> {
        let cipher = get_or_init_static_cipher();
        Some(unsafe { cipher.encrypt4_blocks_xor(b, xor_mask) })
    }

    /// Encrypt eight blocks using the static key, applying a 128-bit XOR mask before the rounds.
    #[inline(always)]
    pub fn aes128_encrypt8_blocks_static_xor(
        b: [[u8; 16]; 8],
        xor_mask: [u8; 16],
    ) -> Option<[[u8; 16]; 8]> {
        let cipher = get_or_init_static_cipher();
        Some(unsafe { cipher.encrypt8_blocks_xor(b, xor_mask) })
    }

    /// Encrypt sixteen blocks using the static key, applying a 128-bit XOR mask before the rounds.
    #[inline(always)]
    pub fn aes128_encrypt16_blocks_static_xor(
        b: [[u8; 16]; 16],
        xor_mask: [u8; 16],
    ) -> Option<[[u8; 16]; 16]> {
        let mut first = [[0u8; 16]; 8];
        let mut second = [[0u8; 16]; 8];
        for i in 0..8 {
            first[i] = b[i];
        }
        for i in 0..8 {
            second[i] = b[8 + i];
        }
        let cipher = get_or_init_static_cipher();
        let out1 = unsafe { cipher.encrypt8_blocks_xor(first, xor_mask) };
        let out2 = unsafe { cipher.encrypt8_blocks_xor(second, xor_mask) };
        Some([
            out1[0], out1[1], out1[2], out1[3], out1[4], out1[5], out1[6], out1[7], out2[0],
            out2[1], out2[2], out2[3], out2[4], out2[5], out2[6], out2[7],
        ])
    }

    // =============================
    // Per-block XOR mask variants
    // =============================

    #[target_feature(enable = "sse2")]
    unsafe fn xor_masks_inplace_sse(b_ptr: *mut u8, m_ptr: *const u8, bytes: usize) {
        // XOR in 16-byte chunks using SSE2. `bytes` is a multiple of 16.
        let mut off = 0usize;
        unsafe {
            while off + 16 <= bytes {
                let vb = _mm_loadu_si128(b_ptr.add(off) as *const __m128i);
                let vm = _mm_loadu_si128(m_ptr.add(off) as *const __m128i);
                let x = _mm_xor_si128(vb, vm);
                _mm_storeu_si128(b_ptr.add(off) as *mut __m128i, x);
                off += 16;
            }
        }
    }

    /// Encrypt two blocks using per-block XOR masks.
    #[inline(always)]
    pub fn aes128_encrypt2_blocks_static_xor_masks(
        mut b: [[u8; 16]; 2],
        masks: [[u8; 16]; 2],
    ) -> Option<[[u8; 16]; 2]> {
        unsafe { xor_masks_inplace_sse(b.as_mut_ptr() as *mut u8, masks.as_ptr() as *const u8, 32) }
        let cipher = get_or_init_static_cipher();
        let (o0, o1) = unsafe { cipher.encrypt2_blocks(b[0], b[1]) };
        Some([o0, o1])
    }

    /// Encrypt four blocks using per-block XOR masks.
    #[inline(always)]
    pub fn aes128_encrypt4_blocks_static_xor_masks(
        mut b: [[u8; 16]; 4],
        masks: [[u8; 16]; 4],
    ) -> Option<[[u8; 16]; 4]> {
        unsafe { xor_masks_inplace_sse(b.as_mut_ptr() as *mut u8, masks.as_ptr() as *const u8, 64) }
        let cipher = get_or_init_static_cipher();
        Some(unsafe { cipher.encrypt4_blocks(b) })
    }

    /// Encrypt eight blocks using per-block XOR masks.
    #[inline(always)]
    pub fn aes128_encrypt8_blocks_static_xor_masks(
        mut b: [[u8; 16]; 8],
        masks: [[u8; 16]; 8],
    ) -> Option<[[u8; 16]; 8]> {
        unsafe {
            xor_masks_inplace_sse(b.as_mut_ptr() as *mut u8, masks.as_ptr() as *const u8, 128)
        }
        let cipher = get_or_init_static_cipher();
        Some(unsafe { cipher.encrypt8_blocks(b) })
    }

    /// Encrypt sixteen blocks using per-block XOR masks.
    #[inline(always)]
    pub fn aes128_encrypt16_blocks_static_xor_masks(
        b: [[u8; 16]; 16],
        masks: [[u8; 16]; 16],
    ) -> Option<[[u8; 16]; 16]> {
        let mut first_b = [[0u8; 16]; 8];
        let mut second_b = [[0u8; 16]; 8];
        let mut first_m = [[0u8; 16]; 8];
        let mut second_m = [[0u8; 16]; 8];
        first_b.copy_from_slice(&b[..8]);
        second_b.copy_from_slice(&b[8..]);
        first_m.copy_from_slice(&masks[..8]);
        second_m.copy_from_slice(&masks[8..]);
        let out1 = aes128_encrypt8_blocks_static_xor_masks(first_b, first_m)?;
        let out2 = aes128_encrypt8_blocks_static_xor_masks(second_b, second_m)?;
        Some([
            out1[0], out1[1], out1[2], out1[3], out1[4], out1[5], out1[6], out1[7], out2[0],
            out2[1], out2[2], out2[3], out2[4], out2[5], out2[6], out2[7],
        ])
    }

    /// Generic dispatcher for M in {1,2,4,8,16} using per-block XOR masks.
    /// Uses transmute to avoid per-call copying for exact sizes.
    #[target_feature(enable = "aes,sse2")]
    pub unsafe fn aes128_encrypt_blocks_static_xor_masks<const M: usize>(
        b: [[u8; 16]; M],
        masks: [[u8; 16]; M],
    ) -> Option<[[u8; 16]; M]> {
        let mut out = [[0u8; 16]; M];
        let mut i = 0usize;
        macro_rules! process_m {
            ($K:expr, $fun:path) => {{
                while i + $K <= M {
                    let mut bi = [[0u8; 16]; $K];
                    let mut mi = [[0u8; 16]; $K];
                    for t in 0..$K {
                        bi[t] = b[i + t];
                        mi[t] = masks[i + t];
                    }
                    let bo = $fun(bi, mi)?;
                    for t in 0..$K {
                        out[i + t] = bo[t];
                    }
                    i += $K;
                }
            }};
        }
        process_m!(16, aes128_encrypt16_blocks_static_xor_masks);
        process_m!(8, aes128_encrypt8_blocks_static_xor_masks);
        process_m!(4, aes128_encrypt4_blocks_static_xor_masks);
        process_m!(2, aes128_encrypt2_blocks_static_xor_masks);
        while i < M {
            let bo = aes128_encrypt_block_static_xor(b[i], masks[i])?;
            out[i] = bo;
            i += 1;
        }
        Some(out)
    }
}

// Fallback (no AES-NI at compile-time): software AES implementation backed by aes crate.
#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
)))]
pub mod aes_ni_unavailable {
    use std::sync::OnceLock;

    use aes::{
        Aes128,
        cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
    };

    // Keep parity with the AES-NI path's default key.
    const DEFAULT_STATIC_KEY: [u8; 16] = [0x42; 16];

    static AES128_STATIC: OnceLock<Aes128> = OnceLock::new();

    #[inline(always)]
    fn get_or_init_static_cipher() -> &'static Aes128 {
        AES128_STATIC.get_or_init(|| Aes128::new_from_slice(&DEFAULT_STATIC_KEY).expect("key size"))
    }

    /// Encrypt a single 16-byte block using a static, shared AES-128 key.
    #[inline(always)]
    pub fn aes128_encrypt_block_static(block: [u8; 16]) -> Option<[u8; 16]> {
        let cipher = get_or_init_static_cipher();
        let mut b = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut b);
        let mut out = [0u8; 16];
        out.copy_from_slice(&b);
        Some(out)
    }

    /// Encrypt a single block using the static key, applying a 128-bit XOR mask before encryption.
    #[inline(always)]
    pub fn aes128_encrypt_block_static_xor(
        block: [u8; 16],
        xor_mask: [u8; 16],
    ) -> Option<[u8; 16]> {
        let cipher = get_or_init_static_cipher();
        let mut inb = block;
        for i in 0..16 {
            inb[i] ^= xor_mask[i];
        }
        let mut b = GenericArray::clone_from_slice(&inb);
        cipher.encrypt_block(&mut b);
        let mut out = [0u8; 16];
        out.copy_from_slice(&b);
        Some(out)
    }

    /// Encrypt two blocks using the static key, applying a 128-bit XOR mask before encryption.
    #[inline(always)]
    pub fn aes128_encrypt2_blocks_static_xor(
        b0: [u8; 16],
        b1: [u8; 16],
        xor_mask: [u8; 16],
    ) -> Option<([u8; 16], [u8; 16])> {
        let out = aes128_encrypt2_blocks_static_xor_masks([b0, b1], [xor_mask; 2])?;
        Some((out[0], out[1]))
    }

    /// Encrypt four blocks using the static key, applying a 128-bit XOR mask before encryption.
    #[inline(always)]
    pub fn aes128_encrypt4_blocks_static_xor(
        b: [[u8; 16]; 4],
        xor_mask: [u8; 16],
    ) -> Option<[[u8; 16]; 4]> {
        aes128_encrypt4_blocks_static_xor_masks(b, [xor_mask; 4])
    }

    /// Encrypt eight blocks using the static key, applying a 128-bit XOR mask before encryption.
    #[inline(always)]
    pub fn aes128_encrypt8_blocks_static_xor(
        b: [[u8; 16]; 8],
        xor_mask: [u8; 16],
    ) -> Option<[[u8; 16]; 8]> {
        aes128_encrypt8_blocks_static_xor_masks(b, [xor_mask; 8])
    }

    /// Encrypt sixteen blocks using the static key, applying a 128-bit XOR mask before encryption.
    #[inline(always)]
    pub fn aes128_encrypt16_blocks_static_xor(
        b: [[u8; 16]; 16],
        xor_mask: [u8; 16],
    ) -> Option<[[u8; 16]; 16]> {
        aes128_encrypt16_blocks_static_xor_masks(b, [xor_mask; 16])
    }

    // =============================
    // Per-block XOR mask variants
    // =============================

    #[inline(always)]
    pub fn aes128_encrypt2_blocks_static_xor_masks(
        mut b: [[u8; 16]; 2],
        masks: [[u8; 16]; 2],
    ) -> Option<[[u8; 16]; 2]> {
        for k in 0..2 {
            for i in 0..16 {
                b[k][i] ^= masks[k][i];
            }
        }
        let cipher = get_or_init_static_cipher();
        use aes::cipher::generic_array::GenericArray;
        let mut blocks = [
            GenericArray::clone_from_slice(&b[0]),
            GenericArray::clone_from_slice(&b[1]),
        ];
        cipher.encrypt_blocks(&mut blocks);
        let mut out = [[0u8; 16]; 2];
        out[0].copy_from_slice(&blocks[0]);
        out[1].copy_from_slice(&blocks[1]);
        Some(out)
    }

    #[inline(always)]
    pub fn aes128_encrypt4_blocks_static_xor_masks(
        mut b: [[u8; 16]; 4],
        masks: [[u8; 16]; 4],
    ) -> Option<[[u8; 16]; 4]> {
        for k in 0..4 {
            for i in 0..16 {
                b[k][i] ^= masks[k][i];
            }
        }
        let cipher = get_or_init_static_cipher();
        use aes::cipher::generic_array::GenericArray;
        let mut blocks = [
            GenericArray::clone_from_slice(&b[0]),
            GenericArray::clone_from_slice(&b[1]),
            GenericArray::clone_from_slice(&b[2]),
            GenericArray::clone_from_slice(&b[3]),
        ];
        cipher.encrypt_blocks(&mut blocks);
        let mut out = [[0u8; 16]; 4];
        for k in 0..4 {
            out[k].copy_from_slice(&blocks[k]);
        }
        Some(out)
    }

    #[inline(always)]
    pub fn aes128_encrypt8_blocks_static_xor_masks(
        mut b: [[u8; 16]; 8],
        masks: [[u8; 16]; 8],
    ) -> Option<[[u8; 16]; 8]> {
        for k in 0..8 {
            for i in 0..16 {
                b[k][i] ^= masks[k][i];
            }
        }
        let cipher = get_or_init_static_cipher();
        use aes::cipher::generic_array::GenericArray;
        let mut blocks = [
            GenericArray::clone_from_slice(&b[0]),
            GenericArray::clone_from_slice(&b[1]),
            GenericArray::clone_from_slice(&b[2]),
            GenericArray::clone_from_slice(&b[3]),
            GenericArray::clone_from_slice(&b[4]),
            GenericArray::clone_from_slice(&b[5]),
            GenericArray::clone_from_slice(&b[6]),
            GenericArray::clone_from_slice(&b[7]),
        ];
        cipher.encrypt_blocks(&mut blocks);
        let mut out = [[0u8; 16]; 8];
        for k in 0..8 {
            out[k].copy_from_slice(&blocks[k]);
        }
        Some(out)
    }

    #[inline(always)]
    pub fn aes128_encrypt16_blocks_static_xor_masks(
        mut b: [[u8; 16]; 16],
        masks: [[u8; 16]; 16],
    ) -> Option<[[u8; 16]; 16]> {
        for k in 0..16 {
            for i in 0..16 {
                b[k][i] ^= masks[k][i];
            }
        }
        let cipher = get_or_init_static_cipher();
        use aes::cipher::generic_array::GenericArray;
        let mut blocks = [
            GenericArray::clone_from_slice(&b[0]),
            GenericArray::clone_from_slice(&b[1]),
            GenericArray::clone_from_slice(&b[2]),
            GenericArray::clone_from_slice(&b[3]),
            GenericArray::clone_from_slice(&b[4]),
            GenericArray::clone_from_slice(&b[5]),
            GenericArray::clone_from_slice(&b[6]),
            GenericArray::clone_from_slice(&b[7]),
            GenericArray::clone_from_slice(&b[8]),
            GenericArray::clone_from_slice(&b[9]),
            GenericArray::clone_from_slice(&b[10]),
            GenericArray::clone_from_slice(&b[11]),
            GenericArray::clone_from_slice(&b[12]),
            GenericArray::clone_from_slice(&b[13]),
            GenericArray::clone_from_slice(&b[14]),
            GenericArray::clone_from_slice(&b[15]),
        ];
        cipher.encrypt_blocks(&mut blocks);
        let mut out = [[0u8; 16]; 16];
        for k in 0..16 {
            out[k].copy_from_slice(&blocks[k]);
        }
        Some(out)
    }

    /// Generic dispatcher for M in {1,2,4,8,16} using per-block XOR masks (software fallback, safe and chunked).
    #[inline(always)]
    pub fn aes128_encrypt_blocks_static_xor_masks<const M: usize>(
        b: [[u8; 16]; M],
        masks: [[u8; 16]; M],
    ) -> Option<[[u8; 16]; M]> {
        let mut out = [[0u8; 16]; M];
        let mut i = 0usize;
        macro_rules! process_m {
            ($K:expr, $fun:ident) => {{
                while i + $K <= M {
                    let mut bi = [[0u8; 16]; $K];
                    let mut mi = [[0u8; 16]; $K];
                    for t in 0..$K {
                        bi[t] = b[i + t];
                        mi[t] = masks[i + t];
                    }
                    let bo = $fun(bi, mi)?;
                    for t in 0..$K {
                        out[i + t] = bo[t];
                    }
                    i += $K;
                }
            }};
        }
        process_m!(16, aes128_encrypt16_blocks_static_xor_masks);
        process_m!(8, aes128_encrypt8_blocks_static_xor_masks);
        process_m!(4, aes128_encrypt4_blocks_static_xor_masks);
        process_m!(2, aes128_encrypt2_blocks_static_xor_masks);
        if i < M {
            // handle remaining single blocks
            while i < M {
                let out1 = aes128_encrypt_block_static_xor(b[i], masks[i])?;
                out[i] = out1;
                i += 1;
            }
        }
        Some(out)
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
pub use aes_ni_unavailable::*;
