use super::super::GateId;
#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
))]
use super::aes_ni::{aes128_encrypt_block, aes128_encrypt2_blocks};
use crate::{S, core::s::S_SIZE};

pub trait GateHasher: Clone + Send + Sync {
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S);
    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S;
}

#[derive(Clone, Debug, Default)]
pub struct Blake3Hasher;

impl GateHasher for Blake3Hasher {
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S) {
        let h_selected = Self::hash_for_degarbling(selected_label, gate_id);
        let h_other = Self::hash_for_degarbling(other_label, gate_id);
        (h_selected, h_other)
    }

    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S {
        let mut result = [0u8; S_SIZE];
        let mut hasher = blake3::Hasher::new();
        let b = label.to_bytes();
        hasher.update(&b);
        hasher.update(&gate_id.to_le_bytes());
        let hash = hasher.finalize();
        result.copy_from_slice(&hash.as_bytes()[0..S_SIZE]);
        S::from_bytes(result)
    }
}

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
))]
#[derive(Clone, Debug, Default)]
pub struct AesNiHasher;

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
))]
impl GateHasher for AesNiHasher {
    #[inline(always)]
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S) {
        // Ultra-fast key generation for hotpath - avoid loops and allocations
        let key = unsafe {
            let gate_id_u64 = gate_id as u64;
            let mut key_u64 = [0u64; 2];
            // Fast domain separation using bit mixing
            key_u64[0] = gate_id_u64 ^ 0x123456789ABCDEF0;
            key_u64[1] = gate_id_u64.wrapping_mul(0xDEADBEEFCAFEBABE);
            core::mem::transmute::<[u64; 2], [u8; 16]>(key_u64)
        };

        // Direct AES encryption without intermediate copies - use transmute for zero-cost
        let (cipher_selected, cipher_other) =
            aes128_encrypt2_blocks(key, selected_label.to_bytes(), other_label.to_bytes())
                .expect("AES-NI should be available when target features are enabled");

        (S::from_bytes(cipher_selected), S::from_bytes(cipher_other))
    }

    #[inline(always)]
    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S {
        // Ultra-fast key generation for hotpath - identical to hash_for_garbling
        let key = unsafe {
            let gate_id_u64 = gate_id as u64;
            let mut key_u64 = [0u64; 2];
            // Fast domain separation using bit mixing
            key_u64[0] = gate_id_u64 ^ 0x123456789ABCDEF0;
            key_u64[1] = gate_id_u64.wrapping_mul(0xDEADBEEFCAFEBABE);
            core::mem::transmute::<[u64; 2], [u8; 16]>(key_u64)
        };

        // Direct AES encryption without intermediate copies
        let ciphertext = aes128_encrypt_block(key, label.to_bytes())
            .expect("AES-NI should be available when target features are enabled");

        S::from_bytes(ciphertext)
    }
}

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
)))]
#[derive(Clone, Debug, Default)]
pub struct AesNiHasher;

#[cfg(not(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    target_feature = "aes",
    target_feature = "sse2"
)))]
impl GateHasher for AesNiHasher {
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S) {
        panic!()
    }

    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S {
        panic!()
    }
}
