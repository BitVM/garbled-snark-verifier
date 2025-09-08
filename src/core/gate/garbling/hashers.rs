use super::{
    super::GateId,
    aes_ni::{aes128_encrypt_block_static_xor, aes128_encrypt2_blocks_static_xor},
};
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

#[derive(Clone, Debug, Default)]
pub struct AesNiHasher;

impl GateHasher for AesNiHasher {
    #[inline(always)]
    fn hash_for_garbling(selected_label: &S, other_label: &S, gate_id: GateId) -> (S, S) {
        // GateId as tweak: XOR pre-whitening with a 128-bit mix of gate_id
        let gate_id_u64 = gate_id as u64;
        let t0 = gate_id_u64 ^ 0x1234_5678_9ABC_DEF0u64;
        let t1 = gate_id_u64.wrapping_mul(0xDEAD_BEEF_CAFE_BABEu64);

        let (c0, c1) = aes128_encrypt2_blocks_static_xor(
            selected_label.to_bytes(),
            other_label.to_bytes(),
            u64_to_mask(t0, t1),
        )
        .expect("AES backend should be available (HW or software)");
        (S::from_bytes(c0), S::from_bytes(c1))
    }

    #[inline(always)]
    fn hash_for_degarbling(label: &S, gate_id: GateId) -> S {
        // Same tweak computation as in garbling
        let gate_id_u64 = gate_id as u64;
        let t0 = gate_id_u64 ^ 0x1234_5678_9ABC_DEF0u64;
        let t1 = gate_id_u64.wrapping_mul(0xDEAD_BEEF_CAFE_BABEu64);
        let c = aes128_encrypt_block_static_xor(label.to_bytes(), u64_to_mask(t0, t1))
            .expect("AES backend should be available (HW or software)");
        S::from_bytes(c)
    }
}

#[inline(always)]
fn u64_to_mask(t0: u64, t1: u64) -> [u8; S_SIZE] {
    // Build mask in the same lane order as _mm_set_epi64x(t1, t0)
    let mut m = [0u8; S_SIZE];
    m[..8].copy_from_slice(&t0.to_le_bytes());
    m[8..].copy_from_slice(&t1.to_le_bytes());
    m
}
