//! Gate hashers used by garbling/degabbling, moved to crate root.
//! These mirror the previous implementations under core::gate::garbling::hashers
//! without functional changes.

use crate::{S, core::s::S_SIZE};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HasherKind {
    Blake3,
    AesNi,
}

pub mod aes_ni;

pub trait GateHasher: HashWithGate<1> + HashWithGate<2> {}
impl<H: HashWithGate<1> + HashWithGate<2>> GateHasher for H {}

pub trait HashWithGate<const N: usize>: Clone + Send + Sync {
    fn hash_with_gate(labels: &[S; N], gate_id: usize) -> [S; N];
}

#[derive(Clone, Debug, Default)]
pub struct Blake3Hasher;

impl HashWithGate<2> for Blake3Hasher {
    fn hash_with_gate(labels: &[S; 2], gate_id: usize) -> [S; 2] {
        let [selected_label, other_label] = labels;

        let [h_selected] = Self::hash_with_gate(&[*selected_label], gate_id);
        let [h_other] = Self::hash_with_gate(&[*other_label], gate_id);

        [h_selected, h_other]
    }
}

impl HashWithGate<1> for Blake3Hasher {
    fn hash_with_gate(label: &[S; 1], gate_id: usize) -> [S; 1] {
        let mut result = [0u8; S_SIZE];
        let mut hasher = blake3::Hasher::new();

        let b = label[0].to_bytes();

        hasher.update(&b);
        hasher.update(&gate_id.to_le_bytes());

        let hash = hasher.finalize();
        result.copy_from_slice(&hash.as_bytes()[0..S_SIZE]);

        [S::from_bytes(result)]
    }
}

#[derive(Clone, Debug, Default)]
pub struct AesNiHasher;

#[inline(always)]
fn to_tweak(gate_id: usize) -> [u8; S_SIZE] {
    let gate_id_u64 = gate_id as u64;

    let t0 = gate_id_u64 ^ 0x1234_5678_9ABC_DEF0u64;
    let t1 = gate_id_u64.wrapping_mul(0xDEAD_BEEF_CAFE_BABEu64);

    u64_to_mask(t0, t1)
}

impl HashWithGate<2> for AesNiHasher {
    #[inline(always)]
    fn hash_with_gate(labels: &[S; 2], gate_id: usize) -> [S; 2] {
        let (c0, c1) = aes_ni::aes128_encrypt2_blocks_static_xor(
            labels[0].to_bytes(),
            labels[1].to_bytes(),
            to_tweak(gate_id),
        )
        .expect("AES backend should be available (HW or software)");

        [S::from_bytes(c0), S::from_bytes(c1)]
    }
}

impl HashWithGate<1> for AesNiHasher {
    #[inline(always)]
    fn hash_with_gate(label: &[S; 1], gate_id: usize) -> [S; 1] {
        let c = aes_ni::aes128_encrypt_block_static_xor(label[0].to_bytes(), to_tweak(gate_id))
            .expect("AES backend should be available (HW or software)");
        [S::from_bytes(c)]
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
