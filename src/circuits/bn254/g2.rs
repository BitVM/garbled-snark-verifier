use crate::{bag::*, circuits::bn254::fq2::Fq2};
use ark_ff::UniformRand;
use ark_std::rand::SeedableRng;
use rand::{Rng, rng};
use rand_chacha::ChaCha20Rng;

pub struct G2Projective;

impl G2Projective {
    pub const N_BITS: usize = 3 * Fq2::N_BITS;

    pub fn as_montgomery(p: ark_bn254::G2Projective) -> ark_bn254::G2Projective {
        ark_bn254::G2Projective {
            x: Fq2::as_montgomery(p.x),
            y: Fq2::as_montgomery(p.y),
            z: Fq2::as_montgomery(p.z),
        }
    }

    pub fn from_montgomery(p: ark_bn254::G2Projective) -> ark_bn254::G2Projective {
        ark_bn254::G2Projective {
            x: Fq2::from_montgomery(p.x),
            y: Fq2::from_montgomery(p.y),
            z: Fq2::from_montgomery(p.z),
        }
    }

    pub fn random() -> ark_bn254::G2Projective {
        let mut prng = ChaCha20Rng::seed_from_u64(rng().random());
        ark_bn254::G2Projective::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::G2Projective) -> Vec<bool> {
        let mut bits = Vec::new();
        bits.extend(Fq2::to_bits(u.x));
        bits.extend(Fq2::to_bits(u.y));
        bits.extend(Fq2::to_bits(u.z));
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::G2Projective {
        let bits1 = &bits[0..Fq2::N_BITS].to_vec();
        let bits2 = &bits[Fq2::N_BITS..Fq2::N_BITS * 2].to_vec();
        let bits3 = &bits[Fq2::N_BITS * 2..Fq2::N_BITS * 3].to_vec();
        ark_bn254::G2Projective::new(
            Fq2::from_bits(bits1.clone()),
            Fq2::from_bits(bits2.clone()),
            Fq2::from_bits(bits3.clone()),
        )
    }

    pub fn from_bits_unchecked(bits: Vec<bool>) -> ark_bn254::G2Projective {
        let bits1 = &bits[0..Fq2::N_BITS].to_vec();
        let bits2 = &bits[Fq2::N_BITS..Fq2::N_BITS * 2].to_vec();
        let bits3 = &bits[Fq2::N_BITS * 2..Fq2::N_BITS * 3].to_vec();
        ark_bn254::G2Projective {
            x: Fq2::from_bits(bits1.clone()),
            y: Fq2::from_bits(bits2.clone()),
            z: Fq2::from_bits(bits3.clone()),
        }
    }

    pub fn wires() -> Wires {
        (0..Self::N_BITS).map(|_| new_wirex()).collect()
    }

    pub fn wires_set(u: ark_bn254::G2Projective) -> Wires {
        Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                let wire = new_wirex();
                wire.borrow_mut().set(*bit);
                wire
            })
            .collect()
    }

    pub fn wires_set_montgomery(u: ark_bn254::G2Projective) -> Wires {
        Self::wires_set(Self::as_montgomery(u))
    }

    pub fn from_wires(wires: Wires) -> ark_bn254::G2Projective {
        Self::from_bits(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_wires_unchecked(wires: Wires) -> ark_bn254::G2Projective {
        Self::from_bits_unchecked(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_montgomery_wires_unchecked(wires: Wires) -> ark_bn254::G2Projective {
        Self::from_montgomery(Self::from_wires_unchecked(wires))
    }
}

pub struct G2Affine;

impl G2Affine {
    pub const N_BITS: usize = 2 * Fq2::N_BITS;

    pub fn as_montgomery(p: ark_bn254::G2Affine) -> ark_bn254::G2Affine {
        ark_bn254::G2Affine {
            x: Fq2::as_montgomery(p.x),
            y: Fq2::as_montgomery(p.y),
            infinity: false,
        }
    }

    pub fn from_montgomery(p: ark_bn254::G2Affine) -> ark_bn254::G2Affine {
        ark_bn254::G2Affine {
            x: Fq2::from_montgomery(p.x),
            y: Fq2::from_montgomery(p.y),
            infinity: false,
        }
    }

    pub fn random() -> ark_bn254::G2Affine {
        let mut prng = ChaCha20Rng::seed_from_u64(rng().random());
        ark_bn254::G2Affine::rand(&mut prng)
    }

    pub fn to_bits(u: ark_bn254::G2Affine) -> Vec<bool> {
        let mut bits = Vec::new();
        bits.extend(Fq2::to_bits(u.x));
        bits.extend(Fq2::to_bits(u.y));
        bits
    }

    pub fn from_bits(bits: Vec<bool>) -> ark_bn254::G2Affine {
        let bits1 = &bits[0..Fq2::N_BITS].to_vec();
        let bits2 = &bits[Fq2::N_BITS..Fq2::N_BITS * 2].to_vec();
        ark_bn254::G2Affine::new(Fq2::from_bits(bits1.clone()), Fq2::from_bits(bits2.clone()))
    }

    pub fn from_bits_unchecked(bits: Vec<bool>) -> ark_bn254::G2Affine {
        let bits1 = &bits[0..Fq2::N_BITS].to_vec();
        let bits2 = &bits[Fq2::N_BITS..Fq2::N_BITS * 2].to_vec();
        ark_bn254::G2Affine {
            x: Fq2::from_bits(bits1.clone()),
            y: Fq2::from_bits(bits2.clone()),
            infinity: false,
        }
    }

    pub fn wires_set(u: ark_bn254::G2Affine) -> Wires {
        Self::to_bits(u)[0..Self::N_BITS]
            .iter()
            .map(|bit| {
                let wire = new_wirex();
                wire.borrow_mut().set(*bit);
                wire
            })
            .collect()
    }

    pub fn wires_set_montgomery(u: ark_bn254::G2Affine) -> Wires {
        Self::wires_set(Self::as_montgomery(u))
    }

    pub fn from_wires(wires: Wires) -> ark_bn254::G2Affine {
        Self::from_bits(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_wires_unchecked(wires: Wires) -> ark_bn254::G2Affine {
        Self::from_bits_unchecked(wires.iter().map(|wire| wire.borrow().get_value()).collect())
    }

    pub fn from_montgomery_wires_unchecked(wires: Wires) -> ark_bn254::G2Affine {
        Self::from_montgomery(Self::from_wires_unchecked(wires))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g2p_random() {
        let u = G2Projective::random();
        println!("u: {:?}", u);
        let b = G2Projective::to_bits(u);
        let v = G2Projective::from_bits(b);
        println!("v: {:?}", v);
        assert_eq!(u, v);
    }

    #[test]
    fn test_g2a_random() {
        let u = G2Affine::random();
        println!("u: {:?}", u);
        let b = G2Affine::to_bits(u);
        let v = G2Affine::from_bits(b);
        println!("v: {:?}", v);
        assert_eq!(u, v);
    }
}
