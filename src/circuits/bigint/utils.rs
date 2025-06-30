use crate::bag::*;
use num_bigint::BigUint;
use rand::{Rng, rng};
use std::str::FromStr;
// Constant byte array representing 2^254
const TWO_POW_254_BYTES_LE: [u8; 32] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0x40,
];

#[inline(always)]
pub fn biguint_two_pow_254() -> BigUint {
    BigUint::from_bytes_le(&TWO_POW_254_BYTES_LE)
}

pub fn random_biguint() -> BigUint {
    BigUint::from_bytes_le(&rng().random::<[u8; 32]>())
}

pub fn random_biguint_n_bits(n_bits: usize) -> BigUint {
    BigUint::from_bytes_le(&rand::rng().random::<[u8; 32]>())
        % BigUint::from_str("2").unwrap().pow(n_bits as u32)
}

pub fn bits_from_biguint(u: BigUint) -> Vec<bool> {
    let mut bytes = u.to_bytes_le();
    bytes.extend(vec![0_u8; 32 - bytes.len()]);
    let mut bits = Vec::new();
    for byte in bytes {
        for i in 0..8 {
            bits.push(((byte >> i) & 1) == 1)
        }
    }
    bits
}

pub fn biguint_from_bits(bits: Vec<bool>) -> BigUint {
    let zero = BigUint::ZERO;
    let one = BigUint::from(1_u8);
    let mut u = zero.clone();
    for bit in bits.iter().rev() {
        u = u.clone() + u.clone() + if *bit { one.clone() } else { zero.clone() };
    }
    u
}

pub fn n_wires(n: usize) -> Wires {
    (0..n).map(|_| new_wirex()).collect()
}

pub fn biguint_from_wires(wires: Wires) -> BigUint {
    biguint_from_bits(wires.iter().map(|wire| wire.borrow().get_value()).collect())
}

pub fn change_to_neg_pos_decomposition(bits: Vec<bool>) -> Vec<i8> {
    let mut len = bits.len();
    let mut res = vec![0i8; len + 1];
    let mut l: i32 = -1;
    for i in 0..len {
        if !bits[i] {
            l = -1;
        } else if i == len - 1 || !bits[i + 1] {
            if l == -1 {
                res[i] = 1;
            } else {
                res[i + 1] = 1;
                res[l as usize] = -1;
            }
        } else if l == -1 {
            l = i as i32;
        }
    }

    while len > 0 && res[len] == 0 {
        res.pop();
        len -= 1;
    }

    res
}

#[cfg(test)]
pub mod tests {
    use std::cmp::Ordering;

    use super::*;

    #[test]
    fn test_random_biguint() {
        let u = random_biguint();
        println!("u: {:?}", u);
        let b = bits_from_biguint(u.clone());
        let v = biguint_from_bits(b);
        println!("v: {:?}", v);
        assert_eq!(u, v);
    }

    #[test]
    fn test_neg_pos_decomposition() {
        for _ in 0..10 {
            let u = random_biguint();
            let b = bits_from_biguint(u.clone());
            let d = change_to_neg_pos_decomposition(b);
            let len = d.len();
            let mut res = BigUint::ZERO;
            let mut pw = vec![BigUint::from(1_u8); len];
            for i in 1..len {
                pw[i] = pw[i - 1].clone() * BigUint::from(2_u8);
            }

            for i in (0..len).rev() {
                match d[i].cmp(&0) {
                    Ordering::Less => {
                        res -= pw[i].clone();
                    }
                    Ordering::Equal => (),
                    Ordering::Greater => {
                        res += pw[i].clone();
                    }
                }
            }

            assert!(res == u);
        }
    }
}
