use num_bigint::BigUint;

/// Trait for types that can be used as off-circuit parameters.
/// These parameters affect component structure but are not circuit wires.
pub trait OffCircuitParam {
    /// Convert the parameter to bytes for key generation
    fn to_key_bytes(&self) -> Vec<u8>;
}

// Basic types
impl OffCircuitParam for usize {
    fn to_key_bytes(&self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
}

impl OffCircuitParam for bool {
    fn to_key_bytes(&self) -> Vec<u8> {
        vec![if *self { 1 } else { 0 }]
    }
}

// BigUint
impl OffCircuitParam for BigUint {
    fn to_key_bytes(&self) -> Vec<u8> {
        self.to_bytes_le()
    }
}

// Field elements
impl OffCircuitParam for ark_bn254::Fq {
    fn to_key_bytes(&self) -> Vec<u8> {
        use ark_ff::{BigInteger, PrimeField};
        self.into_bigint().to_bytes_le()
    }
}

impl OffCircuitParam for ark_bn254::Fr {
    fn to_key_bytes(&self) -> Vec<u8> {
        use ark_ff::{BigInteger, PrimeField};
        self.into_bigint().to_bytes_le()
    }
}

impl OffCircuitParam for ark_bn254::Fq2 {
    fn to_key_bytes(&self) -> Vec<u8> {
        use ark_ff::{BigInteger, PrimeField};
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.c0.into_bigint().to_bytes_le());
        bytes.extend_from_slice(&self.c1.into_bigint().to_bytes_le());
        bytes
    }
}

// Generic implementation for Projective points
// Works for both G1 and G2 since they have different coordinate representations
impl<P: ark_ec::short_weierstrass::SWCurveConfig> OffCircuitParam
    for ark_ec::short_weierstrass::Projective<P>
{
    fn to_key_bytes(&self) -> Vec<u8> {
        // Use the projective coordinates directly as bytes
        // This gives unique representation for each point
        // We use std::ptr to get raw bytes from the coordinates
        unsafe {
            let ptr = self as *const _ as *const u8;
            let size = std::mem::size_of_val(self);
            std::slice::from_raw_parts(ptr, size).to_vec()
        }
    }
}

impl OffCircuitParam for ark_bn254::G2Affine {
    fn to_key_bytes(&self) -> Vec<u8> {
        use ark_ff::{BigInteger, PrimeField};
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.x.c0.into_bigint().to_bytes_le());
        bytes.extend_from_slice(&self.x.c1.into_bigint().to_bytes_le());
        bytes.extend_from_slice(&self.y.c0.into_bigint().to_bytes_le());
        bytes.extend_from_slice(&self.y.c1.into_bigint().to_bytes_le());
        bytes.push(if self.infinity { 1 } else { 0 });
        bytes
    }
}

// Groth16 verifying key
impl OffCircuitParam for ark_groth16::VerifyingKey<ark_bn254::Bn254> {
    fn to_key_bytes(&self) -> Vec<u8> {
        use ark_ec::AffineRepr;
        use ark_ff::{BigInteger, PrimeField};

        let mut bytes = Vec::new();

        // Alpha G1
        bytes.push(if self.alpha_g1.is_zero() { 1 } else { 0 });
        if !self.alpha_g1.is_zero() {
            bytes.extend_from_slice(&self.alpha_g1.x.into_bigint().to_bytes_le());
            bytes.extend_from_slice(&self.alpha_g1.y.into_bigint().to_bytes_le());
        }

        // Beta G2
        bytes.push(if self.beta_g2.is_zero() { 1 } else { 0 });
        if !self.beta_g2.is_zero() {
            bytes.extend_from_slice(&self.beta_g2.x.c0.into_bigint().to_bytes_le());
            bytes.extend_from_slice(&self.beta_g2.x.c1.into_bigint().to_bytes_le());
            bytes.extend_from_slice(&self.beta_g2.y.c0.into_bigint().to_bytes_le());
            bytes.extend_from_slice(&self.beta_g2.y.c1.into_bigint().to_bytes_le());
        }

        // Gamma G2
        bytes.push(if self.gamma_g2.is_zero() { 1 } else { 0 });
        if !self.gamma_g2.is_zero() {
            bytes.extend_from_slice(&self.gamma_g2.x.c0.into_bigint().to_bytes_le());
            bytes.extend_from_slice(&self.gamma_g2.x.c1.into_bigint().to_bytes_le());
            bytes.extend_from_slice(&self.gamma_g2.y.c0.into_bigint().to_bytes_le());
            bytes.extend_from_slice(&self.gamma_g2.y.c1.into_bigint().to_bytes_le());
        }

        // Delta G2
        bytes.push(if self.delta_g2.is_zero() { 1 } else { 0 });
        if !self.delta_g2.is_zero() {
            bytes.extend_from_slice(&self.delta_g2.x.c0.into_bigint().to_bytes_le());
            bytes.extend_from_slice(&self.delta_g2.x.c1.into_bigint().to_bytes_le());
            bytes.extend_from_slice(&self.delta_g2.y.c0.into_bigint().to_bytes_le());
            bytes.extend_from_slice(&self.delta_g2.y.c1.into_bigint().to_bytes_le());
        }

        // Gamma ABC G1 (vector of points)
        bytes.extend_from_slice(&self.gamma_abc_g1.len().to_le_bytes());
        for point in &self.gamma_abc_g1 {
            bytes.push(if point.is_zero() { 1 } else { 0 });
            if !point.is_zero() {
                bytes.extend_from_slice(&point.x.into_bigint().to_bytes_le());
                bytes.extend_from_slice(&point.y.into_bigint().to_bytes_le());
            }
        }

        bytes
    }
}

// Slices of types that implement OffCircuitParam
impl<T: OffCircuitParam> OffCircuitParam for [T] {
    fn to_key_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.len().to_le_bytes());
        for item in self {
            bytes.extend_from_slice(&item.to_key_bytes());
        }
        bytes
    }
}

// References to types that implement OffCircuitParam
impl<T: OffCircuitParam + ?Sized> OffCircuitParam for &T {
    fn to_key_bytes(&self) -> Vec<u8> {
        (*self).to_key_bytes()
    }
}
