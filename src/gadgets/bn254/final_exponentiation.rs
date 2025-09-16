//! BN254 final exponentiation (gadgets + native helpers)
//!
//! This module provides a streaming-gadgets implementation of the BN254 final
//! exponentiation over Fq12, along with native (off-circuit) helpers mirroring
//! the structure used in the main branch.

use ark_ec::bn::BnConfig;
use ark_ff::{BitIteratorBE, Field};
use circuit_component_macro::component;

use crate::{CircuitContext, gadgets::bn254::fq12::Fq12};

pub fn conjugate_native(f: ark_bn254::Fq12) -> ark_bn254::Fq12 {
    ark_bn254::Fq12::new(f.c0, -f.c1)
}

pub fn cyclotomic_exp_native(f: ark_bn254::Fq12) -> ark_bn254::Fq12 {
    let mut res = ark_bn254::Fq12::ONE;
    let mut found_nonzero = false;
    for value in BitIteratorBE::without_leading_zeros(ark_bn254::Config::X).map(|e| e as i8) {
        if found_nonzero {
            res.square_in_place();
        }
        if value != 0 {
            found_nonzero = true;
            if value > 0 {
                res *= &f;
            }
        }
    }
    res
}

pub fn exp_by_neg_x_native(f: ark_bn254::Fq12) -> ark_bn254::Fq12 {
    conjugate_native(cyclotomic_exp_native(f))
}

pub fn final_exponentiation_native(f: ark_bn254::Fq12) -> ark_bn254::Fq12 {
    let u = f.inverse().unwrap() * conjugate_native(f);
    let r = u.frobenius_map(2) * u;
    let y0 = exp_by_neg_x_native(r);
    let y1 = y0.square();
    let y2 = y1.square();
    let y3 = y2 * y1;
    let y4 = exp_by_neg_x_native(y3);
    let y5 = y4.square();
    let y6 = exp_by_neg_x_native(y5);
    let y7 = conjugate_native(y3);
    let y8 = conjugate_native(y6);
    let y9 = y8 * y4;
    let y10 = y9 * y7;
    let y11 = y10 * y1;
    let y12 = y10 * y4;
    let y13 = y12 * r;
    let y14 = y11.frobenius_map(1);
    let y15 = y14 * y13;
    let y16 = y10.frobenius_map(2);
    let y17 = y16 * y15;
    let r2 = conjugate_native(r);
    let y18 = r2 * y11;
    let y19 = y18.frobenius_map(3);
    y19 * y17
}

pub fn cyclotomic_exp_fast_inverse_montgomery_fast<C: CircuitContext>(
    circuit: &mut C,
    f: &Fq12,
) -> Fq12 {
    let mut res = Fq12::new_constant(ark_bn254::Fq12::ONE);
    let f_inverse = Fq12::inverse_montgomery(circuit, f);

    let mut found_nonzero = false;
    for value in ark_ff::biginteger::arithmetic::find_naf(ark_bn254::Config::X)
        .into_iter()
        .rev()
    {
        if found_nonzero {
            res = Fq12::cyclotomic_square_montgomery(circuit, &res);
        }

        if value != 0 {
            found_nonzero = true;

            if value > 0 {
                res = Fq12::mul_montgomery(circuit, &res, f);
            } else {
                res = Fq12::mul_montgomery(circuit, &res, &f_inverse);
            }
        }
    }

    res
}

pub fn exp_by_neg_x_montgomery<C: CircuitContext>(circuit: &mut C, f: &Fq12) -> Fq12 {
    let f2 = cyclotomic_exp_fast_inverse_montgomery_fast(circuit, f);
    Fq12::conjugate(circuit, &f2)
}

#[component]
pub fn final_exponentiation_montgomery<C: CircuitContext>(circuit: &mut C, f: &Fq12) -> Fq12 {
    let f_inv = Fq12::inverse_montgomery(circuit, f);
    let f_conjugate = Fq12::conjugate(circuit, f);
    let u = Fq12::mul_montgomery(circuit, &f_inv, &f_conjugate);
    let u_frobenius = Fq12::frobenius_montgomery(circuit, &u, 2);
    let r = Fq12::mul_montgomery(circuit, &u_frobenius, &u);

    let y0 = exp_by_neg_x_montgomery(circuit, &r);
    let y1 = Fq12::square_montgomery(circuit, &y0);
    let y2 = Fq12::square_montgomery(circuit, &y1);
    let y3 = Fq12::mul_montgomery(circuit, &y1, &y2);
    let y4 = exp_by_neg_x_montgomery(circuit, &y3);
    let y5 = Fq12::square_montgomery(circuit, &y4);
    let y6 = exp_by_neg_x_montgomery(circuit, &y5);
    let y7 = Fq12::conjugate(circuit, &y3);
    let y8 = Fq12::conjugate(circuit, &y6);
    let y9 = Fq12::mul_montgomery(circuit, &y8, &y4);
    let y10 = Fq12::mul_montgomery(circuit, &y9, &y7);
    let y11 = Fq12::mul_montgomery(circuit, &y10, &y1);
    let y12 = Fq12::mul_montgomery(circuit, &y10, &y4);
    let y13 = Fq12::mul_montgomery(circuit, &y12, &r);
    let y14 = Fq12::frobenius_montgomery(circuit, &y11, 1);
    let y15 = Fq12::mul_montgomery(circuit, &y14, &y13);
    let y16 = Fq12::frobenius_montgomery(circuit, &y10, 2);
    let y17 = Fq12::mul_montgomery(circuit, &y16, &y15);
    let r2 = Fq12::conjugate(circuit, &r);
    let y18 = Fq12::mul_montgomery(circuit, &r2, &y11);
    let y19 = Fq12::frobenius_montgomery(circuit, &y18, 3);

    Fq12::mul_montgomery(circuit, &y19, &y17)
}

#[cfg(test)]
mod tests {
    use ark_ec::pairing::Pairing;
    use ark_ff::{PrimeField, UniformRand};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::*;
    use crate::{
        WireId,
        circuit::{
            CircuitBuilder, CircuitInput, CircuitMode, CircuitOutput, EncodeInput, StreamingResult,
            WiresObject, modes::ExecuteMode,
        },
        gadgets::{
            bigint::{BigUint as BigUintOutput, bits_from_biguint_with_len},
            bn254::{
                fp254impl::Fp254Impl, fq::Fq as FqWire, fq6::Fq6 as Fq6Wires,
                fq12::Fq12 as Fq12Wires,
            },
        },
    };

    #[test]
    fn test_final_exponentiation_streaming_matches_ark() {
        let mut rng = ChaCha20Rng::seed_from_u64(123);
        let p = ark_bn254::G1Affine::rand(&mut rng);
        let q = ark_bn254::G2Affine::rand(&mut rng);

        let f_ml = ark_bn254::Bn254::multi_miller_loop([p], [q]).0;
        let expected = ark_bn254::Bn254::pairing(p, q);
        let expected_m = Fq12Wires::as_montgomery(expected.0);

        struct In {
            f: ark_bn254::Fq12,
        }
        struct W {
            f: Fq12Wires,
        }
        struct Out {
            value: ark_bn254::Fq12,
        }
        fn encode_fq6_to_wires<M: CircuitMode<WireValue = bool>>(
            val: &ark_bn254::Fq6,
            wires: &Fq6Wires,
            cache: &mut M,
        ) {
            let c0_c0_bits = bits_from_biguint_with_len(
                &BigUintOutput::from(val.c0.c0.into_bigint()),
                FqWire::N_BITS,
            )
            .unwrap();
            let c0_c1_bits = bits_from_biguint_with_len(
                &BigUintOutput::from(val.c0.c1.into_bigint()),
                FqWire::N_BITS,
            )
            .unwrap();
            wires.0[0].0[0]
                .0
                .iter()
                .zip(c0_c0_bits)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            wires.0[0].0[1]
                .0
                .iter()
                .zip(c0_c1_bits)
                .for_each(|(w, b)| cache.feed_wire(*w, b));

            let c1_c0_bits = bits_from_biguint_with_len(
                &BigUintOutput::from(val.c1.c0.into_bigint()),
                FqWire::N_BITS,
            )
            .unwrap();
            let c1_c1_bits = bits_from_biguint_with_len(
                &BigUintOutput::from(val.c1.c1.into_bigint()),
                FqWire::N_BITS,
            )
            .unwrap();
            wires.0[1].0[0]
                .0
                .iter()
                .zip(c1_c0_bits)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            wires.0[1].0[1]
                .0
                .iter()
                .zip(c1_c1_bits)
                .for_each(|(w, b)| cache.feed_wire(*w, b));

            let c2_c0_bits = bits_from_biguint_with_len(
                &BigUintOutput::from(val.c2.c0.into_bigint()),
                FqWire::N_BITS,
            )
            .unwrap();
            let c2_c1_bits = bits_from_biguint_with_len(
                &BigUintOutput::from(val.c2.c1.into_bigint()),
                FqWire::N_BITS,
            )
            .unwrap();
            wires.0[2].0[0]
                .0
                .iter()
                .zip(c2_c0_bits)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
            wires.0[2].0[1]
                .0
                .iter()
                .zip(c2_c1_bits)
                .for_each(|(w, b)| cache.feed_wire(*w, b));
        }

        impl CircuitInput for In {
            type WireRepr = W;
            fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
                W {
                    f: Fq12Wires::new(issue),
                }
            }
            fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<crate::WireId> {
                repr.f.to_wires_vec()
            }
        }
        impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for In {
            fn encode(&self, repr: &W, cache: &mut M) {
                let f_m = Fq12Wires::as_montgomery(self.f);
                encode_fq6_to_wires(&f_m.c0, &repr.f.0[0], cache);
                encode_fq6_to_wires(&f_m.c1, &repr.f.0[1], cache);
            }
        }
        impl CircuitOutput<ExecuteMode> for Out {
            type WireRepr = Fq12Wires;
            fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
                fn decode_fq6_from_wires(
                    wires: &Fq6Wires,
                    cache: &mut ExecuteMode,
                ) -> ark_bn254::Fq6 {
                    let c0_c0 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[0].0[0].0.clone(),
                        cache,
                    );
                    let c0_c1 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[0].0[1].0.clone(),
                        cache,
                    );
                    let c1_c0 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[1].0[0].0.clone(),
                        cache,
                    );
                    let c1_c1 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[1].0[1].0.clone(),
                        cache,
                    );
                    let c2_c0 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[2].0[0].0.clone(),
                        cache,
                    );
                    let c2_c1 = <BigUintOutput as CircuitOutput<ExecuteMode>>::decode(
                        wires.0[2].0[1].0.clone(),
                        cache,
                    );
                    let c0 =
                        ark_bn254::Fq2::new(ark_bn254::Fq::from(c0_c0), ark_bn254::Fq::from(c0_c1));
                    let c1 =
                        ark_bn254::Fq2::new(ark_bn254::Fq::from(c1_c0), ark_bn254::Fq::from(c1_c1));
                    let c2 =
                        ark_bn254::Fq2::new(ark_bn254::Fq::from(c2_c0), ark_bn254::Fq::from(c2_c1));
                    ark_bn254::Fq6::new(c0, c1, c2)
                }
                let c0 = decode_fq6_from_wires(&wires.0[0], cache);
                let c1 = decode_fq6_from_wires(&wires.0[1], cache);
                Self {
                    value: ark_bn254::Fq12::new(c0, c1),
                }
            }
        }

        let input = In { f: f_ml };
        let result: StreamingResult<_, _, Out> =
            CircuitBuilder::streaming_execute(input, 10_000, |ctx, input| {
                final_exponentiation_montgomery(ctx, &input.f)
            });

        assert_eq!(result.output_value.value, expected_m);
    }
}
