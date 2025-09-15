use crossbeam::channel;
use garbled_snark_verifier::{
    EvaluatedWire, GarbledWire, WireId,
    ark::PrimeField,
    circuit::{
        CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, StreamingResult, WiresObject,
        modes::{EvaluateModeBlake3, GarbleModeBlake3},
    },
    gadgets::{
        bigint::{BigUint as BigUintOutput, bits_from_biguint_with_len},
        bn254::{fp254impl::Fp254Impl, fq::Fq, fq6::Fq6, fq12::Fq12},
    },
};
use itertools::Itertools;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use test_log::test;

// Input wrapper for two Fq12 elements
#[derive(Clone)]
struct Fq12MulInputs {
    a: ark_bn254::Fq12,
    b: ark_bn254::Fq12,
}

#[derive(Clone)]
struct Fq12MulWireRepr {
    a: Fq12,
    b: Fq12,
}

impl Fq12MulInputs {
    fn new(a: ark_bn254::Fq12, b: ark_bn254::Fq12) -> Self {
        Self { a, b }
    }
}

impl CircuitInput for Fq12MulInputs {
    type WireRepr = Fq12MulWireRepr;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Fq12MulWireRepr {
            a: Fq12::new(&mut issue),
            b: Fq12::new(issue),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut ids = repr.a.to_wires_vec();
        ids.extend(repr.b.to_wires_vec());
        ids
    }
}

// Encode inputs for garbling: assign random labels to each bit wire
impl EncodeInput<GarbleModeBlake3> for Fq12MulInputs {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleModeBlake3) {
        let a_m = Fq12::as_montgomery(self.a);
        let b_m = Fq12::as_montgomery(self.b);

        // Helper to feed all bits of an Fq6 into the cache
        fn feed_fq6_bits(val: &ark_bn254::Fq6, wires: &Fq6, cache: &mut GarbleModeBlake3) {
            // For each Fq2(c0,c1) -> for each Fq limb (254 bits)
            let limbs = [val.c0, val.c1, val.c2];
            let wires_arr = [&wires.0[0], &wires.0[1], &wires.0[2]];
            for (fq2_val, fq2_wires) in limbs.into_iter().zip(wires_arr.into_iter()) {
                let c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(fq2_val.c0.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(fq2_val.c1.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();

                for (wire, _bit) in fq2_wires.0[0].0.iter().zip(c0_bits.iter()) {
                    let gw = cache.issue_garbled_wire();
                    cache.feed_wire(*wire, gw);
                }
                for (wire, _bit) in fq2_wires.0[1].0.iter().zip(c1_bits.iter()) {
                    let gw = cache.issue_garbled_wire();
                    cache.feed_wire(*wire, gw);
                }
            }
        }

        feed_fq6_bits(&a_m.c0, &repr.a.0[0], cache);
        feed_fq6_bits(&a_m.c1, &repr.a.0[1], cache);
        feed_fq6_bits(&b_m.c0, &repr.b.0[0], cache);
        feed_fq6_bits(&b_m.c1, &repr.b.0[1], cache);
    }
}

struct EvaluateFq12MulInput {
    inner: Fq12MulInputs,
    wires: Vec<GarbledWire>,
}

impl CircuitInput for EvaluateFq12MulInput {
    type WireRepr = Fq12MulWireRepr;

    fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
        self.inner.allocate(issue)
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        Fq12MulInputs::collect_wire_ids(repr)
    }
}

// Encode inputs for evaluation: same labels but mark active label by bit value
impl EncodeInput<EvaluateModeBlake3> for EvaluateFq12MulInput {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut EvaluateModeBlake3) {
        let a_m = Fq12::as_montgomery(self.inner.a);
        let b_m = Fq12::as_montgomery(self.inner.b);

        // Helper to feed evaluated wires
        fn feed_fq6_bits(
            val: &ark_bn254::Fq6,
            wires: &Fq6,
            labels: &mut impl Iterator<Item = GarbledWire>,
            cache: &mut EvaluateModeBlake3,
        ) {
            let limbs = [val.c0, val.c1, val.c2];
            let wires_arr = [&wires.0[0], &wires.0[1], &wires.0[2]];
            for (fq2_val, fq2_wires) in limbs.into_iter().zip(wires_arr.into_iter()) {
                let c0_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(fq2_val.c0.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();
                let c1_bits = bits_from_biguint_with_len(
                    &BigUintOutput::from(fq2_val.c1.into_bigint()),
                    Fq::N_BITS,
                )
                .unwrap();

                for (wire, bit) in fq2_wires.0[0].0.iter().zip(c0_bits.iter()) {
                    let gw = labels.next().unwrap();
                    cache.feed_wire(*wire, EvaluatedWire::new_from_garbled(&gw, *bit));
                }
                for (wire, bit) in fq2_wires.0[1].0.iter().zip(c1_bits.iter()) {
                    let gw = labels.next().unwrap();
                    cache.feed_wire(*wire, EvaluatedWire::new_from_garbled(&gw, *bit));
                }
            }
        }

        let mut labels = self.wires.iter().cloned();
        feed_fq6_bits(&a_m.c0, &repr.a.0[0], labels.by_ref(), cache);
        feed_fq6_bits(&a_m.c1, &repr.a.0[1], labels.by_ref(), cache);
        feed_fq6_bits(&b_m.c0, &repr.b.0[0], labels.by_ref(), cache);
        feed_fq6_bits(&b_m.c1, &repr.b.0[1], labels.by_ref(), cache);
    }
}

// The circuit under test: Fq12 multiplication (Montgomery)
fn fq12_mul_circuit<C: garbled_snark_verifier::circuit::CircuitContext>(
    ctx: &mut C,
    inputs: &Fq12MulWireRepr,
) -> Vec<WireId> {
    let prod = Fq12::mul_montgomery(ctx, &inputs.a, &inputs.b);
    prod.to_wires_vec()
}

#[test]
fn test_fq12_mul_montgomery_e2e() {
    const SEED: u64 = 0;
    // Deterministic inputs
    let mut rng = ChaChaRng::seed_from_u64(SEED);
    let a = Fq12::random(&mut rng);
    let b = Fq12::random(&mut rng);

    // Prepare inputs (standard form). Encoding converts to Montgomery as needed.
    let inputs = Fq12MulInputs::new(a, b);

    // Garbling phase
    let (garbled_sender, garbled_receiver) = channel::unbounded();
    let garble_result: StreamingResult<_, _, Vec<GarbledWire>> =
        CircuitBuilder::streaming_garbling_blake3(
            inputs.clone(),
            15_000,
            SEED,
            garbled_sender,
            fq12_mul_circuit,
        );

    let true_lbl = garble_result.true_wire_constant.select(true).to_u128();
    let false_lbl = garble_result.false_wire_constant.select(false).to_u128();

    let inputs = EvaluateFq12MulInput {
        inner: inputs,
        wires: garble_result.input_wire_values,
    };

    let eval: garbled_snark_verifier::circuit::StreamingResult<
        EvaluateModeBlake3,
        _,
        Vec<EvaluatedWire>,
    > = CircuitBuilder::<EvaluateModeBlake3>::streaming_evaluation(
        inputs,
        15_000,
        true_lbl,
        false_lbl,
        garbled_receiver,
        fq12_mul_circuit,
    );

    garble_result
        .output_value
        .iter()
        .zip_eq(&eval.output_value)
        .for_each(
            |(
                gw,
                EvaluatedWire {
                    active_label,
                    value,
                },
            )| {
                assert_eq!(
                    gw.select(*value),
                    *active_label,
                    "{gw:?}.select({value} != {active_label:?}"
                );
            },
        );
}
