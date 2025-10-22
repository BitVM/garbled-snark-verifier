use std::array;

use garbled_snark_verifier::{
    AESAccumulatingHash, AESAccumulatingHashBatch,
    circuit::{
        CircuitBuilder, CircuitInput, EncodeInput, StreamingResult, WiresObject, modes::GarbleMode,
    },
    gadgets::bigint::{self, BigIntWires, BigUint},
    hashers::AesNiHasher,
};

use garbled_snark_verifier::ark;
use garbled_snark_verifier::circuit::CircuitMode;
use garbled_snark_verifier::circuit::MultiCiphertextHandler;
use garbled_snark_verifier::circuit::modes::MultigarblingMode;
use garbled_snark_verifier::gadgets::bn254::fq::Fq;
use garbled_snark_verifier::{GarbledWire, WireId};

const CAP_SMALL: usize = 50_000;
const CAP_MEDIUM: usize = 120_000;

fn seeds_for<const N: usize>(base: u64) -> [u64; N] {
    array::from_fn(|i| base.wrapping_add(i as u64))
}

macro_rules! equiv {
    ($name:ident, N=$n:expr, inputs=$inputs:expr, cap=$cap:expr, seed=$seed:expr, |$root:ident, $inp:ident| $body:block) => {
        #[test]
        fn $name() {
            const N: usize = $n;
            let inputs = $inputs;
            let seeds = seeds_for::<N>($seed);
            let multi = CircuitBuilder::run_streaming::<_, _, Vec<_>>(
                inputs.clone(),
                MultigarblingMode::<AesNiHasher, AESAccumulatingHashBatch<N>, N>::new(
                    $cap,
                    seeds,
                    AESAccumulatingHashBatch::<N>::default(),
                ),
                |$root, $inp| $body,
            );

            let multi_hashes: Vec<[u8; 16]> = multi.ciphertext_handler_result.into_iter().collect();

            let mut seq_hashes: Vec<[u8; 16]> = Vec::with_capacity(N);
            for i in 0..N {
                let seq: StreamingResult<
                    GarbleMode<AesNiHasher, AESAccumulatingHash>,
                    _,
                    Vec<GarbledWire>,
                > = CircuitBuilder::<GarbleMode<_, _>>::streaming_garbling(
                    inputs.clone(),
                    $cap,
                    seeds[i],
                    AESAccumulatingHash::default(),
                    |$root, $inp| $body,
                );
                seq_hashes.push(seq.ciphertext_handler_result);
            }

            assert_eq!(multi_hashes, seq_hashes);
        }
    };
}

#[derive(Clone)]
struct BigIntPairInput {
    len: usize,
}

impl BigIntPairInput {
    fn new(len: usize) -> Self {
        Self { len }
    }
}

impl CircuitInput for BigIntPairInput {
    type WireRepr = [BigIntWires; 2];

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        array::from_fn(|_| BigIntWires::new(&mut issue, self.len))
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.iter().flat_map(|w| w.iter().copied()).collect()
    }
}

impl<
    H: garbled_snark_verifier::hashers::GateHasher,
    CTH: garbled_snark_verifier::circuit::CiphertextHandler,
> EncodeInput<GarbleMode<H, CTH>> for BigIntPairInput
{
    fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleMode<H, CTH>) {
        for bn in repr {
            for w in bn.iter() {
                let gw: GarbledWire = cache.issue_garbled_wire();
                cache.feed_wire(*w, gw);
            }
        }
    }
}

impl<
    H: garbled_snark_verifier::hashers::GateHasher,
    MCTH: MultiCiphertextHandler<N>,
    const N: usize,
> EncodeInput<MultigarblingMode<H, MCTH, N>> for BigIntPairInput
where
    <MCTH as MultiCiphertextHandler<N>>::Result: Default,
{
    fn encode(&self, repr: &Self::WireRepr, cache: &mut MultigarblingMode<H, MCTH, N>) {
        for bn in repr {
            for w in bn.iter() {
                let gws: [GarbledWire; N] = cache.issue_garbled_wire_batch();
                cache.feed_wire(*w, gws);
            }
        }
    }
}

#[derive(Clone)]
struct BigIntSingleInput {
    len: usize,
}

impl BigIntSingleInput {
    fn new(len: usize) -> Self {
        Self { len }
    }
}

impl CircuitInput for BigIntSingleInput {
    type WireRepr = BigIntWires;

    fn allocate(&self, issue: impl FnMut() -> WireId) -> Self::WireRepr {
        BigIntWires::new(issue, self.len)
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.iter().copied().collect()
    }
}

impl<
    H: garbled_snark_verifier::hashers::GateHasher,
    CTH: garbled_snark_verifier::circuit::CiphertextHandler,
> EncodeInput<GarbleMode<H, CTH>> for BigIntSingleInput
{
    fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleMode<H, CTH>) {
        for w in repr.iter() {
            let gw = cache.issue_garbled_wire();
            cache.feed_wire(*w, gw);
        }
    }
}

impl<
    H: garbled_snark_verifier::hashers::GateHasher,
    MCTH: MultiCiphertextHandler<N>,
    const N: usize,
> EncodeInput<MultigarblingMode<H, MCTH, N>> for BigIntSingleInput
where
    <MCTH as MultiCiphertextHandler<N>>::Result: Default,
{
    fn encode(&self, repr: &Self::WireRepr, cache: &mut MultigarblingMode<H, MCTH, N>) {
        for w in repr.iter() {
            let gws = cache.issue_garbled_wire_batch();
            cache.feed_wire(*w, gws);
        }
    }
}

#[derive(Clone)]
struct FqPairInput;

impl CircuitInput for FqPairInput {
    type WireRepr = [Fq; 2];

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        [Fq::new(&mut issue), Fq::new(issue)]
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.iter().flat_map(|fq| fq.0.iter().copied()).collect()
    }
}

impl<
    H: garbled_snark_verifier::hashers::GateHasher,
    CTH: garbled_snark_verifier::circuit::CiphertextHandler,
> EncodeInput<GarbleMode<H, CTH>> for FqPairInput
{
    fn encode(&self, repr: &Self::WireRepr, cache: &mut GarbleMode<H, CTH>) {
        for fq in repr {
            for w in fq.0.iter() {
                let gw = cache.issue_garbled_wire();
                cache.feed_wire(*w, gw);
            }
        }
    }
}

impl<
    H: garbled_snark_verifier::hashers::GateHasher,
    MCTH: MultiCiphertextHandler<N>,
    const N: usize,
> EncodeInput<MultigarblingMode<H, MCTH, N>> for FqPairInput
where
    <MCTH as MultiCiphertextHandler<N>>::Result: Default,
{
    fn encode(&self, repr: &Self::WireRepr, cache: &mut MultigarblingMode<H, MCTH, N>) {
        for fq in repr {
            for w in fq.0.iter() {
                let gws = cache.issue_garbled_wire_batch();
                cache.feed_wire(*w, gws);
            }
        }
    }
}

equiv!(
    test_equiv_bigint_add_n1,
    N = 1,
    inputs = BigIntPairInput::new(8),
    cap = CAP_SMALL,
    seed = 424242,
    |root, input| {
        let [a, b] = input;
        let out = bigint::add(root, a, b);
        out.to_wires_vec()
    }
);

equiv!(
    test_equiv_bigint_add_n8,
    N = 8,
    inputs = BigIntPairInput::new(8),
    cap = CAP_SMALL,
    seed = 424242,
    |root, input| {
        let [a, b] = input;
        let out = bigint::add(root, a, b);
        out.to_wires_vec()
    }
);

equiv!(
    test_equiv_bigint_add_n3_bits5,
    N = 3,
    inputs = BigIntPairInput::new(5),
    cap = CAP_SMALL,
    seed = 424242,
    |root, input| {
        let [a, b] = input;
        let out = bigint::add(root, a, b);
        out.to_wires_vec()
    }
);

equiv!(
    test_equiv_bigint_mul_n3_bits5,
    N = 3,
    inputs = BigIntPairInput::new(5),
    cap = CAP_SMALL,
    seed = 1337,
    |root, input| {
        let [a, b] = input;
        let out = bigint::mul(root, a, b);
        out.to_wires_vec()
    }
);

equiv!(
    test_equiv_bigint_mul_n3_bits16,
    N = 3,
    inputs = BigIntPairInput::new(16),
    cap = CAP_SMALL,
    seed = 1337,
    |root, input| {
        let [a, b] = input;
        let out = bigint::mul(root, a, b);
        out.to_wires_vec()
    }
);

equiv!(
    test_equiv_bigint_add_constant_n3_bits16,
    N = 3,
    inputs = BigIntSingleInput::new(16),
    cap = CAP_SMALL,
    seed = 7777,
    |root, a| {
        let c = BigUint::from(12345u64);
        let out = bigint::add_constant(root, a, &c);
        out.to_wires_vec()
    }
);

equiv!(
    test_equiv_fq_add_n1,
    N = 1,
    inputs = FqPairInput,
    cap = CAP_MEDIUM,
    seed = 9999,
    |root, input| {
        let [a, b] = input;
        Fq::add(root, a, b).to_wires_vec()
    }
);

equiv!(
    test_equiv_fq_add_n8,
    N = 8,
    inputs = FqPairInput,
    cap = CAP_MEDIUM,
    seed = 9999,
    |root, input| {
        let [a, b] = input;
        Fq::add(root, a, b).to_wires_vec()
    }
);

equiv!(
    test_equiv_fq_mul_mont_n4,
    N = 4,
    inputs = FqPairInput,
    cap = CAP_MEDIUM,
    seed = 123456,
    |root, input| {
        let [a, b] = input;
        Fq::mul_montgomery(root, a, b).to_wires_vec()
    }
);

equiv!(
    test_equiv_fq_add_const_n3,
    N = 3,
    inputs = FqPairInput,
    cap = CAP_MEDIUM,
    seed = 31415,
    |root, input| {
        let [a, _b] = input;
        let c = ark::Fq::from(7u64);
        Fq::add_constant(root, a, &c).to_wires_vec()
    }
);

equiv!(
    test_equiv_fq_mul_by_const_mont_n3,
    N = 3,
    inputs = FqPairInput,
    cap = CAP_MEDIUM,
    seed = 27182,
    |root, input| {
        let [a, _b] = input;
        let c_mont = Fq::as_montgomery(ark::Fq::from(11u64));
        Fq::mul_by_constant_montgomery(root, a, &c_mont).to_wires_vec()
    }
);

equiv!(
    test_equiv_bigint_equal_n1_bits5,
    N = 1,
    inputs = BigIntPairInput::new(5),
    cap = CAP_SMALL,
    seed = 5001,
    |root, input| {
        let [a, b] = input;
        vec![bigint::equal(root, a, b)]
    }
);

equiv!(
    test_equiv_bigint_gt_n3_bits8,
    N = 3,
    inputs = BigIntPairInput::new(8),
    cap = CAP_SMALL,
    seed = 5002,
    |root, input| {
        let [a, b] = input;
        vec![bigint::greater_than(root, a, b)]
    }
);

equiv!(
    test_equiv_bigint_lt_const_n3_bits16,
    N = 3,
    inputs = BigIntSingleInput::new(16),
    cap = CAP_SMALL,
    seed = 5003,
    |root, a| {
        let c = BigUint::from(0x1234u64);
        vec![bigint::less_than_constant(root, a, &c)]
    }
);

equiv!(
    test_equiv_fq_sub_n1,
    N = 1,
    inputs = FqPairInput,
    cap = CAP_MEDIUM,
    seed = 5004,
    |root, input| {
        let [a, b] = input;
        Fq::sub(root, a, b).to_wires_vec()
    }
);

equiv!(
    test_equiv_fq_square_mont_n3,
    N = 3,
    inputs = FqPairInput,
    cap = CAP_MEDIUM,
    seed = 5005,
    |root, input| {
        let [a, _b] = input;
        Fq::square_montgomery(root, a).to_wires_vec()
    }
);
