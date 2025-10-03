//! Binary Circuit Implementation of Blake3 Hash
//! Supports input message of size less than or equals 1024 bytes only.
//! This limited range is sufficient for usecases concerning garbled circuit inputs

use crate::{
    CircuitContext, WireId,
    circuit::{
        CircuitInput, CircuitMode, CircuitOutput, EncodeInput, ExecuteMode, FALSE_WIRE, TRUE_WIRE,
        WiresObject,
    },
};
use core::cmp::min;

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const ROOT: u32 = 1 << 3;

type U32 = [WireId; 32];
type U8 = [WireId; 8];

use ark_std::iter;
pub fn new_u8(issue: impl FnMut() -> WireId) -> U8 {
    let v: Vec<WireId> = iter::repeat_with(issue).take(8).collect();
    let v: U8 = v.try_into().unwrap();
    v
}

// Input Message is a byte array of size 'N' for N < 1024
#[derive(Debug, Clone, Copy)]
pub struct InputMessage<const N: usize> {
    pub byte_arr: [u8; N],
}

// Input Message is a byte array of size 'N' for N < 1024
#[derive(Debug, Clone, Copy)]
pub struct InputMessageWires<const N: usize> {
    pub byte_arr: [U8; N],
}

impl<const N: usize> InputMessageWires<N> {
    pub fn new(mut issue: impl FnMut() -> WireId) -> Self {
        let wires: Vec<U8> = std::array::from_fn::<_, N, _>(|_| new_u8(&mut issue)).to_vec();
        let wires: [U8; N] = wires.try_into().unwrap();
        InputMessageWires { byte_arr: wires }
    }
}

impl<const N: usize> WiresObject for InputMessageWires<N> {
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.byte_arr
            .iter()
            .flat_map(|fq| fq.iter().copied())
            .collect()
    }

    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        InputMessageWires::new(wire_gen)
    }
}

impl<const N: usize> CircuitInput for InputMessage<N> {
    type WireRepr = InputMessageWires<N>;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        InputMessageWires::new(&mut issue)
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        repr.byte_arr
            .iter()
            .flat_map(|fq| fq.iter().copied())
            .collect()
    }
}

fn u8_to_bits_le(n: u8) -> [bool; 8] {
    let v: Vec<bool> = (0..8).map(|i| (n >> i) & 1 != 0).collect();
    v.try_into().unwrap()
}

impl<const N: usize, M: CircuitMode<WireValue = bool>> EncodeInput<M> for InputMessage<N> {
    fn encode(&self, repr: &Self::WireRepr, cache: &mut M) {
        self.byte_arr
            .iter()
            .zip(repr.byte_arr.iter())
            .for_each(|(x, y)| {
                let x_bits = u8_to_bits_le(*x);
                for itr in 0..8 {
                    cache.feed_wire(y[itr], x_bits[itr]);
                }
            });
    }
}

// 32 byte message hash
pub struct HashOutput {
    pub value: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct HashOutputWires {
    pub value: [U8; 32],
}

impl HashOutputWires {
    pub fn new(mut issue: impl FnMut() -> WireId) -> Self {
        let wires: Vec<U8> = std::array::from_fn::<_, 32, _>(|_| new_u8(&mut issue)).to_vec();
        let wires: [U8; 32] = wires.try_into().unwrap();
        HashOutputWires { value: wires }
    }
}

impl WiresObject for HashOutputWires {
    fn clone_from(&self, wire_gen: &mut impl FnMut() -> WireId) -> Self {
        HashOutputWires::new(wire_gen)
    }
    fn to_wires_vec(&self) -> Vec<WireId> {
        self.value.into_iter().flatten().collect()
    }
}

impl CircuitOutput<ExecuteMode> for HashOutput {
    type WireRepr = HashOutputWires; // [U8; 32]

    fn decode(wires: Self::WireRepr, cache: &mut ExecuteMode) -> Self {
        let wires = wires.to_wires_vec();

        let bit_len = wires.len();

        let mut bytes = vec![0u8; bit_len.div_ceil(8)];

        for (i, w) in wires.iter().enumerate() {
            let bit = cache.lookup_wire(*w).expect("missing wire value");
            if bit {
                bytes[i / 8] |= 1u8 << (i % 8);
            }
        }
        let bytes: [u8; 32] = bytes.try_into().unwrap();
        HashOutput { value: bytes }
    }
}

fn const_u32_to_bits_le(n: u32) -> U32 {
    let vs: Vec<bool> = (0..32).map(|i| (n >> i) & 1 != 0).collect();
    let vs: Vec<WireId> = vs
        .iter()
        .map(|v| if !v { FALSE_WIRE } else { TRUE_WIRE })
        .collect();
    vs.try_into().unwrap()
}

fn get_iv() -> [U32; 8] {
    let iv2: [U32; 8] = [
        const_u32_to_bits_le(0x6A09E667),
        const_u32_to_bits_le(0xBB67AE85),
        const_u32_to_bits_le(0x3C6EF372),
        const_u32_to_bits_le(0xA54FF53A),
        const_u32_to_bits_le(0x510E527F),
        const_u32_to_bits_le(0x9B05688C),
        const_u32_to_bits_le(0x1F83D9AB),
        const_u32_to_bits_le(0x5BE0CD19),
    ];
    iv2
}

const MSG_PERMUTATION: [u8; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

fn xor_wire<C: CircuitContext>(ctx: &mut C, a: WireId, b: WireId) -> WireId {
    let result = ctx.issue_wire();
    ctx.add_gate(crate::Gate::xor(a, b, result));
    result
}

fn and_wire<C: CircuitContext>(ctx: &mut C, a: WireId, b: WireId) -> WireId {
    let result = ctx.issue_wire();
    ctx.add_gate(crate::Gate::and(a, b, result));
    result
}

fn wrapping_add_u32<C: CircuitContext>(circuit: &mut C, a: U32, b: U32) -> U32 {
    let mut result = [FALSE_WIRE; 32];
    let mut carry = FALSE_WIRE;

    for i in 0..32 {
        let ai = a[i];
        let bi = b[i];
        let p = xor_wire(circuit, ai, bi);
        let g = and_wire(circuit, ai, bi);
        result[i] = xor_wire(circuit, p, carry);
        let t0 = and_wire(circuit, p, carry);
        carry = xor_wire(circuit, g, t0);
    }

    result
}

fn xor_u32<C: CircuitContext>(circuit: &mut C, a: U32, b: U32) -> U32 {
    let c: Vec<WireId> = (0..32).map(|i| xor_wire(circuit, a[i], b[i])).collect();
    c.try_into().unwrap()
}

fn and_u32<C: CircuitContext>(circuit: &mut C, a: U32, b: U32) -> U32 {
    let c: Vec<WireId> = (0..32).map(|i| and_wire(circuit, a[i], b[i])).collect();
    c.try_into().unwrap()
}

fn or_u32<C: CircuitContext>(circuit: &mut C, x: U32, y: U32) -> U32 {
    let xpy = xor_u32(circuit, x, y);
    let xmy = and_u32(circuit, x, y);

    xor_u32(circuit, xpy, xmy)
}

fn rotate_right_u32(value: U32, n: u32) -> U32 {
    let mut result = [FALSE_WIRE; 32];
    let shift = (n % 32) as usize;

    for (i, result_i) in result.iter_mut().enumerate() {
        // Compute the new position using modular arithmetic
        let from_index = (i + shift) % 32;
        *result_i = value[from_index];
    }

    result
}

// The mixing function, G, which mixes either a column or a diagonal.
#[allow(clippy::too_many_arguments)]
fn g<C: CircuitContext>(
    circuit: &mut C,
    state: &mut [U32; 16],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    mx: U32,
    my: U32,
) {
    let tmp0 = wrapping_add_u32(circuit, state[a], state[b]);
    state[a] = wrapping_add_u32(circuit, tmp0, mx);
    state[d] = rotate_right_u32(xor_u32(circuit, state[d], state[a]), 16);
    state[c] = wrapping_add_u32(circuit, state[c], state[d]);
    state[b] = rotate_right_u32(xor_u32(circuit, state[b], state[c]), 12);

    let tmp0 = wrapping_add_u32(circuit, state[a], state[b]);
    state[a] = wrapping_add_u32(circuit, tmp0, my);
    state[d] = rotate_right_u32(xor_u32(circuit, state[d], state[a]), 8);
    state[c] = wrapping_add_u32(circuit, state[c], state[d]);
    state[b] = rotate_right_u32(xor_u32(circuit, state[b], state[c]), 7);
}

fn round<C: CircuitContext>(circuit: &mut C, state: &mut [U32; 16], m: &[U32; 16]) {
    // Mix the columns.
    g(circuit, state, 0, 4, 8, 12, m[0], m[1]);
    g(circuit, state, 1, 5, 9, 13, m[2], m[3]);
    g(circuit, state, 2, 6, 10, 14, m[4], m[5]);
    g(circuit, state, 3, 7, 11, 15, m[6], m[7]);
    // Mix the diagonals.
    g(circuit, state, 0, 5, 10, 15, m[8], m[9]);
    g(circuit, state, 1, 6, 11, 12, m[10], m[11]);
    g(circuit, state, 2, 7, 8, 13, m[12], m[13]);
    g(circuit, state, 3, 4, 9, 14, m[14], m[15]);
}

fn permute(m: &mut [U32; 16]) {
    let mut permuted = [[FALSE_WIRE; 32]; 16];
    for i in 0..16 {
        permuted[i] = m[MSG_PERMUTATION[i] as usize];
    }
    *m = permuted;
}

fn compress<C: CircuitContext>(
    circuit: &mut C,
    chaining_value: &[U32; 8],
    block_words: &[U32; 16],
    counter: u64,
    block_len: U32,
    flags: U32,
) -> [U32; 16] {
    let counter_low = const_u32_to_bits_le(counter as u32);
    let counter_high = const_u32_to_bits_le((counter >> 32) as u32);
    #[rustfmt::skip]
    let iv: [U32; 8] = get_iv();
    let mut state = [
        chaining_value[0],
        chaining_value[1],
        chaining_value[2],
        chaining_value[3],
        chaining_value[4],
        chaining_value[5],
        chaining_value[6],
        chaining_value[7],
        iv[0],
        iv[1],
        iv[2],
        iv[3],
        counter_low,
        counter_high,
        block_len,
        flags,
    ];

    let mut block = *block_words;

    round(circuit, &mut state, &block); // round 1
    permute(&mut block);
    round(circuit, &mut state, &block); // round 2
    permute(&mut block);
    round(circuit, &mut state, &block); // round 3
    permute(&mut block);
    round(circuit, &mut state, &block); // round 4
    permute(&mut block);
    round(circuit, &mut state, &block); // round 5
    permute(&mut block);
    round(circuit, &mut state, &block); // round 6
    permute(&mut block);
    round(circuit, &mut state, &block); // round 7

    for i in 0..8 {
        state[i] = xor_u32(circuit, state[i], state[i + 8]);
        state[i + 8] = xor_u32(circuit, state[i + 8], chaining_value[i]);
    }
    state
}

fn first_8_words(compression_output: [U32; 16]) -> [U32; 8] {
    compression_output[0..8].try_into().unwrap()
}

fn words_from_little_endian_bytes(bytes: &[U8], words: &mut [U32]) {
    debug_assert_eq!(bytes.len(), 4 * words.len());
    for (four_bytes, word) in bytes.chunks_exact(4).zip(words) {
        let app_four_bytes: U32 = four_bytes.concat().try_into().unwrap();
        *word = app_four_bytes;
    }
}

struct Output {
    input_chaining_value: [U32; 8],
    block_words: [U32; 16],
    block_len: U32,
    flags: U32,
}

impl Output {
    fn root_output_bytes<C: CircuitContext>(&self, circuit: &mut C, out_slice: &mut [U8]) {
        let root = const_u32_to_bits_le(ROOT);
        for (output_block_counter, out_block) in out_slice.chunks_mut(2 * OUT_LEN).enumerate() {
            let flags = or_u32(circuit, self.flags, root);
            let words = compress(
                circuit,
                &self.input_chaining_value,
                &self.block_words,
                output_block_counter as u64,
                self.block_len,
                flags,
            );
            for (word_bits, out_word_bits) in words.iter().zip(out_block.chunks_mut(4)) {
                for (i, byte_bits) in out_word_bits.iter_mut().enumerate() {
                    let arr: U8 = word_bits[8 * i..(i + 1) * 8].try_into().unwrap();
                    *byte_bits = arr;
                }
            }
        }
    }
}

struct ChunkState {
    chaining_value: [U32; 8],
    chunk_counter: u64,
    block: [U8; BLOCK_LEN],
    block_len: u8,
    blocks_compressed: u8,
    flags: U32,
}

impl ChunkState {
    fn new(key_words: [U32; 8], chunk_counter: u64, flags: U32) -> Self {
        Self {
            chaining_value: key_words,
            chunk_counter,
            block: [[FALSE_WIRE; 8]; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> U32 {
        let r = if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        };
        const_u32_to_bits_le(r)
    }

    fn update<C: CircuitContext>(&mut self, circuit: &mut C, mut input: &[U8]) {
        let zero_gate = FALSE_WIRE;
        let block_len = const_u32_to_bits_le(BLOCK_LEN as u32);
        while !input.is_empty() {
            // If the block buffer is full, compress it and clear it. More
            // input is coming, so this compression is not CHUNK_END.
            if self.block_len as usize == BLOCK_LEN {
                let mut block_words = [[zero_gate; 32]; 16];
                words_from_little_endian_bytes(&self.block, &mut block_words);
                let start_flag = self.start_flag();
                let flags = or_u32(circuit, self.flags, start_flag);
                let cmp = compress(
                    circuit,
                    &self.chaining_value,
                    &block_words,
                    self.chunk_counter,
                    block_len,
                    flags,
                );
                self.chaining_value = first_8_words(cmp);
                self.blocks_compressed += 1;
                self.block = [[zero_gate; 8]; BLOCK_LEN];
                self.block_len = 0;
            }

            // Copy input bytes into the block buffer.
            let want = BLOCK_LEN - self.block_len as usize;
            let take = min(want, input.len());
            self.block[self.block_len as usize..][..take].copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output<C: CircuitContext>(&self, circuit: &mut C) -> Output {
        let zero_gate = FALSE_WIRE;
        let mut block_words = [[zero_gate; 32]; 16];
        words_from_little_endian_bytes(&self.block, &mut block_words);
        let start_flag = self.start_flag();
        let flags = or_u32(circuit, self.flags, start_flag);
        let chunk_end = const_u32_to_bits_le(CHUNK_END);
        let flags = or_u32(circuit, flags, chunk_end);

        Output {
            input_chaining_value: self.chaining_value,
            block_words,
            block_len: const_u32_to_bits_le(self.block_len as u32),
            flags,
        }
    }
}

/// An incremental hasher that can accept any number of writes.
pub(crate) struct Hasher {
    chunk_state: ChunkState,
}

impl Hasher {
    fn new_internal(key_words: [U32; 8], flags: U32) -> Self {
        Self {
            chunk_state: ChunkState::new(key_words, 0, flags),
        }
    }

    /// Construct a new `Hasher` for the regular hash function.
    pub(crate) fn new() -> Self {
        let zero_gate = FALSE_WIRE;
        let iv = get_iv();
        let zero = [zero_gate; 32];
        Self::new_internal(iv, zero)
    }

    /// Add input to the hash state. This can be called any number of times.
    pub(crate) fn update<C: CircuitContext>(&mut self, circuit: &mut C, mut input: &[U8]) {
        while !input.is_empty() {
            // Compress input bytes into the current chunk state.
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = min(want, input.len());
            self.chunk_state.update(circuit, &input[..take]);
            input = &input[take..];
        }
    }

    /// Finalize the hash and write any number of output bytes.
    pub(crate) fn finalize<C: CircuitContext>(&self, circuit: &mut C, out_slice: &mut [U8]) {
        let output = self.chunk_state.output(circuit);
        output.root_output_bytes(circuit, out_slice);
    }
}

/// The function generates 32 byte output hash for given input message
pub fn blake3_hash<const N: usize, C: CircuitContext>(
    circuit: &mut C,
    input_message_bytes: InputMessageWires<N>,
) -> HashOutputWires {
    assert!(
        input_message_bytes.byte_arr.len() <= 1024,
        "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    );
    let mut hasher = Hasher::new();
    hasher.update(circuit, &input_message_bytes.byte_arr);

    let mut hash = [[FALSE_WIRE; 8]; 32];
    hasher.finalize(circuit, &mut hash);
    HashOutputWires { value: hash }
}

#[cfg(test)]
mod test {

    use std::{fs::File, io::BufReader, str::FromStr};

    use blake3::CHUNK_LEN;
    use rand::Rng;

    use crate::{
        circuit::CircuitBuilder,
        gadgets::hash::blake3::{HashOutput, InputMessage},
    };

    use super::blake3_hash;

    fn validate_blake3_hash_for_input<const N: usize>(inputs: InputMessage<N>) {
        let mut ref_hasher = blake3::Hasher::new();
        ref_hasher.update(&inputs.byte_arr);
        let ref_hash = ref_hasher.finalize();
        let ref_hash = ref_hash.as_bytes();

        let calc_hash =
            CircuitBuilder::streaming_execute::<_, _, HashOutput>(inputs, 10_000, |ctx, input| {
                let r = blake3_hash(ctx, *input);
                r
            });

        assert_eq!(calc_hash.output_value.value, *ref_hash);
    }

    #[test]
    fn test_blake3_hash_for_finite_len_random_input() {
        let mut byte_arr = [0u8; 32];
        rand::thread_rng().try_fill(&mut byte_arr[..]).unwrap();

        let inputs = InputMessage { byte_arr };
        validate_blake3_hash_for_input(inputs);
    }

    #[test]
    fn test_zero_length() {
        let inputs = InputMessage { byte_arr: [] };
        validate_blake3_hash_for_input(inputs);
    }

    #[test]
    fn test_max_length() {
        let inputs = InputMessage {
            byte_arr: [0; CHUNK_LEN],
        };

        validate_blake3_hash_for_input(inputs);
    }

    #[test]
    #[should_panic(
        expected = "This BLAKE3 implementation doesn't support messages longer than 1024 bytes"
    )]
    fn test_message_too_long() {
        let inputs = InputMessage {
            byte_arr: [0; CHUNK_LEN + 1],
        };

        validate_blake3_hash_for_input(inputs);
    }

    #[test]
    fn test_vectors() {
        use serde::Deserialize;

        #[derive(Debug, Deserialize)]
        struct TestVectors {
            cases: Vec<TestVector>,
        }

        #[derive(Debug, Deserialize)]
        struct TestVector {
            input_len: usize,
            hash: String,
        }

        fn read_test_vectors() -> Vec<(Vec<u8>, String)> {
            let path = "src/gadgets/hash/blake3_test_vectors.json";
            let file = File::open(path).unwrap();
            let reader = BufReader::new(file);

            let test_vectors: TestVectors = serde_json::from_reader(reader).unwrap();
            test_vectors
                .cases
                .iter()
                .filter(|vector| vector.input_len <= 1024)
                .map(|vector| {
                    let message = (0..251u8).cycle().take(vector.input_len).collect();
                    let expected_hash = String::from_str(&vector.hash[0..64]).unwrap();
                    (message, expected_hash)
                })
                .collect()
        }

        fn validate_blake3_hash_for_input_given_hash<const N: usize>(
            inputs: InputMessage<N>,
            ref_hash: String,
        ) {
            fn bytes_to_hex(bytes: [u8; 32]) -> String {
                bytes.iter().map(|b| format!("{:02x}", b)).collect()
            }

            let calc_hash = CircuitBuilder::streaming_execute::<_, _, HashOutput>(
                inputs,
                10_000,
                |ctx, input| {
                    let r = blake3_hash(ctx, *input);
                    r
                },
            );

            let calc_hash = bytes_to_hex(calc_hash.output_value.value);

            assert_eq!(calc_hash, ref_hash);
        }

        // Dispatcher: second argument must be an array literal of consts
        macro_rules! dispatch_input {
            ($bytes:expr, $expected_hash:expr, vec![$($n:literal),* $(,)?]) => {{
                match $bytes.len() {
                    $(
                        $n => {
                            let arr: [u8; $n] = $bytes.as_slice().try_into().unwrap();
                            let msg = InputMessage::<$n> { byte_arr: arr };
                            validate_blake3_hash_for_input_given_hash(msg, $expected_hash);
                        }
                    )*
                    _ => { panic!("unexpected length of input") }
                }
            }};
        }

        for (input_bytes, expected_hash) in read_test_vectors() {
            dispatch_input!(
                input_bytes,
                expected_hash,
                vec![
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 63, 64, 65, 127, 128, 129, 1023, 1024
                ]
            );
        }
    }
}
