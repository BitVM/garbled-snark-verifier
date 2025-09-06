// Minimal, focused example to profile the streaming G1 multiplexer gadget.
// Run with: cargo run --example g1_multiplexer_flame --release [w] [iters]
// For flamegraph (recommended): cargo flamegraph --example g1_multiplexer_flame --release -- 5 200

use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use garbled_snark_verifier::{self as gsv, circuit::streaming::StreamingResult};
use gsv::{
    G1Wire as G1Projective, WireId,
    circuit::streaming::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput},
};
// Deterministic RNG helpers
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn rnd_fr<R: Rng>(rng: &mut R) -> ark_bn254::Fr {
    let mut prng = ChaCha20Rng::seed_from_u64(rng.r#gen());
    ark_bn254::Fr::rand(&mut prng)
}

fn rnd_g1<R: Rng>(rng: &mut R) -> ark_bn254::G1Projective {
    ark_bn254::G1Projective::generator() * rnd_fr(rng)
}

// Inputs container for the multiplexer: N points and w selector bits
struct MuxInputs {
    a: Vec<ark_bn254::G1Projective>,
    s: Vec<bool>,
}

struct MuxWires {
    a: Vec<G1Projective>,
    s: Vec<WireId>,
}

impl CircuitInput for MuxInputs {
    type WireRepr = MuxWires;

    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        MuxWires {
            a: (0..self.a.len())
                .map(|_| G1Projective::new(&mut issue))
                .collect(),
            s: (0..self.s.len()).map(|_| (issue)()).collect(),
        }
    }

    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<WireId> {
        let mut wires = Vec::new();
        for g1 in &repr.a {
            wires.extend(g1.x.iter());
            wires.extend(g1.y.iter());
            wires.extend(g1.z.iter());
        }
        wires.extend(&repr.s);
        wires
    }
}

impl<M: CircuitMode<WireValue = bool>> EncodeInput<M> for MuxInputs {
    fn encode(&self, repr: &MuxWires, cache: &mut M) {
        for (g1_wire, g1_val) in repr.a.iter().zip(self.a.iter()) {
            let g1_fn = G1Projective::get_wire_bits_fn(g1_wire, g1_val).expect("g1 encoding fn");
            for &wire_id in g1_wire
                .x
                .iter()
                .chain(g1_wire.y.iter())
                .chain(g1_wire.z.iter())
            {
                if let Some(bit) = g1_fn(wire_id) {
                    cache.feed_wire(wire_id, bit);
                }
            }
        }
        for (&wire_id, &bit) in repr.s.iter().zip(self.s.iter()) {
            cache.feed_wire(wire_id, bit);
        }
    }
}

fn main() {
    if !garbled_snark_verifier::hardware_aes_available() {
        eprintln!(
            "Warning: AES hardware acceleration not detected; using software AES (not constant-time)."
        );
    }
    // Keep logs quiet by default so IO doesn’t pollute the flamegraph
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .try_init();

    // Parse optional CLI args: w (bits) and iterations
    let mut args = std::env::args().skip(1);
    let w: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(5); // default N=2^5=32 points
    let iters: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(200);

    let n = 1usize << w;

    // Deterministic inputs
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let a_vals: Vec<_> = (0..n)
        .map(|_| G1Projective::as_montgomery(rnd_g1(&mut rng)))
        .collect();

    // Pick random selector bits once; they stay constant across iterations
    let s_bits: Vec<bool> = (0..w).map(|_| rng.r#gen()).collect();

    // Compute expected selection index (LSB-first as in gadgets)
    let mut idx = 0usize;
    for &b in s_bits.iter().rev() {
        idx = (idx << 1) | (b as usize);
    }
    let expected = a_vals[idx];

    // Run several iterations so sampling has enough signal
    for _ in 0..iters {
        let inputs = MuxInputs {
            a: a_vals.clone(),
            s: s_bits.clone(),
        };

        let result: StreamingResult<_, _, Vec<bool>> =
            CircuitBuilder::streaming_execute(inputs, 10_000, |ctx, wires| {
                let out = G1Projective::multiplexer(ctx, &wires.a, &wires.s, w);
                // Return all coordinate wires so they are decoded, preventing DCE
                let mut ids = Vec::new();
                ids.extend(out.x.iter());
                ids.extend(out.y.iter());
                ids.extend(out.z.iter());
                ids
            });

        // Verify selected point matches expectation (Montgomery domain)
        let got = G1Projective::from_bits_unchecked(result.output_wires.clone());
        debug_assert_eq!(got, expected, "mux output mismatch");
    }

    println!("done: w={} n={} iters={}", w, n, iters);
}
