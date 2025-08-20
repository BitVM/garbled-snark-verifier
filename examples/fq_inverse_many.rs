// Measure streaming overhead on Fq inverse by running many inverses in one circuit.
// Usage:
//   RUST_LOG=warn GSV_MOVE_CHILD_INPUTS=1 cargo run --example fq_inverse_many --release -- 500
// Toggle move optimization off:
//   RUST_LOG=warn GSV_MOVE_CHILD_INPUTS=0 cargo run --example fq_inverse_many --release -- 500

use std::env;

use ark_ff::{UniformRand, Zero};
use garbled_snark_verifier::{self as gsv, WireId};
use gsv::{
    Fq,
    circuit::streaming::{CircuitBuilder, CircuitInput, CircuitMode, EncodeInput, Execute},
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

struct Inputs {
    vals: Vec<ark_bn254::Fq>,
}

struct Wires {
    vals: Vec<Fq>,
}

impl CircuitInput for Inputs {
    type WireRepr = Wires;
    fn allocate(&self, mut issue: impl FnMut() -> WireId) -> Self::WireRepr {
        Wires {
            vals: self.vals.iter().map(|_| Fq::new(&mut issue)).collect(),
        }
    }
    fn collect_wire_ids(repr: &Self::WireRepr) -> Vec<gsv::WireId> {
        repr.vals
            .iter()
            .flat_map(|fq| fq.0.iter().copied())
            .collect()
    }
}

impl EncodeInput<bool> for Inputs {
    fn encode<M: CircuitMode<WireValue = bool>>(&self, repr: &Wires, cache: &mut M) {
        for (w, v) in repr.vals.iter().zip(self.vals.iter()) {
            let fnc = Fq::get_wire_bits_fn(w, v).expect("fq encoding fn");
            for &wire in w.0.iter() {
                if let Some(bit) = fnc(wire) {
                    cache.feed_wire(wire, bit);
                }
            }
        }
    }
}

fn main() {
    // default count
    let n: usize = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    // prepare random non-zero inputs
    let mut rng = ChaCha20Rng::seed_from_u64(42);
    let mut vals = Vec::with_capacity(n);
    while vals.len() < n {
        let v = ark_bn254::Fq::rand(&mut rng);
        if !v.is_zero() {
            vals.push(Fq::as_montgomery(v));
        }
    }

    let inputs = Inputs { vals };

    let result = CircuitBuilder::<Execute>::streaming_execute(inputs, |ctx, wires| {
        // compute inverses and return all wires
        let mut out_ids = Vec::new();
        for fq in &wires.vals {
            let inv = Fq::inverse(ctx, fq);
            out_ids.extend(inv.0.iter());
        }
        out_ids
    });

    // Use the output so optimizer can't drop it
    println!("outputs={} wires", result.output_wires.len());
}
