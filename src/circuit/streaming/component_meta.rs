//! ComponentMeta: collect wire metadata without computation.
//!
//! Purpose
//! - This mode (an implementation of `CircuitMode` and `CircuitContext`) does not execute valve logic and does not stores values on the wires. It only calculates the "credits" of wire usage for subsequent resource scheduling and/or reconciliation with the actual run.
//!
//! Credits model (reads-only)
//! - External wires (inputs and declared outputs of the component) are accounted for in the vector `external_credits = [inputs..., outputs...]`.
//! - Internal wires (issued via `issue_wire`) are accounted for in `credits_stack`, index is calculated as `wire_id - offset`, where `offset = max(inputs ∪ outputs) + 1`.
//! - Credit is added only when the wire is "read": when it is used as a fan-in input (`wire_a`, `wire_b`) or when the wire is passed to a child component via `with_named_child`.
//! - Writing the result to `wire_c` is not considered a read and does not increment credits.
//! - The `TRUE_WIRE`/`FALSE_WIRE` constants are ignored.
//!
//! Model security
//! - If an id less than `offset` is encountered that is not among the I/Os, a panic is generated - such a wire is unknown to the current component.
//! - Calls to child components increase credits only for input wires passed to them; child internals are not analyzed in this mode.

use std::collections::{BTreeMap, VecDeque};

use log::trace;

use crate::{
    CircuitContext, Gate, WireId,
    circuit::streaming::{CircuitMode, FALSE_WIRE, TRUE_WIRE, WiresObject},
    storage::Credits,
};

/// Fast index for input wire -> its position in `inputs_wires`.
/// Picks the fastest strategy based on density of input IDs.
#[derive(Debug)]
enum InputIndex {
    /// Dense array index: O(1) lookups, store index+1 (0 means "none").
    Dense { base: WireId, slots: Box<[usize]> },
    /// Sparse index: O(log n) lookups, avoids requiring `Hash` for `WireId`.
    Sparse(BTreeMap<WireId, usize>),
    /// No inputs.
    Empty,
}

impl InputIndex {
    fn build(inputs: &[WireId]) -> Self {
        // Filter special/unreachable out of the index.
        let filtered: Vec<(usize, WireId)> = inputs
            .iter()
            .copied()
            .enumerate()
            .filter(|(_, w)| *w != WireId::UNREACHABLE)
            .collect();

        if filtered.is_empty() {
            return InputIndex::Empty;
        }

        // Compute min/max to see if a dense table is feasible.
        let min_id = filtered.iter().map(|&(_, w)| w).min().unwrap();
        let max_id = filtered.iter().map(|&(_, w)| w).max().unwrap();

        // Range length in IDs.
        let range_len = max_id.0 - min_id.0 + 1;

        // Heuristic: go dense if the address space is reasonably tight compared to count.
        // With <5000 inputs average, this works very well when IDs are sequential-ish.
        let inputs_len = filtered.len();
        let dense_threshold = inputs_len.saturating_mul(8).max(4096);
        if range_len <= dense_threshold {
            // Dense path.
            let mut slots = vec![0usize; range_len].into_boxed_slice();
            for (i, w) in filtered.iter().copied() {
                let idx = w.0 - min_id.0;
                // Store index+1 (0 means absent).
                slots[idx] = i + 1;
            }
            InputIndex::Dense {
                base: min_id,
                slots,
            }
        } else {
            // Sparse path using BTreeMap (WireId already Ord).
            let mut map = BTreeMap::new();
            for (i, w) in filtered {
                map.insert(w, i);
            }
            InputIndex::Sparse(map)
        }
    }

    #[inline(always)]
    fn get(&self, wire: WireId) -> Option<usize> {
        match self {
            InputIndex::Empty => None,
            InputIndex::Dense { base, slots } => {
                if wire.0 < base.0 {
                    return None;
                }
                let idx = wire.0 - base.0;
                if idx >= slots.len() {
                    return None;
                }
                let v = unsafe { *slots.get_unchecked(idx) };
                if v == 0 { None } else { Some(v - 1) }
            }
            InputIndex::Sparse(map) => map.get(&wire).copied(),
        }
    }
}

#[derive(Debug)]
pub struct ComponentMeta {
    /// During real execution, we take from here (stack-like) lifetime (credits) for real wires.
    pub credits_stack: VecDeque<Credits>,

    /// Input external credits stored in the same order the input is provided.
    inputs_wires: Vec<WireId>,
    extra_input_credits: Vec<Credits>,

    /// Output external credits stored in the same order outputs are provided.
    extra_output_credits: Vec<Credits>,

    /// Fast wire-id -> input index mapping (for wire ids < offset).
    input_index: InputIndex,

    offset: WireId,
    cursor: WireId,
}

impl ComponentMeta {
    pub fn new(inputs: &[WireId], output_external_credits: &[Credits]) -> Self {
        // Compute offset = max(inputs excluding UNREACHABLE) + 1, clamped at MIN.
        let max_input = inputs
            .iter()
            .copied()
            .filter(|w| w.ne(&WireId::UNREACHABLE))
            .max();

        let offset = match max_input {
            None => WireId::MIN,
            Some(wire_id) if wire_id < WireId::MIN => WireId::MIN,
            Some(wire_id) => WireId(wire_id.0 + 1),
        };

        let inputs_wires = inputs.to_vec();
        let input_index = InputIndex::build(&inputs_wires);

        Self {
            credits_stack: VecDeque::new(),
            inputs_wires,
            extra_input_credits: vec![0; inputs.len()],
            extra_output_credits: output_external_credits.to_vec(),
            input_index,
            cursor: offset,
            offset,
        }
    }

    #[inline]
    pub fn extra_input_credits(&self) -> &[Credits] {
        &self.extra_input_credits
    }

    #[inline(always)]
    pub fn increment_credits(&mut self, wires: &[WireId]) {
        self.add_credits(wires, 1);
    }

    /// O(1) or O(log n) depending on index strategy.
    #[inline(always)]
    pub fn find_input_wire_index(&self, wire_id: WireId) -> Option<usize> {
        if wire_id < self.offset {
            self.input_index.get(wire_id)
        } else {
            None
        }
    }

    #[inline(always)]
    fn bump_credit_for_wire(&mut self, wire_id: WireId, credit: Credits) {
        match wire_id {
            TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE => {}
            id if id < self.offset => {
                let pos = self.find_input_wire_index(id).unwrap_or_else(|| {
                    panic!("Unknown input wire id {id} for offset {}", self.offset);
                });
                unsafe {
                    // SAFETY: pos is produced by our index and must be within bounds.
                    *self.extra_input_credits.get_unchecked_mut(pos) += credit;
                }
            }
            id => {
                let idx = id.0 - self.offset.0;
                let slot = self
                    .credits_stack
                    .get_mut(idx)
                    .expect("internal wire out of bounds");
                *slot += credit;
            }
        }
    }

    #[inline(always)]
    pub fn add_credits(&mut self, wires: &[WireId], credit: Credits) {
        for &wire_id in wires {
            self.bump_credit_for_wire(wire_id, credit);
        }
    }

    #[inline]
    pub fn next_credit(&mut self) -> Option<Credits> {
        self.credits_stack.pop_front()
    }

    /// * Args
    /// - `output_wire_types` - the declared outputs (wires) of the component.
    ///   Those < offset are "from inputs"; those in [offset, cursor) are internal; constants are ignored.
    pub fn finalize(mut self, output_wire_types: &[WireId]) -> Self {
        for (index, &output_wire) in output_wire_types.iter().enumerate() {
            if output_wire == TRUE_WIRE || output_wire == FALSE_WIRE {
                continue;
            }

            let extra = self.extra_output_credits[index];

            if output_wire < self.offset {
                let index_in_input = self.find_input_wire_index(output_wire).unwrap_or_else(|| {
                    panic!(
                        "Output wire {output_wire:?} is < offset {}, but not present in inputs",
                        self.offset
                    )
                });
                self.extra_input_credits[index_in_input] += extra;
            } else if output_wire >= self.offset && output_wire < self.cursor {
                // Internal output wire that had already been issued -> add credits.
                self.bump_credit_for_wire(output_wire, extra);
            } else {
                panic!(
                    "Wrong output wire: {output_wire:?}, because offset here is {} with cursor {}",
                    self.offset, self.cursor
                );
            }
        }

        self
    }
}

impl CircuitContext for ComponentMeta {
    type Mode = Empty;

    #[inline]
    fn issue_wire(&mut self) -> WireId {
        let next = self.cursor;
        self.cursor.0 += 1;
        self.credits_stack.push_back(0);

        trace!(
            "ComponentMeta::issue_wire -> {} (stack_len={})",
            next.0,
            self.credits_stack.len()
        );

        next
    }

    #[inline(always)]
    fn add_gate(&mut self, gate: Gate) {
        trace!(
            "ComponentMeta::add_gate kind={:?} a={} b={} c={}",
            gate.gate_type, gate.wire_a.0, gate.wire_b.0, gate.wire_c.0
        );

        // Avoid the slice loop/allocation in hot path.
        self.bump_credit_for_wire(gate.wire_a, 1);
        self.bump_credit_for_wire(gate.wire_b, 1);
    }

    fn with_named_child<O: WiresObject>(
        &mut self,
        _name: &'static str,
        input_wires: Vec<WireId>,
        _f: impl Fn(&mut Self) -> O,
        arity: impl FnOnce() -> usize,
    ) -> O {
        let arity = arity();

        // Count reads on child inputs.
        for &w in &input_wires {
            self.bump_credit_for_wire(w, 1);
        }

        // Produce mock outputs as newly issued internal wires.
        let mock_output = (0..arity).map(|_| self.issue_wire()).collect::<Vec<_>>();

        O::from_wires(&mock_output).unwrap()
    }
}

#[derive(Default, Debug)]
pub struct Empty;
impl CircuitMode for Empty {
    type WireValue = bool;

    fn lookup_wire(&self, _wire: WireId) -> Option<&Self::WireValue> {
        Some(&false)
    }

    fn feed_wire(&mut self, _wire: WireId, _value: Self::WireValue) {}

    fn total_size(&self) -> usize {
        0
    }
    fn current_size(&self) -> usize {
        0
    }

    /// This function is called on the component's input
    fn push_frame(&mut self, _name: &'static str, _inputs: &[WireId]) {}

    fn pop_frame(&mut self, _outputs: &[WireId]) -> Vec<(WireId, Self::WireValue)> {
        vec![]
    }

    fn evaluate_gate(&mut self, _gate: &Gate) -> Option<()> {
        None
    }
}
