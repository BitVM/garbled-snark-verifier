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

use std::collections::{HashMap, VecDeque};

use log::trace;

use crate::{
    CircuitContext, Gate, WireId,
    circuit::streaming::{CircuitMode, FALSE_WIRE, TRUE_WIRE, WiresObject},
    storage::Credits,
};

#[derive(Debug)]
enum InputIndex {
    Vec(Box<[(WireId, Credits)]>),
    Map(HashMap<WireId, Credits>),
    Empty,
}

impl InputIndex {
    fn build(inputs: &[WireId]) -> Self {
        match inputs.len() {
            0 => Self::Empty,
            1..64 => {
                let mut credits = Vec::<(WireId, Credits)>::with_capacity(inputs.len());
                for wire_id in inputs {
                    match *wire_id {
                        WireId::UNREACHABLE => continue,
                        TRUE_WIRE => continue,
                        FALSE_WIRE => continue,
                        wire_id => match credits.binary_search_by(|(w, _c)| w.cmp(&wire_id)) {
                            Err(err) => credits.insert(err, (wire_id, 0)),
                            Ok(_) => {
                                continue;
                            }
                        },
                    }
                }

                Self::Vec(credits.into_boxed_slice())
            }
            64.. => {
                let mut map = HashMap::new();
                for wire_id in inputs {
                    match *wire_id {
                        WireId::UNREACHABLE => continue,
                        TRUE_WIRE => continue,
                        FALSE_WIRE => continue,
                        wire_id => {
                            map.insert(wire_id, 0);
                        }
                    }
                }

                Self::Map(map)
            }
        }
    }

    fn for_each(&self, mut map: impl FnMut(WireId, Credits)) {
        match self {
            InputIndex::Vec(values) => values
                .iter()
                .for_each(move |(wire_id, credits)| map(*wire_id, *credits)),
            InputIndex::Map(hash_map) => hash_map
                .iter()
                .for_each(move |(wire_id, credits)| map(*wire_id, *credits)),
            InputIndex::Empty => (),
        }
    }

    #[inline(always)]
    fn get_mut(&mut self, wire: WireId) -> Option<&mut Credits> {
        match self {
            InputIndex::Empty => None,
            InputIndex::Vec(credits) => match credits.binary_search_by(|(w, _c)| w.cmp(&wire)) {
                Ok(index) => Some(&mut credits[index].1),
                Err(_) => None,
            },
            InputIndex::Map(map) => map.get_mut(&wire),
        }
    }
}

#[derive(Debug)]
pub struct ComponentMeta {
    /// During real execution, we take from here (stack-like) lifetime (credits) for real wires.
    pub credits_stack: VecDeque<Credits>,

    /// Input external credits stored in the same order the input is provided.
    extra_input_credits: InputIndex,

    /// Output external credits stored in the same order outputs are provided.
    extra_output_credits: Vec<Credits>,

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

        Self {
            credits_stack: VecDeque::new(),
            extra_input_credits: InputIndex::build(inputs),
            extra_output_credits: output_external_credits.to_vec(),
            cursor: offset,
            offset,
        }
    }

    #[inline(always)]
    pub fn increment_credits(&mut self, wires: &[WireId]) {
        self.add_credits(wires, 1);
    }

    #[inline(always)]
    fn bump_credit_for_wire(&mut self, wire_id: WireId, credit: Credits) {
        match wire_id {
            TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE => {}
            id if id < self.offset => {
                *self.extra_input_credits.get_mut(id).unwrap() += credit;
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
                *self.extra_input_credits.get_mut(output_wire).unwrap() += extra;
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

    pub fn for_each_input_extra_credits(&self, map: impl FnMut(WireId, Credits)) {
        self.extra_input_credits.for_each(map);
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
        _k: &[u8; 16],
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

    fn evaluate_gate(&mut self, _gate: &Gate) -> Option<()> {
        None
    }
}
