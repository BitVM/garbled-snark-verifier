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

use std::collections::HashMap;

use itertools::Itertools;
use log::{debug, trace};

use crate::{
    CircuitContext, Gate, WireId,
    circuit::streaming::{CircuitMode, FALSE_WIRE, TRUE_WIRE, WiresObject},
    storage::Credits,
};

#[derive(Debug)]
pub enum InputIndex {
    Vec(Box<[(WireId, Credits)]>),
    Map(HashMap<WireId, Credits>),
    Empty,
}

impl InputIndex {
    pub fn build(inputs: &[WireId]) -> Self {
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
pub struct ComponentMetaBuilder {
    /// During real execution, we take from here (stack-like) lifetime (credits) for real wires.
    pub credits_stack: Vec<Credits>,

    /// Input external credits stored in the same order the input is provided.
    pub extra_input_credits: InputIndex,
    pub input_wires: Vec<WireId>,

    offset: WireId,
    cursor: WireId,
}

impl ComponentMetaBuilder {
    pub fn new(inputs: &[WireId]) -> Self {
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
            credits_stack: Vec::new(),
            extra_input_credits: InputIndex::build(inputs),
            input_wires: inputs.to_vec(),
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
                let curr = self.extra_input_credits.get_mut(id).unwrap();
                *curr += credit;
                trace!("bump for input wire: {id:?}, now is {}", curr);
            }
            id => {
                trace!("bump for internal wire: {id:?}");
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

    /// * Args
    /// - `output_wire_types` - the declared outputs (wires) of the component.
    ///   Those < offset are "from inputs"; those in [offset, cursor) are internal; constants are ignored.
    pub fn build(mut self, output_wires: &[WireId]) -> ComponentMetaTemplate {
        let output_wire_types = output_wires
            .iter()
            .map(|&output_wire| {
                if output_wire == TRUE_WIRE || output_wire == FALSE_WIRE {
                    return OutputWireType::Constant;
                }

                if output_wire < self.offset {
                    OutputWireType::Input(
                        self.input_wires
                            .iter()
                            // TODO Optimize perf
                            .position(|w| w == &output_wire)
                            .unwrap(),
                    )
                } else if output_wire >= self.offset && output_wire < self.cursor {
                    let idx = output_wire.0 - self.offset.0;
                    OutputWireType::Internal(idx)
                } else {
                    panic!(
                    "Wrong output wire: {output_wire:?}, because offset here is {} with cursor {}",
                    self.offset, self.cursor
                );
                }
            })
            .collect();

        // TODO Optimize perf
        let extra_input_credits = self
            .input_wires
            .iter()
            .map(|input_wire_id| {
                if input_wire_id == &TRUE_WIRE || input_wire_id == &FALSE_WIRE {
                    return 0;
                }
                self.extra_input_credits
                    .get_mut(*input_wire_id)
                    .copied()
                    .unwrap()
            })
            .collect::<Box<[_]>>();

        ComponentMetaTemplate {
            credits_stack: self.credits_stack.to_vec(),
            extra_input_credits,
            output_wire_types,
        }
    }

    pub fn for_each_input_extra_credits(&self, map: impl FnMut(WireId, Credits)) {
        self.extra_input_credits.for_each(map);
    }
}

#[derive(Debug)]
enum OutputWireType {
    Internal(usize),
    Input(usize),
    Constant,
}

#[derive(Debug)]
pub struct ComponentMetaTemplate {
    /// During real execution, we take from here (stack-like) lifetime (credits) for real wires.
    pub credits_stack: Vec<Credits>,

    /// Input external credits stored in the same order the input is provided.
    extra_input_credits: Box<[Credits]>,
    output_wire_types: Box<[OutputWireType]>,
}

#[derive(Debug)]
pub struct ComponentMetaInstance {
    pub credits_stack: Vec<Credits>,
}

impl ComponentMetaTemplate {
    pub fn to_instance(
        &self,
        input_wires: &[WireId],
        output_credits: &[Credits],
        mut add_credit_to_input: impl FnMut(WireId, Credits),
    ) -> ComponentMetaInstance {
        let mut credits_stack = self.credits_stack.to_vec();

        for (input_wire_id, extra_credits) in input_wires
            .iter()
            .zip_eq(self.extra_input_credits.iter().copied())
        {
            if extra_credits > 0 {
                trace!("bump input_wire_id {input_wire_id:?} with {extra_credits} credits");
                add_credit_to_input(*input_wire_id, extra_credits);
            }
        }

        for (output_wire, credits) in self.output_wire_types.iter().zip_eq(output_credits) {
            match &output_wire {
                OutputWireType::Constant => {
                    debug!("Output wire {output_wire:?} is constant");
                }
                OutputWireType::Input(input_index) => {
                    debug!(
                        "Output wire {output_wire:?} is part of input with index {input_index:?}"
                    );
                    add_credit_to_input(input_wires[*input_index], *credits);
                }
                OutputWireType::Internal(index) => {
                    credits_stack[*index] += credits;
                    debug!(
                        "Output wire {output_wire:?} is internal issue with index {index:?} add credits: {credits}, total is {}",
                        credits_stack[*index]
                    );
                }
            }
        }

        ComponentMetaInstance {
            credits_stack: credits_stack.into_iter().rev().collect::<Vec<_>>(),
        }
    }
}

impl ComponentMetaInstance {
    pub fn next_credit(&mut self) -> Option<Credits> {
        self.credits_stack.pop()
    }
    pub fn is_empty(&self) -> bool {
        self.credits_stack.is_empty()
    }
}

impl CircuitContext for ComponentMetaBuilder {
    type Mode = Empty;

    #[inline]
    fn issue_wire(&mut self) -> WireId {
        let next = self.cursor;
        self.cursor.0 += 1;
        self.credits_stack.push(0);

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
