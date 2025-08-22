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

use std::{cmp::Ordering, collections::VecDeque};

use log::trace;

use crate::{
    CircuitContext, Gate, WireId,
    circuit::streaming::{CircuitMode, FALSE_WIRE, TRUE_WIRE, WiresObject},
    storage::Credits,
};

#[derive(Debug)]
pub struct ComponentMeta {
    /// This variable should be used as follows
    /// During the real execution of the component, we take from here as from the stack
    /// lifetime (credits) for real wires, during their issue
    ///
    /// Since the order in which they are released is deterministic, everything is fairly trivial
    pub credits_stack: VecDeque<Credits>,

    /// Input external credits stored in same order, what input will be provided
    inputs_wires: Vec<WireId>,
    extra_input_credits: Vec<Credits>,

    /// Output external credits stored in same order, what output will be provided
    extra_output_credits: Vec<Credits>,

    offset: WireId,
    cursor: WireId,
}

impl ComponentMeta {
    pub fn new(inputs: &[WireId], output_external_credits: &[Credits]) -> Self {
        let offset = match inputs.iter().filter(|w| w.ne(&&WireId::UNREACHABLE)).max() {
            None => WireId::MIN,
            Some(wire_id) if wire_id < &WireId::MIN => WireId::MIN,
            Some(wire_id) => WireId(wire_id.0 + 1),
        };

        Self {
            credits_stack: VecDeque::new(),
            inputs_wires: inputs.to_vec(),
            extra_input_credits: vec![0; inputs.len()],
            extra_output_credits: output_external_credits.to_vec(),
            cursor: offset,
            offset,
        }
    }

    pub fn extra_input_credits(&self) -> &[Credits] {
        &self.extra_input_credits
    }

    pub fn increment_credits(&mut self, wires: &[WireId]) {
        self.add_credits(wires, 1);
    }

    pub fn find_input_wire_index(&self, wire_id: WireId) -> Option<usize> {
        if wire_id < self.offset {
            self.inputs_wires.iter().position(|w| w == &wire_id)
        } else {
            None
        }
    }

    pub fn add_credits(&mut self, wires: &[WireId], credit: Credits) {
        for wire_id in wires.iter().copied() {
            match wire_id {
                TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE => (),
                index if index < self.offset => {
                    let pos = self.find_input_wire_index(wire_id).unwrap_or_else(|| {
                        panic!("Can't find in input wire id {wire_id} with offset {wire_id}");
                    });
                    self.extra_input_credits[pos] += credit;
                }
                index => {
                    *self
                        .credits_stack
                        .get_mut(index.0 - self.offset.0)
                        .expect("internal wire out of bounds") += credit;
                }
            }
        }
    }

    pub fn next_credit(&mut self) -> Option<Credits> {
        self.credits_stack.pop_front()
    }

    /// * Args
    /// - `outputs` - indices of those outputs that are really internal. The rest are either part
    ///   of the input or constants
    pub fn finalize(mut self, output_wire_types: &[WireId]) -> Self {
        pub enum OutputWireType {
            Internal { wire_id: WireId },
            FromInput { index_in_input: usize },
        }

        for (index, output_wire) in output_wire_types.iter().enumerate() {
            if output_wire == &TRUE_WIRE || output_wire == &FALSE_WIRE {
                continue;
            }

            match output_wire.cmp(&self.offset) {
                Ordering::Less => {
                    let index_in_input = self.find_input_wire_index(*output_wire).unwrap();
                    self.extra_input_credits[index_in_input] += self.extra_output_credits[index];
                }
                Ordering::Equal | Ordering::Greater if output_wire < &self.cursor => {
                    self.add_credits(&[*output_wire], self.extra_output_credits[index])
                }
                _ => panic!(
                    "Wrong output wire: {output_wire:?}, because offset here is {} with cursor {}",
                    self.offset, self.cursor
                ),
            };
        }

        self
    }
}

impl CircuitContext for ComponentMeta {
    type Mode = Empty;

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

    fn add_gate(&mut self, gate: Gate) {
        // Consider only reads: wire_a and wire_b; wire_c is a write, it is not counted.
        trace!(
            "ComponentMeta::add_gate kind={:?} a={} b={} c={}",
            gate.gate_type, gate.wire_a.0, gate.wire_b.0, gate.wire_c.0
        );

        self.increment_credits(&[gate.wire_a, gate.wire_b]);
    }

    fn with_named_child<O: WiresObject>(
        &mut self,
        _name: &'static str,
        input_wires: Vec<WireId>,
        _f: impl Fn(&mut Self) -> O,
        arity: impl FnOnce() -> usize,
    ) -> O {
        let arity = arity();
        self.increment_credits(&input_wires);

        let mock_output = std::iter::repeat_with(|| self.issue_wire())
            .take(arity)
            .collect::<Vec<_>>();

        O::from_wires(&mock_output).unwrap()
    }
}

#[derive(Default)]
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
