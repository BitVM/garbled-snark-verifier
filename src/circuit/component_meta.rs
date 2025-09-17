//! ComponentMeta: collect wire metadata without computation using isolated mock wire IDs.
//!
//! Purpose
//! - This pass does not execute gates nor store values. It computes per-wire fanout totals
//!   (expressed as initial "credits" to be consumed at runtime).
//! - Uses isolated mock wire IDs internally to eliminate dependency on global wire context.
//!
//! Terminology
//! - Fanout (total): total number of downstream reads/uses for a wire within a component.
//! - Credits (remaining): the runtime counter representing remaining reads; initialized from fanout.
//!
//! Isolated fanout model (reads-only)
//! - Input wires use predictable mock IDs: [WireId::MIN, WireId::MIN + input_count)
//! - Internal wires use mock IDs: [WireId::MIN + input_count, cursor)
//! - Input fanout/credits are tracked by input position (0, 1, 2, ...) in `credits_by_input_position`.
//! - Internal fanout/credits are tracked in `credits_stack` indexed by issue order.
//! - A credit is added only when the wire is read: used as a gate input (`wire_a`, `wire_b`) or
//!   passed to a child component via `with_named_child`.
//! - Writing the result to `wire_c` is not a read and does not increment credits.
//! - The `TRUE_WIRE`/`FALSE_WIRE` constants are ignored.
//!
//! Template/Instance mapping
//! - Templates store credits by position, independent of specific wire IDs.
//! - `to_instance()` maps positional credits to real wire IDs using input order.
//! - This enables simpler caching: templates depend only on arity and structure.

use std::num::NonZero;

use itertools::Itertools;
use tracing::{debug, trace};

use crate::{
    CircuitContext, Gate, WireId,
    circuit::{
        CircuitInput, CircuitMode, FALSE_WIRE, TRUE_WIRE, WiresObject, component_key::ComponentKey,
        into_wire_list::FromWires,
    },
    storage::Credits,
};

#[derive(Debug)]
pub struct ComponentMetaBuilder {
    /// During real execution, we take from here (stack-like) remaining-use counters (credits)
    /// for real wires, initialized from fanout totals.
    pub credits_stack: Vec<Credits>,

    input_len: usize,
    cursor: WireId,
}

impl ComponentMetaBuilder {
    pub fn new(input_count: usize) -> Self {
        // Use high range for mock wire IDs to avoid collision with real execution
        // Mock input wires start at the upper half of usize space
        Self {
            credits_stack: Vec::new(),
            input_len: input_count,
            cursor: WireId::MIN,
        }
    }

    pub fn new_with_input<I: CircuitInput>(inputs: &I) -> (I::WireRepr, Self) {
        let mut self_ = Self::new(0);
        let input = inputs.allocate(|| self_.issue_wire());

        self_.input_len = self_.cursor.0 - WireId::MIN.0;

        trace!("Allocated in meta ctx input is {} wires", self_.input_len);

        (input, self_)
    }

    pub fn get_input_len(&self) -> usize {
        self.input_len
    }

    #[inline(always)]
    pub fn increment_credits(&mut self, wires: &[WireId]) {
        self.add_credits(wires, NonZero::<Credits>::MIN);
    }

    #[inline(always)]
    fn bump_credit_for_wire(&mut self, wire_id: WireId, credit: NonZero<Credits>) {
        match wire_id {
            TRUE_WIRE | FALSE_WIRE | WireId::UNREACHABLE => {}
            id if id < self.cursor => {
                trace!("bump for internal wire: {id:?}");
                let idx = id.0 - WireId::MIN.0;

                let slot = self
                    .credits_stack
                    .get_mut(idx)
                    .expect("internal wire out of bounds");

                *slot += credit.get();
            }
            id => {
                // Wire ID from outside our isolated mock range - ignore
                // This can happen when tests use real wire IDs instead of mock ones
                panic!(
                    "External wire {id:?} (not in mock range, cursor at {})",
                    self.cursor
                );
            }
        }
    }

    #[inline(always)]
    pub fn add_credits(&mut self, wires: &[WireId], credit: NonZero<Credits>) {
        for &wire_id in wires {
            self.bump_credit_for_wire(wire_id, credit);
        }
    }

    /// * Args
    /// - `output_wires` - the declared outputs (mock wires) of the component.
    ///   Input range [WireId::MIN, WireId::MIN + input_count), internal range [WireId::MIN + input_count, cursor)
    pub fn build(self, output_wires: &[WireId]) -> ComponentMetaTemplate {
        trace!("start build template: {:?}", self);

        let output_wire_types = output_wires
            .iter()
            .map(|&output_wire| {
                if output_wire == TRUE_WIRE || output_wire == FALSE_WIRE {
                    return OutputWireType::Constant;
                }

                let index = output_wire.0 - WireId::MIN.0;

                if index < self.input_len {
                    OutputWireType::Input(index)
                } else if output_wire < self.cursor {
                    OutputWireType::Internal(index - self.input_len)
                } else {
                    panic!(
                        "Wrong output wire {output_wire}, but cursor is {:?}",
                        self.cursor.0
                    );
                }
            })
            .collect();

        let (credits_by_input_position, credit_stack) = self.credits_stack.split_at(self.input_len);

        ComponentMetaTemplate {
            credits_stack: credit_stack.to_vec(),
            credits_by_input_position: credits_by_input_position.to_vec(),
            output_wire_types,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OutputWireType {
    Internal(usize),
    Input(usize), // Now stores input position (0, 1, 2, ...) instead of wire ID
    Constant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentMetaTemplate {
    /// During real execution, we take from here (stack-like) remaining-use counters (credits)
    /// for real wires.
    pub credits_stack: Vec<Credits>,

    /// Input credits stored by position (0, 1, 2, ...) in input order.
    credits_by_input_position: Vec<Credits>,
    output_wire_types: Vec<OutputWireType>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ComponentMetaInstance {
    pub credits_stack: Vec<Credits>,
}

impl ComponentMetaTemplate {
    pub fn to_instance(
        &self,
        output_credits: &[Credits],
        mut add_credit_to_input: impl FnMut(usize, NonZero<Credits>),
    ) -> ComponentMetaInstance {
        let mut credits_stack = self.credits_stack.clone();

        // Map template input credits (by position) to real input wires
        for (position, &template_credits) in self.credits_by_input_position.iter().enumerate() {
            if let Some(credits) = NonZero::<Credits>::new(template_credits) {
                add_credit_to_input(position, credits);
            }
        }

        // Handle output credits routing
        for (output_wire_type, credits) in self.output_wire_types.iter().zip_eq(output_credits) {
            match output_wire_type {
                OutputWireType::Constant => {
                    debug!("Output wire {output_wire_type:?} is constant");
                }
                OutputWireType::Input(input_position) => {
                    debug!(
                        "Output wire {output_wire_type:?} is input at position {input_position}"
                    );

                    if let Some(credits) = NonZero::<Credits>::new(*credits) {
                        add_credit_to_input(*input_position, credits);
                    }
                }
                OutputWireType::Internal(internal_index) => {
                    credits_stack[*internal_index] += credits;
                    debug!(
                        "Output wire {output_wire_type:?} is internal at index {internal_index} add credits: {credits}, total is {}",
                        credits_stack[*internal_index]
                    );
                }
            }
        }

        credits_stack.reverse();

        ComponentMetaInstance { credits_stack }
    }

    pub fn get_input_len(&self) -> usize {
        self.credits_by_input_position.len()
    }

    /// Total number of credit entries stored in this template
    /// (internal + input-position credits). Useful for memory estimation.
    pub fn total_credits_len(&self) -> usize {
        self.credits_stack.len() + self.credits_by_input_position.len()
    }

    /// Number of input-position credit entries
    pub fn input_positions_len(&self) -> usize {
        self.credits_by_input_position.len()
    }

    /// Number of declared output wire types captured by the template
    pub fn output_types_len(&self) -> usize {
        self.output_wire_types.len()
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

        // Match execution path: inputs must be real wires when the output is real.
        assert_ne!(gate.wire_a, WireId::UNREACHABLE);
        assert_ne!(gate.wire_b, WireId::UNREACHABLE);

        self.bump_credit_for_wire(gate.wire_a, NonZero::<Credits>::MIN);
        self.bump_credit_for_wire(gate.wire_b, NonZero::<Credits>::MIN);
    }

    fn with_named_child<I: WiresObject, O: FromWires>(
        &mut self,
        _k: ComponentKey,
        inputs: I,
        _f: impl Fn(&mut Self, &I) -> O,
        arity: usize,
    ) -> O {
        let input_wires = inputs.to_wires_vec();
        // Count reads on child inputs.
        for &w in &input_wires {
            self.bump_credit_for_wire(w, NonZero::<Credits>::MIN);
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
    type CiphertextAcc = ();

    fn false_value(&self) -> bool {
        false
    }

    fn allocate_wire(&mut self, _credits: Credits) -> WireId {
        WireId::MIN
    }

    fn true_value(&self) -> bool {
        true
    }

    fn lookup_wire(&mut self, _wire: WireId) -> Option<Self::WireValue> {
        None
    }

    fn feed_wire(&mut self, _wire: WireId, _value: Self::WireValue) {}

    fn evaluate_gate(&mut self, _gate: &Gate) {}

    fn add_credits(&mut self, _wires: &[WireId], _credits: NonZero<Credits>) {}
}
