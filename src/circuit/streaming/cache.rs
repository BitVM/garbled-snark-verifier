use std::collections::HashSet;

use bitvec::prelude::*;
use itertools::Itertools;

use crate::{
    WireId,
    circuit::streaming::{FALSE_WIRE, TRUE_WIRE},
};

pub struct BooleanFrame {
    name: &'static str,
    ids: Vec<WireId>,
    vals: BitVec<usize, Lsb0>,
    cursor: usize,
}

impl BooleanFrame {
    #[inline]
    pub fn size(&self) -> usize {
        self.ids.len()
    }

    pub fn with_inputs(
        name: &'static str,
        inputs: impl IntoIterator<Item = (WireId, bool)>,
    ) -> Self {
        let mut ids = Vec::with_capacity(512);
        let mut vals: BitVec<usize, Lsb0> = BitVec::with_capacity(512);

        let mut prev: Option<WireId> = None;

        for (id, v) in inputs.into_iter().sorted_by(|(lw, _), (rw, _)| lw.cmp(rw)) {
            if id == TRUE_WIRE || id == FALSE_WIRE {
                continue;
            }

            if let Some(p) = prev {
                // allow non-decreasing; coalesce consecutive dup
                assert!(id >= p, "with_inputs: WireId {id:?} < previous {p:?}");
                if id == p {
                    // update last bit (coalesce consecutive duplicate)
                    let last = vals.len() - 1;
                    vals.set(last, v);
                    continue;
                }
            }
            prev = Some(id);
            ids.push(id);
            vals.push(v);
        }

        Self {
            ids,
            vals,
            cursor: 0,
            name,
        }
    }

    /// Upsert: update if exists; else insert at sorted position.
    #[inline]
    pub fn insert(&mut self, wire_id: WireId, value: bool) {
        if wire_id == TRUE_WIRE || wire_id == FALSE_WIRE {
            return;
        }

        match self.ids.last().copied() {
            None => {
                self.ids.push(wire_id);
                self.vals.push(value);
                self.cursor = 0;
            }
            Some(last) if wire_id > last => {
                self.ids.push(wire_id);
                self.vals.push(value);
                self.cursor = self.ids.len() - 1;
            }
            Some(last) if wire_id == last => {
                let idx = self.ids.len() - 1;
                self.vals.set(idx, value); // update last
                self.cursor = idx;
            }
            _ => {
                // pos = first index with id >= wire_id
                let pos = self.ids.partition_point(|&x| x < wire_id);
                if pos < self.ids.len() && self.ids[pos] == wire_id {
                    // update existing
                    self.vals.set(pos, value);
                    self.cursor = pos;
                } else {
                    // insert new (keep lockstep)
                    self.ids.insert(pos, wire_id);
                    self.vals.insert(pos, value);
                    if pos <= self.cursor {
                        self.cursor += 1;
                    }
                }
            }
        }
    }

    /// Returns &true / &false (static) for uniform API without exposing storage.
    #[inline]
    pub fn get(&self, wire_id: WireId) -> Option<&bool> {
        match wire_id {
            TRUE_WIRE => return Some(&true),
            FALSE_WIRE => return Some(&false),
            _ => {}
        }

        // cursor fast-paths
        if self.cursor < self.ids.len() && self.ids[self.cursor] == wire_id {
            return Some(if self.vals[self.cursor] {
                &true
            } else {
                &false
            });
        }
        if self.cursor + 1 < self.ids.len() && self.ids[self.cursor + 1] == wire_id {
            return Some(if self.vals[self.cursor + 1] {
                &true
            } else {
                &false
            });
        }

        // binary search
        match self.ids.binary_search_by_key(&wire_id, |&x| x) {
            Ok(i) => Some(if self.vals[i] { &true } else { &false }),
            Err(_) => None,
        }
    }

    pub fn extract_outputs(&self, output_wires: &[WireId]) -> Vec<(WireId, bool)> {
        let mut seen = HashSet::with_capacity(output_wires.len());
        output_wires
            .iter()
            .map(|&wire_id| match wire_id {
                TRUE_WIRE => (TRUE_WIRE, true),
                FALSE_WIRE => (FALSE_WIRE, false),
                id => {
                    if !seen.insert(id) {
                        panic!("Output wire {id:?} appears multiple times");
                    }
                    let v = self
                        .get(id)
                        .unwrap_or_else(|| panic!("Output wire {id:?} not present in frame"));
                    (id, *v)
                }
            })
            .sorted()
            .collect()
    }

    #[inline]
    pub fn name(&self) -> &'static str {
        self.name
    }
}

#[derive(Default)]
pub struct WireStack {
    frames: Vec<BooleanFrame>,
}

impl WireStack {
    pub fn frames_len(&self) -> usize {
        self.frames.len()
    }

    pub fn push_frame(&mut self, name: &'static str, inputs: &[WireId]) {
        let inputs = self.prepare_frame_inputs(inputs);
        self.frames.push(BooleanFrame::with_inputs(name, inputs));
    }

    pub fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, bool)> {
        if let Some(frame) = self.frames.pop() {
            //if frame.size() < 5 {
            //    panic!("Frame {} is too small: {}", frame.name, frame.size());
            //}

            frame.extract_outputs(outputs)
        } else {
            Vec::new()
        }
    }

    pub fn insert(&mut self, wire_id: WireId, value: bool) {
        if let Some(frame) = self.frames.last_mut() {
            frame.insert(wire_id, value);
        } else {
            panic!("empty frames");
        }
    }

    pub fn get(&self, wire_id: WireId) -> Option<&bool> {
        self.frames.last()?.get(wire_id)
    }

    pub fn total_size(&self) -> usize {
        self.frames.iter().map(|frame| frame.size()).sum()
    }

    pub fn current_size(&self) -> usize {
        self.frames
            .last()
            .map(|frame| frame.size())
            .unwrap_or_default()
    }

    fn current_frame_mut(&mut self) -> Option<&mut BooleanFrame> {
        self.frames.last_mut()
    }
}

impl WireStack {
    pub fn lookup_wire(&self, wire: WireId) -> Option<&bool> {
        match wire {
            FALSE_WIRE => Some(&false),
            TRUE_WIRE => Some(&true),
            wire => self.get(wire),
        }
    }

    pub fn feed_wire(&mut self, wire: WireId, value: bool) {
        self.insert(wire, value);
    }

    pub fn prepare_frame_inputs(&self, input_wires: &[WireId]) -> Vec<(WireId, bool)> {
        input_wires
            .iter()
            .map(|&wire_id| {
                let value = self.lookup_wire(wire_id).unwrap_or_else(|| {
                    panic!("Input wire {wire_id:?} not available in current frame")
                });
                (wire_id, *value)
            })
            .collect()
    }

    pub fn extract_frame_outputs(&mut self, output_wires: &[WireId]) -> Vec<(WireId, bool)> {
        self.pop_frame(output_wires)
    }
}
