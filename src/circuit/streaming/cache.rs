use std::collections::{HashMap, HashSet};

use crate::{
    WireId,
    circuit::streaming::{FALSE_WIRE, TRUE_WIRE},
};

pub struct Frame<T> {
    // Change to something cache-friendly
    wires: HashMap<WireId, T>,
}

impl<T> Frame<T> {
    fn with_inputs(inputs: impl IntoIterator<Item = (WireId, T)>) -> Self {
        Self {
            wires: inputs.into_iter().collect(),
        }
    }

    fn insert(&mut self, wire_id: WireId, value: T) {
        self.wires.insert(wire_id, value);
    }

    fn get(&self, wire_id: WireId) -> Option<&T> {
        self.wires.get(&wire_id)
    }

    fn extract_outputs(&self, output_wires: &[WireId]) -> Vec<(WireId, T)>
    where
        T: Clone,
    {
        let mut seen = HashSet::new();

        output_wires
            .iter()
            .map(|&wire_id| {
                if !seen.insert(wire_id) {
                    panic!("Output wire {wire_id:?} appears multiple times");
                }

                let value = self
                    .wires
                    .get(&wire_id)
                    .unwrap_or_else(
                        || panic!("Output wire {wire_id:?} not present in child frame",),
                    )
                    .clone();
                (wire_id, value)
            })
            .collect()
    }

    fn size(&self) -> usize {
        self.wires.len()
    }
}

#[derive(Default)]
pub struct WireStack<T> {
    frames: Vec<Frame<T>>,
}

impl<T: Clone> WireStack<T> {
    pub fn frames_len(&self) -> usize {
        self.frames.len()
    }

    pub fn push_frame(&mut self, inputs: impl IntoIterator<Item = (WireId, T)>) {
        self.frames.push(Frame::with_inputs(inputs));
    }

    pub fn pop_frame(&mut self, outputs: &[WireId]) -> Vec<(WireId, T)> {
        if let Some(frame) = self.frames.pop() {
            frame.extract_outputs(outputs)
        } else {
            Vec::new()
        }
    }

    pub fn insert(&mut self, wire_id: WireId, value: T) {
        if let Some(frame) = self.frames.last_mut() {
            frame.insert(wire_id, value);
        } else {
            panic!("empty frames");
        }
    }

    pub fn get(&self, wire_id: WireId) -> Option<&T> {
        self.frames.last()?.get(wire_id)
    }

    pub fn size(&self) -> usize {
        self.frames.iter().map(|frame| frame.size()).sum()
    }

    fn current_frame_mut(&mut self) -> Option<&mut Frame<T>> {
        self.frames.last_mut()
    }
}

impl WireStack<bool> {
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
