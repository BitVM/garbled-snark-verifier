use crate::core::s::S;

#[derive(Clone, Debug)]
pub struct Wire {
    pub label0: Option<S>,
    pub label1: Option<S>,
    pub value: Option<bool>,
    pub label: Option<S>,
}

impl Default for Wire {
    fn default() -> Self {
        Self::new()
    }
}

impl Wire {
    pub fn new() -> Self {
        Self {
            label0: None,
            label1: None,
            value: None,
            label: None,
        }
    }

    pub fn select(&self, selector: bool) -> S {
        if selector {
            self.label1.unwrap()
        } else {
            self.label0.unwrap()
        }
    }

    pub fn select_hash(&self, selector: bool) -> S {
        if selector {
            self.label1.unwrap().hash()
        } else {
            self.label0.unwrap().hash()
        }
    }

    pub fn get_value(&self) -> bool {
        assert!(self.value.is_some());
        self.value.unwrap()
    }

    pub fn get_label(&self) -> S {
        assert!(self.value.is_some());
        self.label.unwrap()
    }

    pub fn set_labels(&mut self) {
        todo!()
    }

    pub fn set(&mut self, bit: bool) {
        assert!(self.value.is_none());
        self.value = Some(bit);
    }

    pub fn set2(&mut self, bit: bool, label: S) {
        assert!(self.value.is_none());
        self.value = Some(bit);
        self.label = Some(label);
    }
}
