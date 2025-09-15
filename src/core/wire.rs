use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireId(pub usize);

impl WireId {
    pub const MIN: WireId = WireId(2);
    pub const UNREACHABLE: WireId = WireId(usize::MAX);
}

impl fmt::Display for WireId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<usize> for WireId {
    fn from(v: usize) -> Self {
        WireId(v)
    }
}

impl From<WireId> for usize {
    fn from(value: WireId) -> Self {
        value.0
    }
}
