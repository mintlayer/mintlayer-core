use parity_scale_codec_derive::{Decode, Encode};
use std::fmt;

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Encode, Decode)]
pub struct BlockHeight(u64);

// Display should be defined for thiserr crate
impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl BlockHeight {
    pub fn new(height: u64) -> Self {
        Self(height)
    }

    pub fn increment(&mut self) {
        self.0 += 1;
    }
}

impl Into<u64> for BlockHeight {
    fn into(self) -> u64 {
        self.0
    }
}

impl From<u64> for BlockHeight {
    fn from(w: u64) -> BlockHeight {
        BlockHeight(w)
    }
}
