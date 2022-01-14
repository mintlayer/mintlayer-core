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
