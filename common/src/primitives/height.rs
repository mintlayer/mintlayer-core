use parity_scale_codec_derive::{Encode, Decode};

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Encode, Decode)]
pub struct BlockHeight(u64);
