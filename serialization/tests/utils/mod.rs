#![allow(unused)]

use parity_scale_codec::{Decode, DecodeAll, Encode, HasCompact};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Encode, Decode)]
pub struct SimpleWrapper<T>(pub T);

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Encode, Decode)]
pub struct OptionWrapper<T> {
    pub option: Option<T>,
}

impl<T> OptionWrapper<T> {
    pub fn new(option: Option<T>) -> Self {
        OptionWrapper { option }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Encode, Decode)]
pub struct CompactWrapper<T: HasCompact> {
    #[codec(compact)]
    pub field: T,
}

impl<T: HasCompact> CompactWrapper<T> {
    pub fn new(field: T) -> Self {
        CompactWrapper { field }
    }
}

pub fn check_encoding<T: Encode + DecodeAll + Eq + std::fmt::Debug>(x: T, expected: &[u8]) {
    assert_eq!(x.encode(), expected, "Invalid encoding");
    assert_eq!(T::decode_all(&mut &*expected), Ok(x), "Invalid decoding");
}
