use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, PartialOrd, Encode, Decode)]
pub struct SimpleWrapper<T>(pub T);

#[derive(Debug, Clone, PartialEq, PartialOrd, Encode, Decode)]
pub struct OptionWrapper<T> {
    pub option: Option<T>,
}

impl<T> OptionWrapper<T> {
    pub fn new(option: Option<T>) -> Self {
        OptionWrapper { option }
    }
}
