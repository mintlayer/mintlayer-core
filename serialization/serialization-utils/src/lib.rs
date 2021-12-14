use parity_scale_codec::{Decode, Encode, HasCompact};

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
