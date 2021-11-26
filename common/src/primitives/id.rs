fixed_hash::construct_fixed_hash! {
    /// My 256 bit hash type.
    pub struct H256(32);
}

/// a trait for objects that deserve having a unique id with implementations to how to ID them
pub trait Idable {
}

#[allow(dead_code)]
pub type DataID = H256;
