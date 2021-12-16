use crate::primitives::Amount;
use parity_scale_codec::{Decode, Encode};
use script::Script;

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum Destination {
    Address,   // Address type to be added
    PublicKey, // Key type to be added
    ScriptHash(Script),
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TxOutput {
    value: Amount,
    dest: Destination,
}

impl TxOutput {
    pub fn new(value: Amount, destination: Destination) -> Self {
        TxOutput {
            value,
            dest: destination,
        }
    }

    pub fn get_value(&self) -> Amount {
        self.value
    }

    pub fn get_destination(&self) -> &Destination {
        &self.dest
    }
}
