use crate::primitives::{Amount, Id};
use script::Script;
use serialization::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum Destination {
    Address(crate::address::Address), // Address type to be added
    PublicKey,                        // Key type to be added
    ScriptHash(Id<Script>),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
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
