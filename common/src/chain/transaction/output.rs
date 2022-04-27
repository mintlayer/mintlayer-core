use crate::primitives::{Amount, Id};
use parity_scale_codec::{Decode, Encode};
use script::Script;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum Destination {
    #[codec(index = 0)]
    Address(crate::address::Address), // Address type to be added
    #[codec(index = 1)]
    PublicKey(crypto::key::PublicKey), // Key type to be added
    #[codec(index = 2)]
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
