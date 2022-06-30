use crate::{
    address::pubkeyhash::PublicKeyHash,
    primitives::{Amount, Id},
};
use script::Script;
use serialization::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum Destination {
    #[codec(index = 0)]
    Address(PublicKeyHash), // Address type to be added
    #[codec(index = 1)]
    PublicKey(crypto::key::PublicKey), // Key type to be added
    #[codec(index = 2)]
    ScriptHash(Id<Script>),
    #[codec(index = 3)]
    AnyoneCanSpend, // zero verification; used primarily for testing. Never use this for real money
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum OutputPurpose {
    Transfer(Destination),
    StakeLock(Destination),
}

impl OutputPurpose {
    pub fn destination(&self) -> &Destination {
        match self {
            OutputPurpose::Transfer(d) => d,
            OutputPurpose::StakeLock(d) => d,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub struct TxOutput {
    value: Amount, // TODO: Add here tokens
    purpose: OutputPurpose,
}

impl TxOutput {
    pub fn new(value: Amount, purpose: OutputPurpose) -> Self {
        TxOutput { value, purpose }
    }

    pub fn value(&self) -> Amount {
        self.value
    }

    pub fn purpose(&self) -> &OutputPurpose {
        &self.purpose
    }
}
