pub use crate::chain::transaction::input::*;
pub use crate::chain::transaction::output::*;
pub use crate::chain::transaction::TransactionCreationError;
use crate::primitives::{id, Id};
use parity_scale_codec_derive::{Decode as DecodeDer, Encode as EncodeDer};

use super::Transaction;

#[derive(Debug, Clone, PartialEq, Eq, EncodeDer, DecodeDer)]
pub struct TransactionV1 {
    flags: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    lock_time: u32,
}

impl TransactionV1 {
    pub fn new(
        flags: u32,
        inputs: Vec<TxInput>,
        outputs: Vec<TxOutput>,
        lock_time: u32,
    ) -> Result<Self, TransactionCreationError> {
        let tx = TransactionV1 {
            flags,
            inputs,
            outputs,
            lock_time,
        };
        Ok(tx)
    }

    pub fn is_replaceable(&self) -> bool {
        (self.flags & 1) != 0
    }

    pub fn get_flags(&self) -> u32 {
        self.flags
    }

    pub fn get_inputs(&self) -> &Vec<TxInput> {
        &self.inputs
    }

    pub fn get_outputs(&self) -> &Vec<TxOutput> {
        &self.outputs
    }

    pub fn get_lock_time(&self) -> u32 {
        self.lock_time
    }

    pub fn get_serialized_hash(&self) -> Id<Transaction> {
        Id::new(&id::hash_encoded(self))
    }
}
