use crate::chain::block::Block;
use crate::chain::transaction::Transaction;
use crate::primitives::Id;
use parity_scale_codec::{Decode, Encode};

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub enum OutpointSource {
    Transaction(Id<Transaction>),
    BlockReward(Id<Block>),
}

impl From<Id<Transaction>> for OutpointSource {
    fn from(tx: Id<Transaction>) -> Self {
        OutpointSource::Transaction(tx)
    }
}

impl From<Id<Block>> for OutpointSource {
    fn from(blkrwd: Id<Block>) -> Self {
        OutpointSource::BlockReward(blkrwd)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct OutPoint {
    id: OutpointSource,
    #[codec(compact)]
    index: u32,
}

impl OutPoint {
    pub fn new(prev_tx_id: OutpointSource, output_index: u32) -> Self {
        OutPoint {
            id: prev_tx_id,
            index: output_index,
        }
    }

    pub fn get_tx_id(&self) -> OutpointSource {
        self.id.clone()
    }

    pub fn get_output_index(&self) -> u32 {
        self.index
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct TxInput {
    outpoint: OutPoint,
    witness: Vec<u8>,
}

impl TxInput {
    pub fn new(prev_tx_id: OutpointSource, output_index: u32, witness: Vec<u8>) -> Self {
        TxInput {
            outpoint: OutPoint::new(prev_tx_id, output_index),
            witness,
        }
    }

    pub fn get_outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    pub fn get_witness(&self) -> &Vec<u8> {
        &self.witness
    }
}
