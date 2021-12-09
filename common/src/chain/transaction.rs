use crate::primitives::Amount;
use crate::primitives::Idable;
use crate::primitives::H256;
use script::Script;

pub mod transaction_index;
pub use transaction_index::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutPoint {
    pub hash_output: H256,
    pub index_output: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxInput {
    pub outpoint: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
    pub witness: Vec<Script>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutput {
    pub value: Amount,
    pub pub_key: Script,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionV1 {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transaction {
    V1(TransactionV1), // TODO: add serialization index attribute
}

impl Idable for Transaction {
    fn get_id(&self) -> H256 {
        H256::zero()
    }
}
