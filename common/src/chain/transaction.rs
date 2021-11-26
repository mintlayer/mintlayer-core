use crate::primitives::Amount;
use crate::primitives::H256;
use script::Script;

#[derive(Debug, Clone, PartialEq)]
pub struct OutPoint {
    pub hash_output: H256,
    pub index_output: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TxInput {
    pub outpoint: OutPoint,
    pub script_sig: Script,
    pub sequence: u32,
    pub witness: Vec<Script>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TxOutput {
    pub value: Amount,
    pub pub_key: Script,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}
