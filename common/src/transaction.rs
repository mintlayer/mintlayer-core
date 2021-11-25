//TODO: add serde to all these structs

#[derive(Debug, PartialEq, Default, Clone)]
pub struct Outpoint {
    //TODO: add the hash field
    pub index: u32,
}

//TODO: is this correct?
#[derive(Debug,PartialEq, Eq, Hash, Clone)]
pub struct Bytes(Vec<u8>);

#[derive(Debug, PartialEq, Clone)]
pub struct TransactionInput {
    pub previous_output: Outpoint,
    pub script_sig: Bytes,
    pub sequence: u32,
    pub script_witness: Vec<Bytes>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct TransactionOutput {
    pub value: u64,
    pub script_pubkey: Bytes,
}

#[derive(Debug, PartialEq, Clone)]
pub struct Transaction {
    pub version: i32,
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u32,
}