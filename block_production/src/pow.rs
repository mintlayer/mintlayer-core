use common::chain::block::{Block, BlockHeader, ConsensusData};
use common::chain::transaction::Transaction;
use common::primitives::{H256, Idable};
use crate::{BlockProducer, BlockProductionError, Chain, Compact};


pub trait ExtractData {
    fn get_difficulty(&self) -> Vec<u8>;
    fn get_nonce(&self) -> u128;

    fn create(difficulty:Vec<u8>, nonce:u128) -> Self;
}

impl ExtractData for ConsensusData {
    fn get_difficulty(&self) -> Vec<u8> {
        todo!()
    }

    fn get_nonce(&self) -> u128 {
        todo!()
    }

    fn create(difficulty: Vec<u8>, nonce: u128) -> Self {
        todo!()
    }
}

pub struct Pow;


impl Chain for Pow {
    fn get_block_hash(block_number: u32) -> H256 {
        todo!()
    }

    fn get_block_number(block_hash: &H256) -> u32 {
        todo!()
    }

    fn get_latest_block() -> Block {
        todo!()
    }

    fn get_block_id(block: &Block) -> H256 {
        todo!()
    }

    fn add_block(block: Block) {
        todo!()
    }
}

impl BlockProducer for Pow {
    fn verify_block(block: &Block) -> Result<(), BlockProductionError> {
        todo!()
    }

    fn create_block(time: u32, transactions: Vec<Transaction>, consensus_data:ConsensusData) -> Block {
        let last_block = Self::get_latest_block();
        let last_block_id = Self::get_block_id(&last_block);
        let new_height = Self::get_block_number(&last_block_id) + 1;

        let header = BlockHeader {
            version: 0,// TODO
            hash_prev_block: last_block.get_id(),
            hash_merkle_root: Default::default(), // TODO
            time,
            consensus_data
        };

        Block {
            header,
            transactions
        }
    }
}



impl Pow {

    fn get_target(difficulty:Vec<u8>) -> H256 {
        todo!()
    }

    pub fn mine_block(&self, time: u32, transactions: Vec<Transaction>, consensus_params: ConsensusData) -> Option<Block> {
        let difficulty = consensus_params.get_difficulty();
        let target = Pow::get_target(difficulty.clone());

        let max_nonce = consensus_params.get_nonce();

        for nonce in 0..max_nonce {
            let consensus_data = ConsensusData::create(difficulty.clone(),nonce);
            let block = Self::create_block(time,transactions.clone(),consensus_data);


            if block.calculate_hash() < target {
                return Some(block);
            }
        }

        None

    }
}