use crate::pow::{convert_to_u256, ExtractData, Hashable, U256};
use crate::{BlockProducer, BlockProductionError, Chain};
use common::chain::block::{Block, BlockHeader, ConsensusData};
use common::chain::transaction::Transaction;
use common::primitives::{Idable, H256};

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


impl ExtractData for ConsensusData {
    fn get_bits(&self) -> Vec<u8> {
        todo!()
    }

    fn get_nonce(&self) -> u128 {
        todo!()
    }

    fn get_difficulty(&self) -> U256 {
        let bits = self.get_bits();
        convert_to_u256(bits)
    }

    fn create(bits: &[u8], nonce: u128) -> Self {
        todo!()
    }
}

impl Hashable for Block {
    fn hash(&self) -> U256 {
        todo!()
    }
}

impl BlockProducer for Pow {
    fn verify_block(block: &Block) -> Result<(), BlockProductionError> {
        todo!()
    }

    fn create_block(
        time: u32,
        version: i32,
        transactions: Vec<Transaction>,
        consensus_params: ConsensusData,
    ) -> Result<Block, BlockProductionError> {
        let hash_prev_block = Self::get_latest_block().get_id();
        let bits = consensus_params.get_bits();

        let difficulty = consensus_params.get_difficulty();
        let max_nonce = consensus_params.get_nonce();

        for nonce in 0..max_nonce {
            let consensus_data = ConsensusData::create(&bits, nonce);
            let header = BlockHeader {
                version,
                hash_prev_block,
                hash_merkle_root: Default::default(), // TODO
                time,
                consensus_data,
            };

            let block = Block {
                header: header.clone(),
                transactions: transactions.clone(),
            };

            if block.hash() >= difficulty {
                return Ok(block);
            }
        }

        Err(BlockProductionError::Error2)
    }
}
