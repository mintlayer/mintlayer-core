use crate::detail::tests::*;
use common::chain::block::{Block, ConsensusData};
use common::chain::{OutputSpentState, Transaction, TxInput, TxOutput};
use common::primitives::Id;
use common::primitives::H256;

pub struct BlockTestFrameWork {
    pub consensus: Consensus,
    pub blocks: Vec<Block>,
}

impl<'a> BlockTestFrameWork {
    pub fn new() -> Self {
        let consensus = setup_consensus();
        let genesis = consensus.chain_config.genesis_block().clone();
        Self {
            consensus,
            blocks: vec![genesis],
        }
    }

    #[allow(dead_code)]
    pub(in crate::detail::tests) fn random_block(
        &self,
        parent_block: &Block,
        params: Option<&[TestBlockParams]>,
    ) -> Block {
        let (mut inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = parent_block
            .transactions()
            .iter()
            .flat_map(|tx| create_new_outputs(&self.consensus.chain_config, tx))
            .unzip();

        let mut hash_prev_block = Some(parent_block.get_id());
        if let Some(params) = params {
            for param in params {
                match param {
                    TestBlockParams::SpendFrom(block_id) => {
                        let block = self
                            .consensus
                            .blockchain_storage
                            .get_block(block_id.clone())
                            .unwrap()
                            .unwrap();

                        let double_spend_input = TxInput::new(
                            OutPointSourceId::Transaction(block.transactions()[0].get_id()),
                            0,
                            vec![],
                        );
                        inputs.push(double_spend_input)
                    }
                    TestBlockParams::Orphan => hash_prev_block = Some(Id::new(&H256::random())),
                    _ => unimplemented!(),
                }
            }
        }

        Block::new(
            vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
            hash_prev_block,
            time::get() as u32,
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL)
    }

    pub fn genesis(&self) -> &Block {
        self.consensus.chain_config.genesis_block()
    }

    fn get_children_blocks(current_block_id: &Id<Block>, blocks: &Vec<Block>) -> Vec<Id<Block>> {
        let mut result = Vec::new();
        for block in blocks {
            if let Some(ref prev_block_id) = block.prev_block_id() {
                if prev_block_id == current_block_id {
                    result.push(block.get_id());
                }
            }
        }
        result
    }

    fn get_block_index(&self, block_id: &Id<Block>) -> BlockIndex {
        self.consensus.blockchain_storage.get_block_index(block_id).unwrap().unwrap()
    }

    pub fn debug_print_chains(&self, blocks: Vec<Id<Block>>, depth: usize) {
        if blocks.is_empty() {
            println!("{}X", "--".repeat(depth));
        } else {
            for block_id in blocks {
                let block_index = self.get_block_index(&block_id);
                let mut main_chain = "";
                if self.is_block_in_main_chain(&block_id) {
                    main_chain = ",M";
                }
                println!(
                    "{tabs}+-- {block_id} (H:{height}{mainchain_flag},P:{position})",
                    tabs = "\t".repeat(depth),
                    block_id = &block_id.get(),
                    height = block_index.get_block_height(),
                    mainchain_flag = main_chain,
                    position =
                        self.blocks.iter().position(|block| block.get_id() == block_id).unwrap()
                );
                let block_children = Self::get_children_blocks(&block_id, &self.blocks);
                if !block_children.is_empty() {
                    self.debug_print_chains(block_children, depth + 1);
                }
            }
        }
    }

    pub fn debug_print_tx(&self, block_id: Id<Block>, transactions: &Vec<Transaction>) {
        println!();
        for tx in transactions {
            println!("+ BLOCK: {} => TX: {}", block_id.get(), tx.get_id().get());
            for (input_index, input) in tx.get_inputs().iter().enumerate() {
                println!("\t+Input: {}", input_index);
                println!("\t\t+From: {:?}", input.get_outpoint());
            }
            for (output_index, output) in tx.get_outputs().iter().enumerate() {
                let spent_status = self.get_spent_status(&tx.get_id(), output_index as u32);
                println!("\t+Output: {}", output_index);
                println!("\t\t+Value: {}", output.get_value().into_atoms());
                match spent_status {
                    Some(OutputSpentState::Unspent) => println!("\t\t+Spend: Unspent"),
                    Some(OutputSpentState::SpentBy(spender)) => {
                        println!("\t\t+Spend: {:?}", spender)
                    }
                    None => println!("\t\t+Spend: Not in mainchain"),
                }
            }
        }
    }

    pub fn create_chain(&mut self, parent_block_id: &Id<Block>, count_blocks: usize) {
        let mut block = self
            .consensus
            .blockchain_storage
            .get_block(parent_block_id.clone())
            .ok()
            .flatten()
            .unwrap();

        for _ in 0..count_blocks {
            block = produce_test_block(&self.consensus.chain_config.clone(), &block, false);
            self.consensus
                .process_block(block.clone(), BlockSource::Local)
                .expect("Err block processing");
            self.blocks.push(block.clone());
        }
    }

    pub fn add_special_block(&mut self, block: Block) -> Result<Option<BlockIndex>, BlockError> {
        let result = self.consensus.process_block(block.clone(), BlockSource::Local);
        if result.is_ok() {
            self.blocks.push(block);
        }
        result
    }

    pub fn get_spent_status(
        &self,
        tx_id: &Id<Transaction>,
        output_index: u32,
    ) -> Option<OutputSpentState> {
        let tx_index = self
            .consensus
            .blockchain_storage
            .get_mainchain_tx_index(&OutPointSourceId::from(tx_id.clone()))
            .unwrap()?;
        tx_index.get_spent_state(output_index).ok()
    }

    fn check_spend_status(&self, tx: &Transaction, spend_status: &TestSpentStatus) {
        for (output_index, _) in tx.get_outputs().iter().enumerate() {
            let is_spend_status_correct = if spend_status == &TestSpentStatus::Spent {
                self.get_spent_status(&tx.get_id(), output_index as u32)
                    != Some(OutputSpentState::Unspent)
            } else {
                self.get_spent_status(&tx.get_id(), output_index as u32)
                    == Some(OutputSpentState::Unspent)
            };

            assert!(is_spend_status_correct);
        }
    }

    fn check_block_at_height(
        &self,
        block_height: BlockHeight,
        expected_block_id: &Option<Id<Block>>,
    ) {
        if expected_block_id.is_some() {
            let real_next_block_id =
                self.consensus.blockchain_storage.get_block_id_by_height(&block_height).unwrap();
            assert_eq!(&real_next_block_id, expected_block_id);
        }
    }

    pub(in crate::detail::tests) fn test_block(
        &self,
        block_id: &Id<Block>,
        prev_block_id: &Option<Id<Block>>,
        next_block_id: &Option<Id<Block>>,
        height: u64,
        spend_status: TestSpentStatus,
    ) {
        if spend_status != TestSpentStatus::NotInMainchain {
            match self.blocks.iter().find(|x| &x.get_id() == block_id) {
                Some(block) => {
                    for tx in block.transactions() {
                        self.check_spend_status(tx, &spend_status);
                    }
                }
                None => {
                    panic!("block not found")
                }
            }
        }

        let block_index = self.get_block_index(block_id);
        assert_eq!(block_index.get_prev_block_id(), prev_block_id);
        assert_eq!(block_index.get_block_height(), BlockHeight::new(height));
        self.check_block_at_height(block_index.get_block_height().next_height(), next_block_id);
    }

    pub fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> bool {
        let block_index =
            self.consensus.blockchain_storage.get_block_index(block_id).unwrap().unwrap();
        let height = block_index.get_block_height();
        let id_at_height =
            self.consensus.blockchain_storage.get_block_id_by_height(&height).unwrap();
        match id_at_height {
            Some(id) => id == *block_index.get_block_id(),
            None => false,
        }
    }
}
