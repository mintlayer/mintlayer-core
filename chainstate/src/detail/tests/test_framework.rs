// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Sinitsyn, S. Tkach

use crate::detail::tests::*;
use chainstate_storage::BlockchainStorageRead;
use common::{
    chain::{
        block::ConsensusData, Block, GenBlock, Genesis, OutputSpentState, Transaction, TxInput,
        TxOutput,
    },
    primitives::{Id, Idable, H256},
};

#[derive(Debug, Eq, PartialEq)]
pub enum TestSpentStatus {
    Spent,
    Unspent,
    NotInMainchain,
}

// TODO: See https://github.com/mintlayer/mintlayer-core/issues/274 for details.
#[allow(dead_code)]
pub enum TestBlockParams {
    NoErrors,
    TxCount(usize),
    Fee(Amount),
    Orphan,
    SpendFrom(Id<Block>),
}

pub struct BlockTestFramework {
    pub chainstate: Chainstate,
    pub block_indexes: Vec<BlockIndex>,
}

impl BlockTestFramework {
    pub fn with_chainstate(chainstate: Chainstate) -> Self {
        Self {
            chainstate,
            block_indexes: Vec::new(),
        }
    }

    pub fn new() -> Self {
        let chainstate = setup_chainstate();
        Self::with_chainstate(chainstate)
    }

    pub fn random_block(
        &self,
        parent_info: TestBlockInfo,
        params: Option<&[TestBlockParams]>,
        rng: &mut impl Rng,
    ) -> Block {
        let (mut inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = parent_info
            .txns
            .into_iter()
            .flat_map(|(s, o)| create_new_outputs(s, &o, rng))
            .unzip();

        let mut prev_block_hash = parent_info.id;
        if let Some(params) = params {
            for param in params {
                match param {
                    TestBlockParams::SpendFrom(block_id) => {
                        let block = self
                            .chainstate
                            .chainstate_storage
                            .get_block(block_id.clone())
                            .unwrap()
                            .unwrap();

                        let double_spend_input = TxInput::new(
                            OutPointSourceId::Transaction(block.transactions()[0].get_id()),
                            0,
                            InputWitness::NoSignature(None),
                        );
                        inputs.push(double_spend_input)
                    }
                    TestBlockParams::Orphan => prev_block_hash = Id::new(H256::random()),
                    // TODO: FIXME.
                    _ => unimplemented!(),
                }
            }
        }

        Block::new(
            vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
            prev_block_hash,
            BlockTimestamp::from_duration_since_epoch(time::get()),
            ConsensusData::None,
        )
        .expect(ERR_CREATE_BLOCK_FAIL)
    }

    pub fn genesis(&self) -> &Genesis {
        self.chainstate.chain_config.genesis_block()
    }

    pub fn get_block_index(&self, id: &Id<GenBlock>) -> GenBlockIndex {
        self.chainstate.make_db_tx_ro().get_gen_block_index(id).unwrap().unwrap()
    }

    /// Creates and processes a given amount of blocks. Returns the last produced block.
    pub(in crate::detail::tests) fn create_chain(
        &mut self,
        parent_block_id: &Id<GenBlock>,
        count_blocks: usize,
        rng: &mut impl Rng,
    ) -> Result<Id<GenBlock>, BlockError> {
        let mut test_block_info = TestBlockInfo::from_id(&self.chainstate, parent_block_id.clone());

        for _ in 0..count_blocks {
            let block = produce_test_block(test_block_info, rng);
            test_block_info = TestBlockInfo::from_block(&block);
            self.add_special_block(block.clone())?;
        }
        Ok(test_block_info.id)
    }

    pub fn add_special_block(&mut self, block: Block) -> Result<Option<BlockIndex>, BlockError> {
        let id = block.get_id();
        let block_index = self.chainstate.process_block(block, BlockSource::Local)?;
        self.block_indexes.push(block_index.clone().unwrap_or_else(|| {
            self.chainstate.chainstate_storage.get_block_index(&id).unwrap().unwrap()
        }));
        Ok(block_index)
    }

    pub fn get_spent_status(
        &self,
        tx_id: &Id<Transaction>,
        output_index: u32,
    ) -> Option<OutputSpentState> {
        let tx_index = self
            .chainstate
            .chainstate_storage
            .get_mainchain_tx_index(&OutPointSourceId::from(tx_id.clone()))
            .unwrap()?;
        tx_index.get_spent_state(output_index).ok()
    }

    fn check_spend_status(&self, tx: &Transaction, spend_status: &TestSpentStatus) {
        for (output_index, _) in tx.outputs().iter().enumerate() {
            let status = self.get_spent_status(&tx.get_id(), output_index as u32);
            if spend_status == &TestSpentStatus::Spent {
                assert_ne!(status, Some(OutputSpentState::Unspent));
            } else {
                assert_eq!(status, Some(OutputSpentState::Unspent));
            }
        }
    }

    fn check_block_at_height(
        &self,
        block_height: BlockHeight,
        expected_block_id: Option<&Id<Block>>,
    ) {
        if expected_block_id.is_some() {
            let real_next_block_id = self
                .chainstate
                .chainstate_storage
                .get_block_id_by_height(&block_height)
                .unwrap();
            let expected_block_id: Option<Id<GenBlock>> =
                expected_block_id.map(|id| id.clone().into());
            assert_eq!(real_next_block_id, expected_block_id);
        }
    }

    pub fn test_block(
        &self,
        block_id: &Id<Block>,
        prev_block_id: &Id<GenBlock>,
        next_block_id: Option<&Id<Block>>,
        height: u64,
        spend_status: TestSpentStatus,
    ) {
        if spend_status != TestSpentStatus::NotInMainchain {
            match self.block_indexes.iter().find(|x| x.block_id() == block_id) {
                Some(block_index) => {
                    let block = self
                        .chainstate
                        .chainstate_storage
                        .get_block(block_index.block_id().clone())
                        .unwrap()
                        .unwrap();
                    for tx in block.transactions() {
                        self.check_spend_status(tx, &spend_status);
                    }
                }
                None => {
                    panic!("block not found")
                }
            }
        }

        let block_index =
            self.chainstate.chainstate_storage.get_block_index(block_id).unwrap().unwrap();
        assert_eq!(block_index.prev_block_id(), prev_block_id);
        assert_eq!(block_index.block_height(), BlockHeight::new(height));
        self.check_block_at_height(block_index.block_height().next_height(), next_block_id);
    }

    pub fn is_block_in_main_chain(&self, block_id: &Id<Block>) -> bool {
        let block_index = self
            .chainstate
            .chainstate_storage
            .get_block_index(block_id)
            .ok()
            .flatten()
            .unwrap();
        let height = block_index.block_height();
        let id_at_height =
            self.chainstate.chainstate_storage.get_block_id_by_height(&height).unwrap();
        match id_at_height {
            Some(id) => id == *block_index.block_id(),
            None => false,
        }
    }

    pub fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, PropertyQueryError> {
        self.chainstate.get_block(block_id)
    }

    pub fn chainstate(&mut self) -> &mut Chainstate {
        &mut self.chainstate
    }

    pub fn index_at(&self, at: usize) -> &BlockIndex {
        assert!(at > 0, "No block index for genesis");
        &self.block_indexes[at - 1]
    }
}
