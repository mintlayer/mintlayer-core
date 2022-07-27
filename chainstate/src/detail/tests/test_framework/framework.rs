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

use chainstate_storage::BlockchainStorageRead;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, ConsensusData},
        config::{Builder as ChainConfigBuilder, ChainType},
        signature::inputsig::InputWitness,
        Block, Destination, GenBlock, Genesis, NetUpgrades, OutPointSourceId, OutputSpentState,
        Transaction, TxInput, TxOutput,
    },
    primitives::{time, Amount, Id, Idable, H256},
};
use crypto::random::Rng;

use crate::{
    detail::{
        tests::{
            create_new_outputs, produce_test_block,
            test_framework::{BlockBuilder, TestFrameworkBuilder},
            TestBlockInfo, ERR_CREATE_BLOCK_FAIL, ERR_CREATE_TX_FAIL,
        },
        BlockIndex, GenBlockIndex, TimeGetter,
    },
    BlockError, BlockHeight, BlockSource, Chainstate, ChainstateConfig, PropertyQueryError,
};

/// The `Chainstate` wrapper that simplifies operations and checks in the tests.
pub struct TestFramework {
    // TODO: FIXME: Private fields?
    pub chainstate: Chainstate,
    // TODO: FIXME: Remove?..
    pub block_indexes: Vec<BlockIndex>,
}

impl TestFramework {
    /// Creates a new test framework instance using a builder api.
    pub fn builder() -> TestFrameworkBuilder {
        TestFrameworkBuilder::new()
    }

    /// Processes a new block with the parameters specified using `ProcessBlockBuilder`.
    pub fn block_builder(&mut self) -> BlockBuilder {
        BlockBuilder::new(self)
    }

    /// Creates and processes a given amount of blocks. Returns the if of the last produced block.
    pub fn create_chain(
        &mut self,
        parent_block_id: &Id<GenBlock>,
        count_blocks: usize,
        rng: &mut impl Rng,
    ) -> Result<Id<GenBlock>, BlockError> {
        let mut prev_block = TestBlockInfo::from_id(&self.chainstate, *parent_block_id);

        for _ in 0..count_blocks {
            // TODO: FIXME:
            let block = produce_test_block(prev_block, rng);
            prev_block = TestBlockInfo::from_block(&block);
            self.add_special_block(block.clone())?;

            // // The value of each output is decreased by a random amount to produce a new input and output.
            // let (inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = prev_block
            //     .txns
            //     .into_iter()
            //     .flat_map(|(s, o)| create_new_outputs(s, &o, rng))
            //     .unzip();
            // let transaction = Transaction::new(0, inputs, outputs, 0).unwrap();
            //
            // self.process_block()
            //     .with_transactions(vec![transaction])
            //     .with_prev_block_hash(prev_block.id)
            //     .process()
            //     .unwrap();

            // let block = produce_test_block(test_block_info, rng);
            // test_block_info = TestBlockInfo::from_block(&block);
            // self.add_special_block(block.clone())?;

            /*
                        fn produce_test_block_with_consensus_data(
                prev_block: TestBlockInfo,
                consensus_data: ConsensusData,
                rng: &mut impl Rng,
            ) -> Block {
                // The value of each output is decreased by a random amount to produce a new input and output.
                let (inputs, outputs): (Vec<TxInput>, Vec<TxOutput>) = prev_block
                    .txns
                    .into_iter()
                    .flat_map(|(s, o)| create_new_outputs(s, &o, rng))
                    .unzip();

                Block::new(
                    vec![Transaction::new(0, inputs, outputs, 0).expect(ERR_CREATE_TX_FAIL)],
                    prev_block.id,
                    BlockTimestamp::from_duration_since_epoch(time::get()),
                    consensus_data,
                )
                .expect(ERR_CREATE_BLOCK_FAIL)
            }
                         */
        }

        Ok(prev_block.id)
    }

    /// Returns the genesis block of the chain.
    pub fn genesis(&self) -> &Genesis {
        self.chainstate.chain_config.genesis_block()
    }
}

impl Default for TestFramework {
    fn default() -> Self {
        Self::builder().build()
    }
}

#[test]
fn build_test_framework() {
    let chain_type = ChainType::Mainnet;
    let max_db_commit_attempts = 10;

    let tf = TestFramework::builder()
        .with_chain_config(
            ChainConfigBuilder::new(chain_type)
                .net_upgrades(NetUpgrades::unit_tests())
                .genesis_unittest(Destination::AnyoneCanSpend)
                .build(),
        )
        .with_chainstate_config(ChainstateConfig {
            max_db_commit_attempts,
            ..Default::default()
        })
        .with_time_getter(TimeGetter::default())
        .build();

    assert_eq!(
        tf.chainstate.chainstate_config.max_db_commit_attempts,
        max_db_commit_attempts
    );
    assert_eq!(tf.chainstate.chain_config.chain_type(), &chain_type);
}

#[test]
fn process_block() {
    let mut tf = TestFramework::default();
    tf.block_builder().process().unwrap();
}

// TODO: FIXME ///////////////////////////////////////////////////////
// TODO: FIXME: Check everything below.

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

impl TestFramework {
    // TODO: FIXME: Remove unused?..
    pub fn with_chainstate(chainstate: Chainstate) -> Self {
        Self {
            chainstate,
            block_indexes: Vec::new(),
        }
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
                            .get_block(*block_id)
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

    pub fn get_block_index(&self, id: &Id<GenBlock>) -> GenBlockIndex {
        self.chainstate.make_db_tx_ro().get_gen_block_index(id).unwrap().unwrap()
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
            .get_mainchain_tx_index(&OutPointSourceId::from(*tx_id))
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
            let expected_block_id: Option<Id<GenBlock>> = expected_block_id.map(|id| (*id).into());
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
                        .get_block(*block_index.block_id())
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
