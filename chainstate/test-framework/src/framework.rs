// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use chainstate::chainstate_interface::ChainstateInterface;
use chainstate::ChainstateError;
use common::chain::signature::inputsig::InputWitness;
use common::chain::tokens::TokenData;
use common::chain::tokens::TokenTransferV1;
use common::chain::TxInput;
use common::chain::TxOutput;
use common::primitives::id::WithId;
use common::{
    chain::{tokens::OutputValue, Block, Destination, GenBlock, Genesis, OutputPurpose},
    primitives::{Amount, Id, Idable},
};
use crypto::random::Rng;
use std::sync::Arc;

use crate::{BlockBuilder, TestFrameworkBuilder};
use chainstate::BlockSource;
use common::chain::gen_block::GenBlockId;
use common::primitives::BlockHeight;

use crate::TestChainstate;
use chainstate_types::{BlockIndex, GenBlockIndex};

/// The `Chainstate` wrapper that simplifies operations and checks in the tests.
pub struct TestFramework {
    pub chainstate: super::TestChainstate,
    pub block_indexes: Vec<BlockIndex>,
}

impl TestFramework {
    pub fn chainstate(self) -> super::TestChainstate {
        self.chainstate
    }

    /// Creates a new test framework instance using a builder api.
    pub fn builder() -> TestFrameworkBuilder {
        TestFrameworkBuilder::new()
    }

    /// Returns a block builder instance that can be used for a block construction and processing.
    pub fn make_block_builder(&mut self) -> BlockBuilder {
        BlockBuilder::new(self)
    }

    /// Processes the given block.
    pub fn process_block(
        &mut self,
        block: Block,
        source: BlockSource,
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        let id = block.get_id();
        let block_index_result = self.chainstate.process_block(block, source)?;
        let index = match self.chainstate.get_gen_block_index(&id.into()).unwrap().unwrap() {
            GenBlockIndex::Genesis(..) => panic!("we have processed a block"),
            GenBlockIndex::Block(block_index) => block_index,
        };
        self.block_indexes.push(index);
        Ok(block_index_result)
    }

    /// Creates and processes a given amount of blocks. Returns the id of the last produced block.
    ///
    /// Each block contains a single transaction that spends a random amount from the previous
    /// block outputs.
    pub fn create_chain(
        &mut self,
        parent_block: &Id<GenBlock>,
        blocks: usize,
        rng: &mut impl Rng,
    ) -> Result<Id<GenBlock>, ChainstateError> {
        let mut prev_block_id = *parent_block;
        for _ in 0..blocks {
            let block = self
                .make_block_builder()
                .add_test_transaction_with_parent(prev_block_id, rng)
                .with_parent(prev_block_id)
                .build();
            prev_block_id = block.get_id().into();
            self.process_block(block, BlockSource::Local)?;
        }

        Ok(prev_block_id)
    }

    /// Returns the genesis block of the chain.
    pub fn genesis(&self) -> Arc<WithId<Genesis>> {
        self.chainstate.get_chain_config().genesis_block().clone()
    }

    /// Returns the best block index.
    #[track_caller]
    pub fn best_block_index(&self) -> GenBlockIndex {
        self.chainstate.get_best_block_index().unwrap()
    }

    /// Return the best block identifier.
    #[track_caller]
    pub fn best_block_id(&self) -> Id<GenBlock> {
        self.best_block_index().block_id()
    }

    /// Returns a test block information for the best block.
    #[track_caller]
    pub fn best_block_info(&self) -> TestBlockInfo {
        TestBlockInfo::from_id(&self.chainstate, self.best_block_id())
    }

    /// Returns a block identifier for the specified height.
    #[track_caller]
    pub fn block_id(&self, height: u64) -> Id<GenBlock> {
        self.chainstate
            .get_block_id_from_height(&BlockHeight::from(height))
            .unwrap()
            .unwrap()
    }

    /// Returns a test block information for the specified height.
    #[track_caller]
    pub fn block_info(&self, height: u64) -> TestBlockInfo {
        let id = self
            .chainstate
            .get_block_id_from_height(&BlockHeight::from(height))
            .unwrap()
            .unwrap();
        TestBlockInfo::from_id(&self.chainstate, id)
    }

    /// Returns a block corresponding to the specified identifier.
    #[track_caller]
    pub fn block(&self, id: Id<Block>) -> Block {
        self.chainstate.get_block(id).unwrap().unwrap()
    }

    /// Returns a block index corresponding to the specified id.
    pub fn block_index(&self, id: &Id<GenBlock>) -> GenBlockIndex {
        self.chainstate.get_gen_block_index(id).unwrap().unwrap()
    }

    pub fn index_at(&self, at: usize) -> &BlockIndex {
        assert!(at > 0, "No block index for genesis");
        &self.block_indexes[at - 1]
    }
}

fn create_utxo_data(
    chainstate: &TestChainstate,
    outsrc: OutPointSourceId,
    index: usize,
    output: &TxOutput,
    rng: &mut impl Rng,
) -> Option<(InputWitness, TxInput, TxOutput)> {
    Some((
        empty_witness(rng),
        TxInput::new(outsrc.clone(), index as u32),
        match output.value() {
            OutputValue::Coin(output_value) => {
                let spent_value = Amount::from_atoms(rng.gen_range(0..output_value.into_atoms()));
                let new_value = (*output_value - spent_value).unwrap();
                utils::ensure!(new_value >= Amount::from_atoms(1));
                TxOutput::new(
                    OutputValue::Coin(new_value),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                )
            }
            OutputValue::Token(asset) => match asset {
                TokenData::TokenTransferV1(_transfer) => TxOutput::new(
                    OutputValue::Token(asset.clone()),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                ),
                TokenData::TokenIssuanceV1(issuance) => TxOutput::new(
                    OutputValue::Token(TokenData::TokenTransferV1(TokenTransferV1 {
                        token_id: match outsrc {
                            OutPointSourceId::Transaction(prev_tx) => {
                                chainstate.get_token_id_from_issuance_tx(&prev_tx).unwrap().unwrap()
                            }
                            OutPointSourceId::BlockReward(_) => return None,
                        },
                        amount: issuance.amount_to_issue,
                    })),
                    OutputPurpose::Transfer(anyonecanspend_address()),
                ),
                TokenData::TokenBurnV1(_burn) => return None,
            },
        },
    ))
}

pub fn empty_witness(rng: &mut impl Rng) -> InputWitness {
    use crypto::random::SliceRandom;
    let mut msg: Vec<u8> = (1..100).collect();
    msg.shuffle(rng);
    InputWitness::NoSignature(Some(msg))
}

pub fn anyonecanspend_address() -> Destination {
    Destination::AnyoneCanSpend
}

pub(crate) fn create_new_outputs(
    chainstate: &TestChainstate,
    srcid: OutPointSourceId,
    outs: &[TxOutput],
    rng: &mut impl Rng,
) -> Vec<(InputWitness, TxInput, TxOutput)> {
    outs.iter()
        .enumerate()
        .filter_map(move |(index, output)| {
            create_utxo_data(chainstate, srcid.clone(), index, output, rng)
        })
        .collect()
}
impl Default for TestFramework {
    fn default() -> Self {
        Self::builder().build()
    }
}
use common::chain::OutPointSourceId;
// TODO: Replace by a proper UTXO set abstraction
// (https://github.com/mintlayer/mintlayer-core/issues/312).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestBlockInfo {
    pub txns: Vec<(OutPointSourceId, Vec<TxOutput>)>,
    pub id: Id<GenBlock>,
}

impl TestBlockInfo {
    pub fn from_block(blk: &Block) -> Self {
        let txns = blk
            .transactions()
            .iter()
            .map(|tx| {
                (
                    OutPointSourceId::Transaction(tx.transaction().get_id()),
                    tx.transaction().outputs().clone(),
                )
            })
            .collect();
        let id = blk.get_id().into();
        Self { txns, id }
    }

    pub fn from_genesis(genesis: &Genesis) -> Self {
        let id: Id<GenBlock> = genesis.get_id().into();
        let outsrc = OutPointSourceId::BlockReward(id);
        let txns = vec![(outsrc, genesis.utxos().to_vec())];
        Self { txns, id }
    }

    pub fn from_id(cs: &TestChainstate, id: Id<GenBlock>) -> Self {
        match id.classify(&cs.get_chain_config()) {
            GenBlockId::Genesis(_) => Self::from_genesis(cs.get_chain_config().genesis_block()),
            GenBlockId::Block(id) => {
                let block = cs.get_block(id).unwrap().unwrap();
                Self::from_block(&block)
            }
        }
    }
}

#[test]
fn build_test_framework() {
    use chainstate::ChainstateConfig;
    use common::chain::config::Builder as ChainConfigBuilder;
    use common::chain::config::ChainType;
    use common::chain::NetUpgrades;
    use common::time_getter::TimeGetter;
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
        tf.chainstate.get_chainstate_config().max_db_commit_attempts,
        max_db_commit_attempts
    );
    assert_eq!(tf.chainstate.get_chain_config().chain_type(), &chain_type);
}

#[test]
fn process_block() {
    use crate::TransactionBuilder;

    let mut tf = TestFramework::default();
    let gen_block_id = tf.genesis().get_id();
    tf.make_block_builder()
        .add_transaction(
            TransactionBuilder::new()
                .add_input(
                    TxInput::new(
                        OutPointSourceId::BlockReward(<Id<GenBlock>>::from(gen_block_id)),
                        0,
                    ),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::new(
                    OutputValue::Coin(Amount::from_atoms(0)),
                    OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                ))
                .build(),
        )
        .build_and_process()
        .unwrap();
}
