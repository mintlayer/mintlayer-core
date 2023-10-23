// Copyright (c) 2023 RBB S.r.l
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

use crate::{
    utils::{get_target_block_time, pos_mine, produce_kernel_signature},
    TestFramework,
};
use chainstate::{BlockSource, ChainstateError};
use chainstate_types::{pos_randomness::PoSRandomness, BlockIndex, EpochStorageRead};
use common::{
    chain::{
        block::{
            block_body::BlockBody,
            consensus_data::PoSData,
            signed_block_header::{BlockHeaderSignature, BlockHeaderSignatureData},
            timestamp::BlockTimestamp,
            BlockHeader, BlockReward, ConsensusData,
        },
        signature::inputsig::InputWitness,
        signed_transaction::SignedTransaction,
        Block, Destination, GenBlock, PoolId, RequiredConsensus, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, Id, Idable, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey, PublicKey},
    random::{CryptoRng, Rng},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use serialization::Encode;

/// The block builder that allows construction and processing of a block.
pub struct PoSBlockBuilder<'f> {
    framework: &'f mut TestFramework,
    prev_block_hash: Id<GenBlock>,
    timestamp: BlockTimestamp,
    consensus_data: Option<ConsensusData>,
    block_signing_key: Option<PrivateKey>,
    transactions: Vec<SignedTransaction>,

    staking_pool: Option<PoolId>,
    kernel_input_outpoint: Option<UtxoOutPoint>,

    staker_sk: PrivateKey,
    staker_vrf_sk: VRFPrivateKey,

    randomness: Option<PoSRandomness>,
    stake_pool_balance: Option<Amount>,
}

impl<'f> PoSBlockBuilder<'f> {
    /// Creates a new builder instance.
    pub fn new(framework: &'f mut TestFramework, rng: &mut (impl Rng + CryptoRng)) -> Self {
        let transactions = Vec::new();
        let prev_block_hash = framework.chainstate.get_best_block_id().unwrap();
        let timestamp = BlockTimestamp::from_time(framework.time_getter.get_time());

        let (staker_vrf_sk, _) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
        let (staker_sk, _) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);

        let staking_pool =
            framework.chainstate.get_chain_config().genesis_block().utxos().iter().find_map(
                |output| match output {
                    TxOutput::Transfer(_, _)
                    | TxOutput::LockThenTransfer(_, _, _)
                    | TxOutput::Burn(_)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::IssueNft(_, _, _) => None,
                    | TxOutput::CreateStakePool(pool_id, _) => Some(*pool_id),
                },
            );

        Self {
            framework,
            transactions,
            prev_block_hash,
            timestamp,
            consensus_data: None,
            block_signing_key: None,
            staking_pool,
            kernel_input_outpoint: None,
            staker_sk,
            staker_vrf_sk,
            randomness: None,
            stake_pool_balance: None,
        }
    }

    /// Replaces the transactions.
    pub fn with_transactions(mut self, transactions: Vec<SignedTransaction>) -> Self {
        self.transactions = transactions;
        self
    }

    /// Appends the given transaction to the transactions list.
    pub fn add_transaction(mut self, transaction: SignedTransaction) -> Self {
        self.transactions.push(transaction);
        self
    }

    /// Overrides the previous block hash that is deduced by default as the best block.
    pub fn with_parent(mut self, prev_block_hash: Id<GenBlock>) -> Self {
        self.prev_block_hash = prev_block_hash;
        self
    }

    /// Overrides the previous block hash by a random value making the resulting block an orphan.
    pub fn make_orphan(mut self, rng: &mut impl Rng) -> Self {
        self.prev_block_hash = Id::new(H256::random_using(rng));
        self
    }

    /// Overrides the consensus data that is `ConsensusData::None` by default.
    pub fn with_consensus_data(mut self, data: PoSData) -> Self {
        self.consensus_data = Some(ConsensusData::PoS(Box::new(data)));
        self
    }

    pub fn with_block_signing_key(mut self, block_signing_key: PrivateKey) -> Self {
        self.block_signing_key = Some(block_signing_key);
        self
    }

    pub fn with_stake_spending_key(mut self, staker_key: PrivateKey) -> Self {
        self.staker_sk = staker_key;
        self
    }

    pub fn with_vrf_key(mut self, staker_vrf_key: VRFPrivateKey) -> Self {
        self.staker_vrf_sk = staker_vrf_key;
        self
    }

    pub fn with_stake_pool(mut self, pool_id: PoolId) -> Self {
        self.staking_pool = Some(pool_id);
        self
    }

    pub fn with_randomness(mut self, randomness: PoSRandomness) -> Self {
        self.randomness = Some(randomness);
        self
    }

    pub fn with_stake_pool_balance(mut self, balance: Amount) -> Self {
        self.stake_pool_balance = Some(balance);
        self
    }

    pub fn with_kernel_input(mut self, outpoint: UtxoOutPoint) -> Self {
        self.kernel_input_outpoint = Some(outpoint);
        self
    }

    fn build_impl(self) -> (Block, &'f mut TestFramework) {
        let (consensus_data, block_timestamp) = match self.consensus_data {
            Some(data) => (data, self.timestamp),
            None => {
                let (pos_data, block_timestamp) = self.mine_pos_block();
                (ConsensusData::PoS(Box::new(pos_data)), block_timestamp)
            }
        };

        let staking_destination =
            Destination::PublicKey(PublicKey::from_private_key(&self.staker_sk));
        let reward = BlockReward::new(vec![TxOutput::ProduceBlockFromStake(
            staking_destination,
            self.staking_pool.unwrap(),
        )]);

        let block_body = BlockBody::new(reward, self.transactions);
        let merkle_proxy = block_body.merkle_tree_proxy().unwrap();
        let unsigned_header = BlockHeader::new(
            self.prev_block_hash,
            merkle_proxy.merkle_tree().root(),
            merkle_proxy.witness_merkle_tree().root(),
            block_timestamp,
            consensus_data,
        );

        let signed_header = if let Some(key) = self.block_signing_key {
            let signature = key.sign_message(&unsigned_header.encode()).unwrap();
            let sig_data = BlockHeaderSignatureData::new(signature);
            let done_signature = BlockHeaderSignature::HeaderSignature(sig_data);
            unsigned_header.with_signature(done_signature)
        } else {
            unsigned_header.with_no_signature()
        };

        let target_block_time = get_target_block_time(
            self.framework.chainstate.get_chain_config(),
            self.framework.best_block_index().block_height().next_height(),
        );
        self.framework.progress_time_seconds_since_epoch(target_block_time.get());

        (
            Block::new_from_header(signed_header, block_body).unwrap(),
            self.framework,
        )
    }

    /// Builds a block without processing it.
    pub fn build(self) -> Block {
        self.build_impl().0
    }

    /// Constructs a block and processes it by the chainstate.
    pub fn build_and_process(self) -> Result<Option<BlockIndex>, ChainstateError> {
        let (block, framework) = self.build_impl();
        let res = framework.process_block(block, BlockSource::Local)?;
        Ok(res)
    }

    fn mine_pos_block(&self) -> (PoSData, BlockTimestamp) {
        let parent_block_index = self.framework.block_index(&self.prev_block_hash);
        let staking_pool = self.staking_pool.expect("staking pool id must be set");

        let kernel_input_outpoint = self.kernel_input_outpoint.clone().unwrap_or_else(|| {
            // if staking outpoint is not set try to extract it from the parent
            match &parent_block_index {
                chainstate_types::GenBlockIndex::Block(block_index) => {
                    match block_index.block_header().header().consensus_data() {
                        ConsensusData::None | ConsensusData::PoW(_) => {
                            unimplemented!()
                        }
                        ConsensusData::PoS(_) => {
                            UtxoOutPoint::new(parent_block_index.block_id().into(), 0)
                        }
                    }
                }
                chainstate_types::GenBlockIndex::Genesis(genesis) => {
                    let output_index = genesis
                        .utxos()
                        .iter()
                        .position(|output| match output {
                            TxOutput::Transfer(..)
                            | TxOutput::LockThenTransfer(..)
                            | TxOutput::Burn(..)
                            | TxOutput::ProduceBlockFromStake(..)
                            | TxOutput::CreateDelegationId(..)
                            | TxOutput::DelegateStaking(..)
                            | TxOutput::IssueFungibleToken(_)
                            | TxOutput::IssueNft(_, _, _) => false,
                            TxOutput::CreateStakePool(pool_id, _) => *pool_id == staking_pool,
                        })
                        .unwrap();
                    UtxoOutPoint::new(genesis.get_id().into(), output_index as u32)
                }
            }
        });

        let staking_destination =
            Destination::PublicKey(PublicKey::from_private_key(&self.staker_sk));
        let kernel_outputs =
            vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), staking_pool)];

        let kernel_sig = produce_kernel_signature(
            self.framework,
            &self.staker_sk,
            kernel_outputs.as_slice(),
            staking_destination,
            self.prev_block_hash,
            kernel_input_outpoint.clone(),
        );

        let new_block_height = parent_block_index.block_height().next_height();
        let pos_status = match self
            .framework
            .chainstate
            .get_chain_config()
            .consensus_upgrades()
            .consensus_status(new_block_height)
        {
            RequiredConsensus::PoS(status) => status,
            RequiredConsensus::PoW(_) | RequiredConsensus::IgnoreConsensus => {
                panic!("Invalid consensus")
            }
        };
        let current_difficulty = pos_status.get_chain_config().target_limit();
        let chain_config = self.framework.chainstate.get_chain_config().as_ref();
        let epoch_index = chain_config.epoch_index_from_height(&new_block_height);

        let randomness = self.randomness.unwrap_or_else(|| {
            match chain_config.sealed_epoch_index(&new_block_height) {
                Some(epoch) => {
                    *self.framework.storage.get_epoch_data(epoch).unwrap().unwrap().randomness()
                }
                None => PoSRandomness::new(chain_config.initial_randomness()),
            }
        });

        pos_mine(
            &self.framework.storage,
            pos_status.get_chain_config(),
            BlockTimestamp::from_time(self.framework.current_time()),
            kernel_input_outpoint,
            InputWitness::Standard(kernel_sig),
            &self.staker_vrf_sk,
            randomness,
            staking_pool,
            chain_config.final_supply().unwrap(),
            epoch_index,
            current_difficulty.into(),
        )
        .unwrap()
    }
}
