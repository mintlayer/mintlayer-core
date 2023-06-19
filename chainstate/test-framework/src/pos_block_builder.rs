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

use crate::TestFramework;
use chainstate::{BlockSource, ChainstateError};
use chainstate_types::pos_randomness::PoSRandomness;
use chainstate_types::vrf_tools::construct_transcript;
use chainstate_types::{BlockIndex, EpochStorageRead};
use common::chain::block::block_body::BlockBody;
use common::chain::block::consensus_data::PoSData;
use common::chain::block::signed_block_header::{BlockHeaderSignature, BlockHeaderSignatureData};
use common::chain::block::{BlockHeader, BlockRewardTransactable};
use common::chain::config::EpochIndex;
use common::chain::signature::inputsig::standard_signature::StandardInputSignature;
use common::chain::signature::sighash::sighashtype::SigHashType;
use common::chain::{Destination, PoolId, RequiredConsensus, UtxoOutPoint};
use common::primitives::{Amount, Compact, Idable};
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        signature::inputsig::InputWitness,
        signed_transaction::SignedTransaction,
        Block, GenBlock, TxOutput,
    },
    primitives::{Id, H256},
};
use crypto::key::{KeyKind, PrivateKey, PublicKey};
use crypto::random::{CryptoRng, Rng};
use crypto::vrf::{VRFKeyKind, VRFPrivateKey, VRFPublicKey};
use serialization::Encode;

/// The block builder that allows construction and processing of a block.
pub struct PoSBlockBuilder<'f> {
    framework: &'f mut TestFramework,
    prev_block_hash: Id<GenBlock>,
    timestamp: BlockTimestamp,
    reward: BlockReward,
    consensus_data: Option<ConsensusData>,
    block_signing_key: Option<PrivateKey>,
    transactions: Vec<SignedTransaction>,

    staking_pool: Option<PoolId>,
    staking_outpoint: Option<UtxoOutPoint>,

    staker_sk: PrivateKey,
    staker_vrf_sk: VRFPrivateKey,
}

impl<'f> PoSBlockBuilder<'f> {
    /// Creates a new builder instance.
    pub fn new(framework: &'f mut TestFramework, rng: &mut (impl Rng + CryptoRng)) -> Self {
        let transactions = Vec::new();
        let prev_block_hash = framework.chainstate.get_best_block_id().unwrap();
        let timestamp = BlockTimestamp::from_duration_since_epoch(framework.time_getter.get_time());
        let reward = BlockReward::new(Vec::new());

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
                    | TxOutput::DelegateStaking(_, _) => None,
                    | TxOutput::CreateStakePool(pool_id, _) => Some(*pool_id),
                },
            );

        Self {
            framework,
            transactions,
            prev_block_hash,
            timestamp,
            consensus_data: None,
            reward,
            block_signing_key: None,
            staking_pool,
            staking_outpoint: None,
            staker_sk,
            staker_vrf_sk,
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

    /// Overrides the timestamp that is equal to the current time by default.
    //pub fn with_timestamp(mut self, timestamp: BlockTimestamp) -> Self {
    //    self.timestamp = timestamp;
    //    self
    //}

    /// Overrides the consensus data that is `ConsensusData::None` by default.
    pub fn with_consensus_data(mut self, data: PoSData) -> Self {
        self.consensus_data = Some(ConsensusData::PoS(Box::new(data)));
        self
    }

    /// Overrides the block reward that is empty by default.
    pub fn with_reward(mut self, reward: Vec<TxOutput>) -> Self {
        self.reward = BlockReward::new(reward);
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

    fn build_impl(self) -> (Block, &'f mut TestFramework) {
        let (consensus_data, block_timestamp) = match self.consensus_data {
            Some(data) => (data, self.timestamp),
            None => {
                let (pos_data, block_timestamp) = self.mine_pos_block();
                (ConsensusData::PoS(Box::new(pos_data)), block_timestamp)
            }
        };
        let block_body = BlockBody::new(self.reward, self.transactions);
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
        framework.process_block(block, BlockSource::Local)
        // FIXME: framework advance time
    }

    fn mine_pos_block(&self) -> (PoSData, BlockTimestamp) {
        //let parent = tf.best_block_index();
        let parent_block_index = self.framework.block_index(&self.prev_block_hash);
        let staking_pool = self.staking_pool.expect("staking pool id must be set");
        //tf.set_time_seconds_since_epoch(parent.block_timestamp().as_int_seconds() + 1);

        let kernel_input = self.staking_outpoint.clone().unwrap_or_else(|| {
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
                            | TxOutput::DelegateStaking(..) => false,
                            TxOutput::CreateStakePool(pool_id, _) => *pool_id == staking_pool,
                        })
                        .unwrap();
                    UtxoOutPoint::new(genesis.get_id().into(), output_index as u32)
                }
            }
        });
        //let kernel_inputs = vec![kernel_input];
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
            kernel_input.clone(),
        );

        let new_block_height = parent_block_index.block_height().next_height();
        // FIXME: calculate???
        let current_difficulty = match self
            .framework
            .chainstate
            .get_chain_config()
            .net_upgrade()
            .consensus_status(new_block_height)
        {
            RequiredConsensus::PoS(status) => status,
            RequiredConsensus::PoW(_) | RequiredConsensus::IgnoreConsensus => {
                panic!("Invalid consensus")
            }
        }
        .get_chain_config()
        .target_limit();
        let chain_config = self.framework.chainstate.get_chain_config().as_ref();
        let randomness = match chain_config.sealed_epoch_index(&new_block_height) {
            Some(epoch) => self
                .framework
                .storage
                .get_epoch_data(epoch)
                .unwrap()
                .unwrap()
                .randomness()
                .clone(),
            None => PoSRandomness::new(chain_config.initial_randomness()),
        };
        let pool_balance =
            self.framework.chainstate.get_stake_pool_balance(staking_pool).unwrap().unwrap();

        pos_mine(
            BlockTimestamp::from_duration_since_epoch(self.framework.current_time()),
            kernel_input,
            InputWitness::Standard(kernel_sig),
            &self.staker_vrf_sk,
            randomness,
            staking_pool,
            pool_balance,
            0,
            current_difficulty.into(),
        )
        .unwrap()
    }
}

fn produce_kernel_signature(
    tf: &TestFramework,
    staking_sk: &PrivateKey,
    reward_outputs: &[TxOutput],
    staking_destination: Destination,
    kernel_utxo_block_id: Id<GenBlock>,
    kernel_outpoint: UtxoOutPoint,
) -> StandardInputSignature {
    let block_outputs = tf.outputs_from_genblock(kernel_utxo_block_id);
    let utxo = &block_outputs.get(&kernel_outpoint.tx_id()).unwrap()
        [kernel_outpoint.output_index() as usize];

    let kernel_inputs = vec![kernel_outpoint.into()];

    let block_reward_tx =
        BlockRewardTransactable::new(Some(kernel_inputs.as_slice()), Some(reward_outputs), None);
    StandardInputSignature::produce_uniparty_signature_for_input(
        staking_sk,
        SigHashType::default(),
        staking_destination,
        &block_reward_tx,
        std::iter::once(Some(utxo)).collect::<Vec<_>>().as_slice(),
        0,
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn pos_mine(
    initial_timestamp: BlockTimestamp,
    kernel_outpoint: UtxoOutPoint,
    kernel_witness: InputWitness,
    vrf_sk: &VRFPrivateKey,
    sealed_epoch_randomness: PoSRandomness,
    pool_id: PoolId,
    pool_balance: Amount,
    epoch_index: EpochIndex,
    target: Compact,
) -> Option<(PoSData, BlockTimestamp)> {
    let mut timestamp = initial_timestamp;

    for _ in 0..1000 {
        let transcript =
            construct_transcript(epoch_index, &sealed_epoch_randomness.value(), timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(transcript.into());

        let pos_data = PoSData::new(
            vec![kernel_outpoint.clone().into()],
            vec![kernel_witness.clone()],
            pool_id,
            vrf_data,
            target,
        );

        let vrf_pk = VRFPublicKey::from_private_key(vrf_sk);
        if consensus::check_pos_hash(
            epoch_index,
            &sealed_epoch_randomness,
            &pos_data,
            &vrf_pk,
            timestamp,
            pool_balance,
        )
        .is_ok()
        {
            return Some((pos_data, timestamp));
        }

        timestamp = timestamp.add_int_seconds(1).unwrap();
    }
    None
}
