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

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    utils::{pos_mine, produce_kernel_signature},
    TestFramework,
};
use chainstate::{BlockSource, ChainstateError};
use chainstate_storage::{BlockchainStorageRead, Transactional};
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
        AccountNonce, AccountType, Block, Destination, GenBlock, PoolId, RequiredConsensus,
        TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Id, Idable, H256},
};
use crypto::{
    key::{PrivateKey, PublicKey},
    random::{seq::IteratorRandom, CryptoRng, Rng},
    vrf::VRFPrivateKey,
};
use pos_accounting::{InMemoryPoSAccounting, PoSAccountingDB};
use serialization::Encode;
use tokens_accounting::{InMemoryTokensAccounting, TokensAccountingDB};

/// The block builder that allows construction and processing of a block.
pub struct PoSBlockBuilder<'f> {
    framework: &'f mut TestFramework,
    prev_block_hash: Id<GenBlock>,
    timestamp: BlockTimestamp,
    consensus_data: Option<ConsensusData>,
    transactions: Vec<SignedTransaction>,

    staking_pool: PoolId,
    kernel_input_outpoint: Option<UtxoOutPoint>,
    staker_sk: PrivateKey,
    staker_vrf_sk: VRFPrivateKey,

    randomness: Option<PoSRandomness>, // FIXME: remove it

    // need these fields to track info across the txs
    used_utxo: BTreeSet<UtxoOutPoint>,
    account_nonce_tracker: BTreeMap<AccountType, AccountNonce>,
    tokens_accounting_store: InMemoryTokensAccounting,
    pos_accounting_store: InMemoryPoSAccounting,
}

impl<'f> PoSBlockBuilder<'f> {
    /// Creates a new builder instance.
    pub fn new(
        framework: &'f mut TestFramework,
        rng: &mut (impl Rng + CryptoRng),
        staking_pool: Option<(PoolId, PrivateKey, VRFPrivateKey)>,
    ) -> Self {
        let transactions = Vec::new();
        let prev_block_hash = framework.chainstate.get_best_block_id().unwrap();
        let timestamp = BlockTimestamp::from_time(framework.time_getter.get_time());

        // Staking pool is set here and via builders methods because it must be known in advance before `add_test_transaction` is called.
        // Also it would make order of calls matter.
        let (staking_pool, staker_sk, staker_vrf_sk) = staking_pool.unwrap_or_else(|| {
            framework
                .staking_pools
                .staking_pools()
                .iter()
                .map(|(id, (sk, vrf))| (*id, sk.clone(), vrf.clone()))
                .choose(rng)
                .expect("if pool is not provided it should be available for random selection in TestFramework")
        });

        let all_tokens_data = framework
            .storage
            .transaction_ro()
            .unwrap()
            .read_tokens_accounting_data()
            .unwrap();
        let tokens_accounting_store = InMemoryTokensAccounting::from_values(
            all_tokens_data.token_data,
            all_tokens_data.circulating_supply,
        );

        let all_pos_accounting_data = framework
            .storage
            .transaction_ro()
            .unwrap()
            .read_pos_accounting_data_tip()
            .unwrap();
        let pos_accounting_store = InMemoryPoSAccounting::from_data(all_pos_accounting_data);

        Self {
            framework,
            transactions,
            prev_block_hash,
            timestamp,
            consensus_data: None,
            staking_pool,
            kernel_input_outpoint: None,
            staker_sk,
            staker_vrf_sk,
            randomness: None,
            used_utxo: BTreeSet::new(),
            account_nonce_tracker: BTreeMap::new(),
            tokens_accounting_store,
            pos_accounting_store,
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

    pub fn with_randomness(mut self, randomness: PoSRandomness) -> Self {
        self.randomness = Some(randomness);
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
            self.staking_pool,
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

        let signed_header = {
            let signature = self.staker_sk.sign_message(&unsigned_header.encode()).unwrap();
            let sig_data = BlockHeaderSignatureData::new(signature);
            let done_signature = BlockHeaderSignature::HeaderSignature(sig_data);
            unsigned_header.with_signature(done_signature)
        };

        let target_block_time = self.framework.chainstate.get_chain_config().target_block_spacing();
        self.framework.progress_time_seconds_since_epoch(target_block_time.as_secs());

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

        let kernel_input_outpoint = self.kernel_input_outpoint.clone().unwrap_or_else(|| {
            // if staking outpoint is not set try to extract it from the parent
            match &parent_block_index {
                chainstate_types::GenBlockIndex::Block(block_index) => {
                    match block_index.block_header().header().consensus_data() {
                        ConsensusData::None | ConsensusData::PoW(_) => {
                            unimplemented!()
                        }
                        ConsensusData::PoS(data) => {
                            if *data.stake_pool_id() == self.staking_pool {
                                UtxoOutPoint::new(parent_block_index.block_id().into(), 0)
                            } else {
                                // FIXME: look among transactions
                                todo!()
                            }
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
                            | TxOutput::IssueNft(_, _, _)
                            | TxOutput::DataDeposit(_) => false,
                            TxOutput::CreateStakePool(pool_id, _) => *pool_id == self.staking_pool,
                        })
                        .unwrap();
                    UtxoOutPoint::new(genesis.get_id().into(), output_index as u32)
                }
            }
        });

        let staking_destination =
            Destination::PublicKey(PublicKey::from_private_key(&self.staker_sk));
        let kernel_outputs =
            vec![TxOutput::ProduceBlockFromStake(staking_destination.clone(), self.staking_pool)];

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
                Some(epoch) => *self
                    .framework
                    .storage
                    .transaction_ro()
                    .unwrap()
                    .get_epoch_data(epoch)
                    .unwrap()
                    .unwrap()
                    .randomness(),
                None => PoSRandomness::new(chain_config.initial_randomness()),
            }
        });

        pos_mine(
            &self.framework.storage.transaction_ro().unwrap(),
            pos_status.get_chain_config(),
            BlockTimestamp::from_time(self.framework.current_time()),
            kernel_input_outpoint,
            InputWitness::Standard(kernel_sig),
            &self.staker_vrf_sk,
            randomness,
            self.staking_pool,
            chain_config.final_supply().unwrap(),
            epoch_index,
            current_difficulty.into(),
        )
        .unwrap()
    }

    /// Adds a transaction that uses random utxos and accounts
    pub fn add_test_transaction(mut self, rng: &mut (impl Rng + CryptoRng)) -> Self {
        let utxo_set = self
            .framework
            .storage
            .transaction_ro()
            .unwrap()
            .read_utxo_set()
            .unwrap()
            .into_iter()
            .filter(|(outpoint, _)| !self.used_utxo.contains(outpoint))
            .collect();

        let account_nonce_getter = Box::new(|account: AccountType| -> Option<AccountNonce> {
            self.account_nonce_tracker.get(&account).copied().or_else(|| {
                let db_tx = self.framework.storage.transaction_ro().unwrap();
                db_tx.get_account_nonce_count(account).unwrap()
            })
        });

        let (tx, new_tokens_delta, new_pos_accounting_delta) =
            super::random_tx_maker::RandomTxMaker::new(
                &self.framework.chainstate,
                &utxo_set,
                &self.tokens_accounting_store,
                &self.pos_accounting_store,
                Some(self.staking_pool),
                account_nonce_getter,
            )
            .make(rng, &mut self.framework.staking_pools);

        if !tx.inputs().is_empty() && !tx.outputs().is_empty() {
            // flush new tokens info to the in-memory store
            let mut tokens_db = TokensAccountingDB::new(&mut self.tokens_accounting_store);
            tokens_db.merge_with_delta(new_tokens_delta).unwrap();

            // flush new pos accounting info to the in-memory store
            let mut pos_db = PoSAccountingDB::new(&mut self.pos_accounting_store);
            pos_db.merge_with_delta(new_pos_accounting_delta).unwrap();

            // update used utxo set because this function can be called multiple times without flushing data to storage
            tx.inputs().iter().for_each(|input| {
                match input {
                    TxInput::Utxo(utxo_outpoint) => {
                        self.used_utxo.insert(utxo_outpoint.clone());
                    }
                    TxInput::Account(outpoint) => {
                        self.account_nonce_tracker
                            .insert(outpoint.account().clone().into(), outpoint.nonce());
                    }
                    TxInput::AccountCommand(nonce, op) => {
                        self.account_nonce_tracker.insert(op.clone().into(), *nonce);
                    }
                };
            });

            let witnesses = tx.inputs().iter().map(|_| super::empty_witness(rng)).collect();
            let tx = SignedTransaction::new(tx, witnesses).expect("invalid witness count");

            self.add_transaction(tx)
        } else {
            self
        }
    }
}
