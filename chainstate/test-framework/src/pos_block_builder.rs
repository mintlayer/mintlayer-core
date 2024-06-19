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
    signature_destination_getter::SignatureDestinationGetter,
    staking_pools::{apply_staking_pools_updates, StakingPoolUpdate},
    utils::{find_create_pool_tx_in_genesis, pos_mine, produce_kernel_signature, sign_witnesses},
    PoolBalances, TestFramework,
};
use chainstate::{BlockSource, ChainstateError};
use chainstate_storage::{BlockchainStorageRead, TipStorageTag, Transactional};
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
    vrf::VRFPrivateKey,
};
use pos_accounting::{InMemoryPoSAccounting, PoSAccountingDB, PoSAccountingView};
use randomness::{seq::IteratorRandom, CryptoRng, Rng};
use serialization::Encode;
use tokens_accounting::{InMemoryTokensAccounting, TokensAccountingDB};

/// The block builder that allows construction and processing of a block.
pub struct PoSBlockBuilder<'f> {
    framework: &'f mut TestFramework,
    prev_block_hash: Option<Id<GenBlock>>,
    timestamp: BlockTimestamp,
    consensus_data: Option<ConsensusData>,
    transactions: Vec<SignedTransaction>,

    staking_pool: Option<PoolId>,
    staking_pool_balances: Option<PoolBalances>,
    kernel_input: Option<(UtxoOutPoint, Id<GenBlock>)>,
    staker_sk: Option<PrivateKey>,
    staker_vrf_sk: Option<VRFPrivateKey>,

    randomness: Option<PoSRandomness>,

    // need these fields to track info across the txs
    used_utxo: BTreeSet<UtxoOutPoint>,
    account_nonce_tracker: BTreeMap<AccountType, AccountNonce>,
    tokens_accounting_store: InMemoryTokensAccounting,
    pos_accounting_store: InMemoryPoSAccounting,

    staking_pools_updates: Vec<StakingPoolUpdate>,
}

impl<'f> PoSBlockBuilder<'f> {
    /// Creates a new builder instance.
    pub fn new(framework: &'f mut TestFramework) -> Self {
        let transactions = Vec::new();
        let timestamp = BlockTimestamp::from_time(framework.time_getter.get_time());

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
            prev_block_hash: None,
            timestamp,
            consensus_data: None,
            staking_pool: None,
            staking_pool_balances: None,
            kernel_input: None,
            staker_sk: None,
            staker_vrf_sk: None,
            randomness: None,
            used_utxo: BTreeSet::new(),
            account_nonce_tracker: BTreeMap::new(),
            tokens_accounting_store,
            pos_accounting_store,
            staking_pools_updates: Vec::new(),
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

    /// Sets the previous block hash; if not set, the best block will be used.
    pub fn with_parent(mut self, prev_block_hash: Id<GenBlock>) -> Self {
        assert!(self.prev_block_hash.is_none());
        self.prev_block_hash = Some(prev_block_hash);
        self
    }

    /// Explicitly set the previous block hash to the best block (some builder functions require
    /// the parent to be specified explicitly).
    pub fn with_best_block_as_parent(self) -> Self {
        let parent_id = self.framework.chainstate.get_best_block_id().unwrap();
        self.with_parent(parent_id)
    }

    /// Overrides the previous block hash by a random value making the resulting block an orphan.
    pub fn make_orphan(mut self, rng: &mut impl Rng) -> Self {
        assert!(self.prev_block_hash.is_none());
        self.prev_block_hash = Some(Id::new(H256::random_using(rng)));
        self
    }

    /// Overrides the consensus data that is `ConsensusData::None` by default.
    pub fn with_consensus_data(mut self, data: PoSData) -> Self {
        self.consensus_data = Some(ConsensusData::PoS(Box::new(data)));
        self
    }

    pub fn with_stake_spending_key(mut self, staker_key: PrivateKey) -> Self {
        debug_assert!(self.staker_sk.is_none());
        self.staker_sk = Some(staker_key);
        self
    }

    pub fn with_vrf_key(mut self, staker_vrf_key: VRFPrivateKey) -> Self {
        debug_assert!(self.staker_vrf_sk.is_none());
        self.staker_vrf_sk = Some(staker_vrf_key);
        self
    }

    pub fn with_stake_pool_id(mut self, pool_id: PoolId) -> Self {
        debug_assert!(self.staking_pool.is_none());
        self.staking_pool = Some(pool_id);
        self
    }

    pub fn with_randomness(mut self, randomness: PoSRandomness) -> Self {
        self.randomness = Some(randomness);
        self
    }

    pub fn with_kernel_input(
        mut self,
        outpoint: UtxoOutPoint,
        utxo_block_id: Id<GenBlock>,
    ) -> Self {
        debug_assert!(self.kernel_input.is_none());
        self.kernel_input = Some((outpoint, utxo_block_id));
        self
    }

    pub fn with_random_staking_pool(self, rng: &mut impl Rng) -> Self {
        let prev_block_hash = self
            .prev_block_hash
            .expect("this function requires the previous block to be specified in advance");

        let (staking_pool, staker_sk, staker_vrf_sk, kernel_input_outpoint, kernel_utxo_block_id) =
            self.framework
                 .staking_pools
                 .staking_pools_for_base_block(&prev_block_hash)
                 .staking_pools()
                 .iter()
                 .map(|(id, (sk, vrf, kernel_input_outpoint, kernel_utxo_block_id))| (*id, sk.clone(), vrf.clone(), kernel_input_outpoint.clone(), *kernel_utxo_block_id))
                 .choose(rng)
                 .expect("if pool is not provided it should be available for random selection in TestFramework");

        self.with_stake_pool_id(staking_pool)
            .with_stake_spending_key(staker_sk)
            .with_vrf_key(staker_vrf_sk)
            .with_kernel_input(kernel_input_outpoint, kernel_utxo_block_id)
    }

    pub fn with_specific_staking_pool(self, pool_id: &PoolId) -> Self {
        let prev_block_hash = self
            .prev_block_hash
            .expect("this function requires the previous block to be specified in advance");

        let (staker_sk, staker_vrf_sk, kernel_input_outpoint, kernel_utxo_block_id) = self
            .framework
            .staking_pools
            .staking_pools_for_base_block(&prev_block_hash)
            .staking_pools()
            .get(pool_id)
            .unwrap();
        let staker_sk = staker_sk.clone();
        let staker_vrf_sk = staker_vrf_sk.clone();
        let kernel_input_outpoint = kernel_input_outpoint.clone();
        let kernel_utxo_block_id = *kernel_utxo_block_id;

        self.with_stake_pool_id(*pool_id)
            .with_stake_spending_key(staker_sk)
            .with_vrf_key(staker_vrf_sk)
            .with_kernel_input(kernel_input_outpoint, kernel_utxo_block_id)
    }

    // Assume that the specified staking pool has these balances (if not set, the pool balances
    // at the tip will be used).
    pub fn with_staking_pool_balances(mut self, balances: PoolBalances) -> Self {
        self.staking_pool_balances = Some(balances);
        self
    }

    fn build_impl(self, rng: &mut (impl Rng + CryptoRng)) -> (Block, &'f mut TestFramework) {
        let prev_block_hash = self
            .prev_block_hash
            .unwrap_or_else(|| self.framework.chainstate.get_best_block_id().unwrap());

        let (consensus_data, block_timestamp) = match self.consensus_data {
            Some(data) => (data, self.timestamp),
            None => {
                let (pos_data, block_timestamp) = self.mine_pos_block(&prev_block_hash, rng);
                (ConsensusData::PoS(Box::new(pos_data)), block_timestamp)
            }
        };

        let staking_destination = Destination::PublicKey(PublicKey::from_private_key(
            self.staker_sk.as_ref().unwrap(),
        ));
        let staking_pool = self.staking_pool.unwrap();
        let reward = BlockReward::new(vec![TxOutput::ProduceBlockFromStake(
            staking_destination,
            staking_pool,
        )]);

        let block_body = BlockBody::new(reward, self.transactions);
        let merkle_proxy = block_body.merkle_tree_proxy().unwrap();

        let unsigned_header = BlockHeader::new(
            prev_block_hash,
            merkle_proxy.merkle_tree().root(),
            merkle_proxy.witness_merkle_tree().root(),
            block_timestamp,
            consensus_data,
        );

        let signed_header = {
            let signature = self
                .staker_sk
                .as_ref()
                .unwrap()
                .sign_message(&unsigned_header.encode(), &mut *rng)
                .unwrap();
            let sig_data = BlockHeaderSignatureData::new(signature);
            let done_signature = BlockHeaderSignature::HeaderSignature(sig_data);
            unsigned_header.with_signature(done_signature)
        };

        let target_block_time = self.framework.chainstate.get_chain_config().target_block_spacing();
        self.framework.progress_time_seconds_since_epoch(target_block_time.as_secs());

        let block = Block::new_from_header(signed_header, block_body).unwrap();

        let mut staking_pools_updates = self.staking_pools_updates;
        staking_pools_updates.push(StakingPoolUpdate::UsedForStaking {
            pool_id: staking_pool,
            outpoint: UtxoOutPoint::new(block.get_id().into(), 0),
        });
        apply_staking_pools_updates(
            &staking_pools_updates,
            &mut self.framework.staking_pools,
            &block.get_id().into(),
            Some(&prev_block_hash),
        );

        (block, self.framework)
    }

    /// Builds a block without processing it.
    pub fn build(self, rng: &mut (impl Rng + CryptoRng)) -> Block {
        self.build_impl(&mut *rng).0
    }

    /// Constructs a block and processes it by the chainstate.
    pub fn build_and_process(
        self,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        let (block, framework) = self.build_impl(&mut *rng);
        let res = framework.process_block(block, BlockSource::Local)?;
        Ok(res)
    }

    /// Construct a block and process it by the chainstate.
    /// Return the id of the new block.
    pub fn build_and_process_return_block_id(
        self,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Id<Block>, ChainstateError> {
        let (block, framework) = self.build_impl(&mut *rng);
        let block_id = block.get_id();
        framework.process_block(block, BlockSource::Local)?;
        Ok(block_id)
    }

    fn mine_pos_block(
        &self,
        prev_block_hash: &Id<GenBlock>,
        rng: &mut (impl Rng + CryptoRng),
    ) -> (PoSData, BlockTimestamp) {
        let parent_block_index = self.framework.gen_block_index(prev_block_hash);

        let (kernel_input_outpoint, kernel_utxo_block_id) =
            self.kernel_input.clone().unwrap_or_else(|| {
                // if staking outpoint is not set try to extract it from the parent
                match &parent_block_index {
                    chainstate_types::GenBlockIndex::Block(block_index) => {
                        match block_index.block_header().header().consensus_data() {
                            ConsensusData::None | ConsensusData::PoW(_) => {
                                unimplemented!()
                            }
                            ConsensusData::PoS(_) => {
                                let parent_block_id = parent_block_index.block_id();
                                (
                                    UtxoOutPoint::new(parent_block_id.into(), 0),
                                    parent_block_id,
                                )
                            }
                        }
                    }
                    chainstate_types::GenBlockIndex::Genesis(genesis) => (
                        find_create_pool_tx_in_genesis(genesis, &self.staking_pool.unwrap())
                            .unwrap(),
                        genesis.get_id().into(),
                    ),
                }
            });

        let staking_destination = Destination::PublicKey(PublicKey::from_private_key(
            self.staker_sk.as_ref().unwrap(),
        ));
        let kernel_outputs = vec![TxOutput::ProduceBlockFromStake(
            staking_destination.clone(),
            self.staking_pool.unwrap(),
        )];

        let kernel_sig = produce_kernel_signature(
            self.framework,
            rng,
            self.staker_sk.as_ref().unwrap(),
            kernel_outputs.as_slice(),
            staking_destination,
            kernel_utxo_block_id,
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

        let pool_id = self.staking_pool.unwrap();
        let staking_pool_balances = self.staking_pool_balances.unwrap_or_else(|| {
            let storage = &self.framework.storage.transaction_ro().unwrap();
            let pos_db = PoSAccountingDB::<_, TipStorageTag>::new(&storage);

            let staker_balance =
                pos_db.get_pool_data(pool_id).unwrap().unwrap().staker_balance().unwrap();
            let total_balance = pos_db.get_pool_balance(pool_id).unwrap().unwrap();

            PoolBalances {
                total_balance,
                staker_balance,
            }
        });

        pos_mine(
            rng,
            pos_status.get_chain_config(),
            BlockTimestamp::from_time(self.framework.current_time()),
            kernel_input_outpoint,
            InputWitness::Standard(kernel_sig),
            self.staker_vrf_sk.as_ref().unwrap(),
            randomness,
            pool_id,
            chain_config.final_supply().unwrap(),
            epoch_index,
            current_difficulty.into(),
            staking_pool_balances,
        )
        .unwrap()
    }

    /// Adds a transaction that uses random utxos and accounts
    pub fn add_test_transaction(mut self, rng: &mut (impl Rng + CryptoRng)) -> Self {
        let prev_block_hash = self
            .prev_block_hash
            .expect("this function requires the previous block to be specified in advance");

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
        let utxo_set = utxo::UtxosDBInMemoryImpl::new(prev_block_hash, utxo_set);

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
                self.staking_pool,
                account_nonce_getter,
            )
            .make(
                rng,
                &mut self.staking_pools_updates,
                &mut self.framework.key_manager,
            );

        if !tx.inputs().is_empty() && !tx.outputs().is_empty() {
            // First we must sign inputs because after accounting deltas are flushed
            // spending destinations could change
            let tokens_db = TokensAccountingDB::new(&self.tokens_accounting_store);
            let pos_db = PoSAccountingDB::new(&self.pos_accounting_store);
            let destination_getter =
                SignatureDestinationGetter::new_for_transaction(&tokens_db, &pos_db, &utxo_set);
            let witnesses = sign_witnesses(
                rng,
                &self.framework.key_manager,
                self.framework.chainstate.get_chain_config(),
                &tx,
                &utxo_set,
                destination_getter,
            );
            let tx = SignedTransaction::new(tx, witnesses).expect("invalid witness count");

            // flush new tokens info to the in-memory store
            let mut tokens_db = TokensAccountingDB::new(&mut self.tokens_accounting_store);
            tokens_db.merge_with_delta(new_tokens_delta).unwrap();

            // flush new pos accounting info to the in-memory store
            let mut pos_db = PoSAccountingDB::new(&mut self.pos_accounting_store);
            pos_db.merge_with_delta(new_pos_accounting_delta).unwrap();

            // update used utxo set because this function can be called multiple times without flushing data to storage
            tx.transaction().inputs().iter().for_each(|input| {
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

            self.add_transaction(tx)
        } else {
            self
        }
    }
}
