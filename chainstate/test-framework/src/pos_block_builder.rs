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
    random_tx_maker::StakingPoolsObserver,
    signature_destination_getter::SignatureDestinationGetter,
    utils::{find_create_pool_tx_in_genesis, pos_mine, produce_kernel_signature, sign_witnesses},
    TestFramework,
};
use chainstate::{BlockSource, ChainstateError};
use chainstate_storage::{BlockchainStorageRead, Transactional};
use chainstate_types::{pos_randomness::PoSRandomness, BlockIndex};
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
    primitives::{Id, Idable},
};
use crypto::{
    key::{PrivateKey, PublicKey},
    vrf::VRFPrivateKey,
};
use orders_accounting::{InMemoryOrdersAccounting, OrdersAccountingDB};
use pos_accounting::{InMemoryPoSAccounting, PoSAccountingDB};
use randomness::{seq::IteratorRandom, CryptoRng, Rng};
use serialization::Encode;
use tokens_accounting::{InMemoryTokensAccounting, TokensAccountingDB};

/// The block builder that allows construction and processing of a block.
pub struct PoSBlockBuilder<'f> {
    framework: &'f mut TestFramework,
    prev_block_hash: Id<GenBlock>,
    // If true, prev_block_hash has been used in some way already and cannot be changed.
    prev_block_hash_used: bool,
    timestamp: BlockTimestamp,
    consensus_data: Option<ConsensusData>,
    transactions: Vec<SignedTransaction>,

    staking_pool: Option<PoolId>,
    kernel_input_outpoint: Option<UtxoOutPoint>,
    staker_sk: Option<PrivateKey>,
    staker_vrf_sk: Option<VRFPrivateKey>,

    randomness: Option<PoSRandomness>,

    // need these fields to track info across the txs
    used_utxo: BTreeSet<UtxoOutPoint>,
    account_nonce_tracker: BTreeMap<AccountType, AccountNonce>,
    tokens_accounting_store: InMemoryTokensAccounting,
    pos_accounting_store: InMemoryPoSAccounting,
    orders_accounting_store: InMemoryOrdersAccounting,
}

impl<'f> PoSBlockBuilder<'f> {
    /// Creates a new builder instance.
    pub fn new(framework: &'f mut TestFramework) -> Self {
        let transactions = Vec::new();
        let prev_block_hash = framework.chainstate.get_best_block_id().unwrap();
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

        let all_orders_data = framework
            .storage
            .transaction_ro()
            .unwrap()
            .read_orders_accounting_data()
            .unwrap();
        let orders_accounting_store = InMemoryOrdersAccounting::from_values(
            all_orders_data.order_data,
            all_orders_data.ask_balances,
            all_orders_data.give_balances,
        );

        Self {
            framework,
            transactions,
            prev_block_hash,
            prev_block_hash_used: false,
            timestamp,
            consensus_data: None,
            staking_pool: None,
            kernel_input_outpoint: None,
            staker_sk: None,
            staker_vrf_sk: None,
            randomness: None,
            used_utxo: BTreeSet::new(),
            account_nonce_tracker: BTreeMap::new(),
            tokens_accounting_store,
            pos_accounting_store,
            orders_accounting_store,
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
        assert!(
            !self.prev_block_hash_used,
            "The current builder state may depend on the previous value of prev_block_hash; consider re-ordering function calls"
        );
        self.prev_block_hash = prev_block_hash;
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

    pub fn with_kernel_input(mut self, outpoint: UtxoOutPoint) -> Self {
        debug_assert!(self.kernel_input_outpoint.is_none());
        self.kernel_input_outpoint = Some(outpoint);
        self
    }

    pub fn with_random_staking_pool(self, rng: &mut impl Rng) -> Self {
        let (staking_pool, staker_sk, staker_vrf_sk, kernel_input_outpoint) =
            self.framework
                 .staking_pools
                 .staking_pools()
                 .iter()
                 .map(|(id, (sk, vrf, kernel_input_outpoint))| (*id, sk.clone(), vrf.clone(), kernel_input_outpoint.clone()))
                 .choose(rng)
                 .expect("if pool is not provided it should be available for random selection in TestFramework");

        self.with_stake_pool_id(staking_pool)
            .with_stake_spending_key(staker_sk)
            .with_vrf_key(staker_vrf_sk)
            .with_kernel_input(kernel_input_outpoint)
    }

    pub fn with_specific_staking_pool(self, pool_id: &PoolId) -> Self {
        let (staker_sk, staker_vrf_sk, kernel_input_outpoint) =
            self.framework.staking_pools.staking_pools().get(pool_id).unwrap();
        let staker_sk = staker_sk.clone();
        let staker_vrf_sk = staker_vrf_sk.clone();
        let kernel_input_outpoint = kernel_input_outpoint.clone();

        self.with_stake_pool_id(*pool_id)
            .with_stake_spending_key(staker_sk)
            .with_vrf_key(staker_vrf_sk)
            .with_kernel_input(kernel_input_outpoint)
    }

    fn build_impl(self, rng: &mut (impl Rng + CryptoRng)) -> (Block, &'f mut TestFramework) {
        let (consensus_data, block_timestamp) = match self.consensus_data {
            Some(data) => (data, self.timestamp),
            None => {
                let (pos_data, block_timestamp) = self.mine_pos_block(rng);
                (ConsensusData::PoS(Box::new(pos_data)), block_timestamp)
            }
        };

        let staking_destination = Destination::PublicKey(PublicKey::from_private_key(
            self.staker_sk.as_ref().unwrap(),
        ));
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

        self.framework.staking_pools.on_pool_used_for_staking(
            self.staking_pool.unwrap(),
            UtxoOutPoint::new(block.get_id().into(), 0),
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

    fn mine_pos_block(&self, rng: &mut (impl Rng + CryptoRng)) -> (PoSData, BlockTimestamp) {
        let parent_block_index = self.framework.gen_block_index(&self.prev_block_hash);

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
                    find_create_pool_tx_in_genesis(genesis, &self.staking_pool.unwrap()).unwrap()
                }
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

        let randomness = self
            .randomness
            .unwrap_or_else(|| self.framework.pos_randomness_for_height(&new_block_height));

        pos_mine(
            rng,
            &self.framework.storage.transaction_ro().unwrap(),
            pos_status.get_chain_config(),
            BlockTimestamp::from_time(self.framework.current_time()),
            kernel_input_outpoint,
            InputWitness::Standard(kernel_sig),
            self.staker_vrf_sk.as_ref().unwrap(),
            randomness,
            self.staking_pool.unwrap(),
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
        let utxo_set = utxo::UtxosDBInMemoryImpl::new(self.prev_block_hash, utxo_set);
        self.prev_block_hash_used = true;

        let account_nonce_getter = Box::new(|account: AccountType| -> Option<AccountNonce> {
            self.account_nonce_tracker.get(&account).copied().or_else(|| {
                let db_tx = self.framework.storage.transaction_ro().unwrap();
                db_tx.get_account_nonce_count(account).unwrap()
            })
        });

        let (tx, new_tokens_delta, new_pos_accounting_delta, new_orders_accounting_delta) =
            super::random_tx_maker::RandomTxMaker::new(
                &self.framework.chainstate,
                &utxo_set,
                &self.tokens_accounting_store,
                &self.pos_accounting_store,
                &self.orders_accounting_store,
                self.staking_pool,
                account_nonce_getter,
            )
            .make(
                rng,
                &mut self.framework.staking_pools,
                &mut self.framework.key_manager,
            );

        if !tx.inputs().is_empty() && !tx.outputs().is_empty() {
            // First we must sign inputs because after accounting deltas are flushed
            // spending destinations could change
            let tokens_db = TokensAccountingDB::new(&self.tokens_accounting_store);
            let pos_db = PoSAccountingDB::new(&self.pos_accounting_store);
            let orders_db = OrdersAccountingDB::new(&self.orders_accounting_store);
            let destination_getter = SignatureDestinationGetter::new_for_transaction(
                &tokens_db, &pos_db, &orders_db, &utxo_set,
            );
            let block_height = self
                .framework
                .gen_block_index(&self.prev_block_hash)
                .block_height()
                .next_height();
            let witnesses = sign_witnesses(
                rng,
                &self.framework.key_manager,
                self.framework.chainstate.get_chain_config(),
                &tx,
                &utxo_set,
                &pos_db,
                &orders_db,
                destination_getter,
                block_height,
            );
            let tx = SignedTransaction::new(tx, witnesses).expect("invalid witness count");

            // flush new tokens info to the in-memory store
            let mut tokens_db = TokensAccountingDB::new(&mut self.tokens_accounting_store);
            tokens_db.merge_with_delta(new_tokens_delta).unwrap();

            // flush new orders info to the in-memory store
            let mut orders_db = OrdersAccountingDB::new(&mut self.orders_accounting_store);
            orders_db.merge_with_delta(new_orders_accounting_delta).unwrap();

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
                            .insert(outpoint.account().into(), outpoint.nonce());
                    }
                    TxInput::AccountCommand(nonce, op) => {
                        self.account_nonce_tracker.insert(op.into(), *nonce);
                    }
                    TxInput::OrderAccountCommand(..) => {}
                };
            });

            self.add_transaction(tx)
        } else {
            self
        }
    }
}
