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

use std::collections::{BTreeMap, BTreeSet};

use crate::framework::BlockOutputs;
use crate::signature_destination_getter::SignatureDestinationGetter;
use crate::staking_pools::{apply_staking_pools_updates, StakingPoolUpdate};
use crate::utils::{create_new_outputs, outputs_from_block, sign_witnesses};
use crate::TestFramework;
use chainstate::{BlockSource, ChainstateError};
use chainstate_storage::{BlockchainStorageRead, Transactional};
use chainstate_types::BlockIndex;
use common::chain::block::block_body::BlockBody;
use common::chain::block::signed_block_header::{BlockHeaderSignature, BlockHeaderSignatureData};
use common::chain::block::BlockHeader;
use common::chain::{AccountNonce, AccountType, OutPointSourceId, UtxoOutPoint};
use common::primitives::Idable;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockReward, ConsensusData},
        signature::inputsig::InputWitness,
        signed_transaction::SignedTransaction,
        Block, GenBlock, Transaction, TxInput, TxOutput,
    },
    primitives::{Id, H256},
};
use crypto::key::PrivateKey;
use itertools::Itertools;
use pos_accounting::{InMemoryPoSAccounting, PoSAccountingDB};
use randomness::{CryptoRng, Rng};
use serialization::Encode;
use tokens_accounting::{InMemoryTokensAccounting, TokensAccountingDB};

/// The block builder that allows construction and processing of a block.
pub struct BlockBuilder<'f> {
    framework: &'f mut TestFramework,
    transactions: Vec<SignedTransaction>,
    prev_block_hash: Option<Id<GenBlock>>,
    timestamp: BlockTimestamp,
    consensus_data: ConsensusData,
    reward: BlockReward,
    block_source: BlockSource,
    block_signing_key: Option<PrivateKey>,

    // need these fields to track info across the txs
    used_utxo: BTreeSet<UtxoOutPoint>,
    account_nonce_tracker: BTreeMap<AccountType, AccountNonce>,
    tokens_accounting_store: InMemoryTokensAccounting,
    pos_accounting_store: InMemoryPoSAccounting,

    staking_pools_updates: Vec<StakingPoolUpdate>,
}

impl<'f> BlockBuilder<'f> {
    /// Creates a new builder instance.
    pub fn new(framework: &'f mut TestFramework) -> Self {
        let transactions = Vec::new();
        let timestamp = BlockTimestamp::from_time(framework.time_getter.get_time());
        let consensus_data = ConsensusData::None;
        let reward = BlockReward::new(Vec::new());
        let block_source = BlockSource::Local;
        let used_utxo = BTreeSet::new();
        let account_nonce_tracker = BTreeMap::new();

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
            consensus_data,
            reward,
            block_source,
            block_signing_key: None,
            used_utxo,
            account_nonce_tracker,
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
                None,
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

    /// Returns regular transaction output(s) if any, otherwise returns block reward outputs
    fn filter_outputs(outputs: BlockOutputs) -> BlockOutputs {
        let has_tx_outputs = outputs
            .iter()
            .any(|(output, _)| matches!(output, OutPointSourceId::Transaction(_)));
        outputs
            .into_iter()
            .filter(|(output, _)| {
                matches!(output, OutPointSourceId::Transaction(_)) == has_tx_outputs
            })
            .collect()
    }

    /// Adds a transaction that uses the transactions from the best block as inputs and
    /// produces new outputs.
    pub fn add_test_transaction_from_best_block(self, rng: &mut impl Rng) -> Self {
        let parent = self.framework.best_block_id();
        self.add_test_transaction_with_parent(parent, rng)
    }

    /// Same as `add_test_transaction_from_best_block`, but with a custom parent.
    pub fn add_test_transaction_with_parent(
        self,
        parent: Id<GenBlock>,
        rng: &mut impl Rng,
    ) -> Self {
        let (witnesses, inputs, outputs) = self.make_test_inputs_outputs(
            Self::filter_outputs(self.framework.outputs_from_genblock(parent)),
            rng,
        );
        self.add_transaction(
            SignedTransaction::new(Transaction::new(0, inputs, outputs).unwrap(), witnesses)
                .expect("invalid witness count"),
        )
    }

    /// Same as `add_test_transaction_with_parent`, but uses reference to a block.
    pub fn add_test_transaction_from_block(self, parent: &Block, rng: &mut impl Rng) -> Self {
        let (witnesses, inputs, outputs) =
            self.make_test_inputs_outputs(Self::filter_outputs(outputs_from_block(parent)), rng);
        self.add_transaction(
            SignedTransaction::new(Transaction::new(0, inputs, outputs).unwrap(), witnesses)
                .expect("invalid witness count"),
        )
    }

    /// Adds a transaction that tries to spend the already spent output from the specified block.
    pub fn add_double_spend_transaction(
        mut self,
        parent: Id<GenBlock>,
        spend_from: Id<Block>,
        rng: &mut impl Rng,
    ) -> Self {
        let parent_outputs = self.framework.outputs_from_genblock(parent);
        let (mut witnesses, mut inputs, outputs) =
            self.make_test_inputs_outputs(parent_outputs, rng);
        let spend_from = self.framework.outputs_from_genblock(spend_from.into());
        inputs.push(TxInput::from_utxo(
            spend_from.keys().next().unwrap().clone(),
            0,
        ));
        witnesses.push(InputWitness::NoSignature(None));
        self.transactions.push(
            SignedTransaction::new(Transaction::new(0, inputs, outputs).unwrap(), witnesses)
                .expect("invalid witness count"),
        );
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

    /// Overrides the timestamp that is equal to the current time by default.
    pub fn with_timestamp(mut self, timestamp: BlockTimestamp) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Overrides the consensus data that is `ConsensusData::None` by default.
    pub fn with_consensus_data(mut self, data: ConsensusData) -> Self {
        self.consensus_data = data;
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

    fn build_impl(self, rng: &mut (impl Rng + CryptoRng)) -> (Block, &'f mut TestFramework) {
        let prev_block_hash = self
            .prev_block_hash
            .unwrap_or_else(|| self.framework.chainstate.get_best_block_id().unwrap());
        let block_body = BlockBody::new(self.reward, self.transactions);
        let merkle_proxy = block_body.merkle_tree_proxy().unwrap();
        let unsigned_header = BlockHeader::new(
            prev_block_hash,
            merkle_proxy.merkle_tree().root(),
            merkle_proxy.witness_merkle_tree().root(),
            self.timestamp,
            self.consensus_data,
        );

        let signed_header = if let Some(key) = self.block_signing_key {
            let signature = key.sign_message(&unsigned_header.encode(), &mut *rng).unwrap();
            let sig_data = BlockHeaderSignatureData::new(signature);
            let done_signature = BlockHeaderSignature::HeaderSignature(sig_data);
            unsigned_header.with_signature(done_signature)
        } else {
            unsigned_header.with_no_signature()
        };

        let block = Block::new_from_header(signed_header, block_body).unwrap();

        apply_staking_pools_updates(
            &self.staking_pools_updates,
            &mut self.framework.staking_pools,
            &block.get_id().into(),
            Some(&prev_block_hash),
        );

        (block, self.framework)
    }

    /// Builds a block without processing it.
    pub fn build(self, rng: &mut (impl Rng + CryptoRng)) -> Block {
        self.build_impl(rng).0
    }

    /// Constructs a block and processes it by the chainstate.
    pub fn build_and_process(
        self,
        rng: &mut (impl Rng + CryptoRng),
    ) -> Result<Option<BlockIndex>, ChainstateError> {
        let block_source = self.block_source;
        let (block, framework) = self.build_impl(rng);
        framework.process_block(block, block_source)
    }

    /// Produces a new set of inputs and outputs from the transactions of the specified block.
    fn make_test_inputs_outputs(
        &self,
        outputs: BlockOutputs,
        rng: &mut impl Rng,
    ) -> (Vec<InputWitness>, Vec<TxInput>, Vec<TxOutput>) {
        outputs
            .into_iter()
            .flat_map(|(s, o)| create_new_outputs(s, &o, rng))
            .multiunzip()
    }
}
