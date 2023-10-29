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

mod input_output_policy;
mod pos_accounting_delta_adapter;
mod pos_accounting_undo_cache;
mod reward_distribution;
mod signature_check;
mod token_issuance_cache;
mod tokens_accounting_undo_cache;
mod transferred_amount_check;
mod utxos_undo_cache;

pub mod error;
pub mod flush;
pub mod hierarchy;
pub mod signature_destination_getter;
pub mod storage;
pub mod timelock_check;

mod amounts_map;
pub use amounts_map::CoinOrTokenId;

mod tx_source;
use tokens_accounting::{
    TokensAccountingCache, TokensAccountingDB, TokensAccountingDeltaData,
    TokensAccountingOperations, TokensAccountingStorageRead, TokensAccountingView,
};
pub use tx_source::{TransactionSource, TransactionSourceForConnect};

mod cached_operation;
pub use cached_operation::CachedOperation;

pub use input_output_policy::IOPolicyError;

use std::collections::BTreeMap;

use self::{
    error::{ConnectTransactionError, SpendStakeError, TokensError},
    pos_accounting_delta_adapter::PoSAccountingDeltaAdapter,
    pos_accounting_undo_cache::{PoSAccountingBlockUndoCache, PoSAccountingBlockUndoEntry},
    signature_destination_getter::SignatureDestinationGetter,
    storage::TransactionVerifierStorageRef,
    token_issuance_cache::{ConsumedTokenIssuanceCache, TokenIssuanceCache},
    tokens_accounting_undo_cache::{
        TokensAccountingBlockUndoCache, TokensAccountingBlockUndoEntry,
    },
    transferred_amount_check::{
        check_transferred_amount_in_reward, check_transferred_amounts_and_get_fee,
    },
    utxos_undo_cache::{UtxosBlockUndoCache, UtxosBlockUndoEntry},
};
use ::utils::{ensure, shallow_clone::ShallowClone};

use chainstate_types::BlockIndex;
use common::{
    chain::{
        block::{timestamp::BlockTimestamp, BlockRewardTransactable, ConsensusData},
        output_value::OutputValue,
        signature::Signable,
        signed_transaction::SignedTransaction,
        tokens::{get_issuance_count_via_tokens_op, make_token_id, TokenId, TokenIssuanceVersion},
        AccountCommand, AccountNonce, AccountSpending, AccountType, Block, ChainConfig,
        DelegationId, GenBlock, PoolId, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{id::WithId, Amount, BlockHeight, Id, Idable},
};
use consensus::ConsensusPoSError;
use pos_accounting::{
    PoSAccountingDelta, PoSAccountingDeltaData, PoSAccountingOperations, PoSAccountingUndo,
    PoSAccountingView, PoolData,
};
use utxo::{ConsumedUtxoCache, UtxosCache, UtxosDB, UtxosView};

// TODO: We can move it to mod common, because in chain config we have `token_min_issuance_fee`
//       that essentially belongs to this type, but return Amount
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fee(pub Amount);

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Subsidy(pub Amount);

/// The change that a block has caused to the blockchain state
#[derive(Debug, Eq, PartialEq)]
pub struct TransactionVerifierDelta {
    utxo_cache: ConsumedUtxoCache,
    utxo_block_undo: BTreeMap<TransactionSource, UtxosBlockUndoEntry>,
    token_issuance_cache: ConsumedTokenIssuanceCache,
    accounting_delta: PoSAccountingDeltaData,
    pos_accounting_delta_undo: BTreeMap<TransactionSource, PoSAccountingBlockUndoEntry>,
    pos_accounting_block_deltas: BTreeMap<TransactionSource, PoSAccountingDeltaData>,
    account_nonce: BTreeMap<AccountType, CachedOperation<AccountNonce>>,
    tokens_accounting_delta: TokensAccountingDeltaData,
    tokens_accounting_delta_undo: BTreeMap<TransactionSource, TokensAccountingBlockUndoEntry>,
}

impl TransactionVerifierDelta {
    pub fn consume(self) -> (ConsumedUtxoCache, PoSAccountingDeltaData) {
        (self.utxo_cache, self.accounting_delta)
    }
}

/// The tool used to verify transactions and cache their updated states in memory
pub struct TransactionVerifier<C, S, U, A, T> {
    chain_config: C,
    storage: S,
    best_block: Id<GenBlock>,

    token_issuance_cache: TokenIssuanceCache,

    utxo_cache: UtxosCache<U>,
    utxo_block_undo: UtxosBlockUndoCache,

    pos_accounting_adapter: PoSAccountingDeltaAdapter<A>,
    pos_accounting_block_undo: PoSAccountingBlockUndoCache,

    tokens_accounting_cache: TokensAccountingCache<T>,
    tokens_accounting_block_undo: TokensAccountingBlockUndoCache,

    account_nonce: BTreeMap<AccountType, CachedOperation<AccountNonce>>,
}

impl<C, S: TransactionVerifierStorageRef + ShallowClone>
    TransactionVerifier<C, S, UtxosDB<S>, S, TokensAccountingDB<S>>
{
    pub fn new(storage: S, chain_config: C) -> Self {
        let accounting_delta_adapter = PoSAccountingDeltaAdapter::new(storage.shallow_clone());
        let utxo_cache = UtxosCache::new(UtxosDB::new(storage.shallow_clone()))
            .expect("Utxo cache setup failed");
        let best_block = storage
            .get_best_block_for_utxos()
            .expect("Database error while reading utxos best block");
        let tokens_accounting_cache =
            TokensAccountingCache::new(TokensAccountingDB::new(storage.shallow_clone()));
        Self {
            storage,
            chain_config,
            best_block,
            token_issuance_cache: TokenIssuanceCache::new(),
            utxo_cache,
            utxo_block_undo: UtxosBlockUndoCache::new(),
            pos_accounting_adapter: accounting_delta_adapter,
            pos_accounting_block_undo: PoSAccountingBlockUndoCache::new(),
            tokens_accounting_cache,
            tokens_accounting_block_undo: TokensAccountingBlockUndoCache::new(),
            account_nonce: BTreeMap::new(),
        }
    }
}

impl<C, S, U, A, T> TransactionVerifier<C, S, U, A, T>
where
    S: TransactionVerifierStorageRef,
    U: UtxosView + Send + Sync,
    A: PoSAccountingView + Send + Sync,
    T: TokensAccountingView + Send + Sync,
{
    pub fn new_generic(
        storage: S,
        chain_config: C,
        utxos: U,
        accounting: A,
        tokens_accounting: T,
    ) -> Self {
        // TODO: both "expect"s in this function may fire when exiting the node-gui app;
        // get rid of them and return a proper Result.
        // See https://github.com/mintlayer/mintlayer-core/issues/1221
        let best_block = storage
            .get_best_block_for_utxos()
            .expect("Database error while reading utxos best block");
        Self {
            storage,
            chain_config,
            best_block,
            token_issuance_cache: TokenIssuanceCache::new(),
            utxo_cache: UtxosCache::new(utxos).expect("Utxo cache setup failed"),
            utxo_block_undo: UtxosBlockUndoCache::new(),
            pos_accounting_adapter: PoSAccountingDeltaAdapter::new(accounting),
            pos_accounting_block_undo: PoSAccountingBlockUndoCache::new(),
            tokens_accounting_cache: TokensAccountingCache::new(tokens_accounting),
            tokens_accounting_block_undo: TokensAccountingBlockUndoCache::new(),
            account_nonce: BTreeMap::new(),
        }
    }
}

impl<C, S, U, A, T> TransactionVerifier<C, S, U, A, T>
where
    C: AsRef<ChainConfig>,
    S: TransactionVerifierStorageRef,
    U: UtxosView,
    A: PoSAccountingView,
    T: TokensAccountingView,
    <S as utxo::UtxosStorageRead>::Error: From<U::Error>,
{
    pub fn derive_child(
        &self,
    ) -> TransactionVerifier<
        &ChainConfig,
        &Self,
        &UtxosCache<U>,
        &PoSAccountingDelta<A>,
        &TokensAccountingCache<T>,
    > {
        TransactionVerifier {
            storage: self,
            chain_config: self.chain_config.as_ref(),
            utxo_cache: UtxosCache::new(&self.utxo_cache).expect("construct"),
            utxo_block_undo: UtxosBlockUndoCache::new(),
            token_issuance_cache: TokenIssuanceCache::new(),
            pos_accounting_adapter: PoSAccountingDeltaAdapter::new(
                self.pos_accounting_adapter.accounting_delta(),
            ),
            pos_accounting_block_undo: PoSAccountingBlockUndoCache::new(),
            tokens_accounting_cache: TokensAccountingCache::new(&self.tokens_accounting_cache),
            tokens_accounting_block_undo: TokensAccountingBlockUndoCache::new(),
            best_block: self.best_block,
            account_nonce: BTreeMap::new(),
        }
    }

    fn get_pool_data_from_output_in_reward(
        &self,
        output: &TxOutput,
        block_id: Id<Block>,
    ) -> Result<PoolData, ConnectTransactionError> {
        match output {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_) => Err(ConnectTransactionError::IOPolicyError(
                IOPolicyError::InvalidOutputTypeInReward,
                block_id.into(),
            )),
            TxOutput::CreateStakePool(_, d) => Ok(d.as_ref().clone().into()),
            TxOutput::ProduceBlockFromStake(_, pool_id) => self
                .pos_accounting_adapter
                .accounting_delta()
                .get_pool_data(*pool_id)?
                .ok_or(ConnectTransactionError::PoolDataNotFound(*pool_id)),
        }
    }

    fn get_pool_id_from_output_in_reward(
        &self,
        output: &TxOutput,
        block_id: Id<Block>,
    ) -> Result<PoolId, ConnectTransactionError> {
        match output {
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_) => Err(ConnectTransactionError::IOPolicyError(
                IOPolicyError::InvalidOutputTypeInReward,
                block_id.into(),
            )),
            TxOutput::CreateStakePool(pool_id, _) => Ok(*pool_id),
            TxOutput::ProduceBlockFromStake(_, pool_id) => Ok(*pool_id),
        }
    }

    fn check_stake_outputs_in_reward(
        &self,
        block: &WithId<Block>,
    ) -> Result<(), ConnectTransactionError> {
        match block.consensus_data() {
            ConsensusData::None | ConsensusData::PoW(_) => Ok(()),
            ConsensusData::PoS(_) => {
                let block_reward_transactable = block.block_reward_transactable();

                let kernel_output = consensus::get_kernel_output(
                    block_reward_transactable.inputs().ok_or(
                        SpendStakeError::ConsensusPoSError(ConsensusPoSError::NoKernel),
                    )?,
                    &self.utxo_cache,
                )
                .map_err(SpendStakeError::ConsensusPoSError)?;

                let reward_output = match block_reward_transactable
                    .outputs()
                    .ok_or(SpendStakeError::NoBlockRewardOutputs)?
                {
                    [] => Err(SpendStakeError::NoBlockRewardOutputs),
                    [output] => Ok(output),
                    _ => Err(SpendStakeError::MultipleBlockRewardOutputs),
                }?;

                let kernel_pool_id =
                    self.get_pool_id_from_output_in_reward(&kernel_output, block.get_id())?;
                let reward_pool_id =
                    self.get_pool_id_from_output_in_reward(reward_output, block.get_id())?;

                ensure!(
                    kernel_pool_id == reward_pool_id,
                    SpendStakeError::StakePoolIdMismatch(kernel_pool_id, reward_pool_id)
                );

                let kernel_pool_data =
                    self.get_pool_data_from_output_in_reward(&kernel_output, block.get_id())?;
                let reward_pool_data =
                    self.get_pool_data_from_output_in_reward(reward_output, block.get_id())?;

                ensure!(
                    kernel_pool_data == reward_pool_data,
                    SpendStakeError::StakePoolDataMismatch
                );

                Ok(())
            }
        }
    }

    pub fn check_block_reward(
        &self,
        block: &WithId<Block>,
        total_fees: Fee,
        block_height: BlockHeight,
    ) -> Result<(), ConnectTransactionError> {
        input_output_policy::check_reward_inputs_outputs_policy(
            &block.block_reward_transactable(),
            &self.utxo_cache,
            block.get_id(),
        )?;

        self.check_stake_outputs_in_reward(block)?;

        let block_subsidy_at_height =
            Subsidy(self.chain_config.as_ref().block_subsidy_at_height(&block_height));
        check_transferred_amount_in_reward(
            &self.utxo_cache,
            &self.pos_accounting_adapter.accounting_delta(),
            &block.block_reward_transactable(),
            block.get_id(),
            block.consensus_data(),
            total_fees,
            block_subsidy_at_height,
        )
    }

    fn spend_input_from_account(
        &mut self,
        nonce: AccountNonce,
        account: AccountType,
    ) -> Result<(), ConnectTransactionError> {
        // Check that account nonce increments previous value
        let expected_nonce = match self
            .get_account_nonce_count(account)
            .map_err(|_| ConnectTransactionError::TxVerifierStorage)?
        {
            Some(nonce) => nonce
                .increment()
                .ok_or(ConnectTransactionError::FailedToIncrementAccountNonce)?,
            None => AccountNonce::new(0),
        };
        ensure!(
            expected_nonce == nonce,
            ConnectTransactionError::NonceIsNotIncremental(account, expected_nonce, nonce,)
        );
        // store new nonce
        self.account_nonce.insert(account, CachedOperation::Write(nonce));

        Ok(())
    }

    fn unspend_input_from_account(
        &mut self,
        account: AccountType,
    ) -> Result<(), ConnectTransactionError> {
        let new_nonce = self
            .get_account_nonce_count(account)
            .map_err(|_| ConnectTransactionError::TxVerifierStorage)?
            .ok_or(ConnectTransactionError::MissingTransactionNonce(account))?
            .decrement()
            .map_or(CachedOperation::Erase, CachedOperation::Write);
        self.account_nonce.insert(account, new_nonce);
        Ok(())
    }

    fn spend_input_from_utxo(
        &mut self,
        tx_source: TransactionSource,
        input_outpoint: &UtxoOutPoint,
    ) -> Result<Option<PoSAccountingUndo>, ConnectTransactionError> {
        let input_utxo =
            self.utxo_cache.utxo(input_outpoint).map_err(|_| utxo::Error::ViewRead)?.ok_or(
                ConnectTransactionError::MissingOutputOrSpent(input_outpoint.clone()),
            )?;
        match input_utxo.output() {
            TxOutput::CreateStakePool(pool_id, _) | TxOutput::ProduceBlockFromStake(_, pool_id) => {
                // If the input spends `CreateStakePool` or `ProduceBlockFromStake` utxo,
                // this means the user is decommissioning the pool.
                let undo = self
                    .pos_accounting_adapter
                    .operations(tx_source)
                    .decommission_pool(*pool_id)
                    .map_err(ConnectTransactionError::PoSAccountingError)?;
                Ok(Some(undo))
            }
            TxOutput::DelegateStaking(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::IssueFungibleToken(_)
            | TxOutput::IssueNft(_, _, _)
            | TxOutput::DataDeposit(_) => Ok(None),
        }
    }

    fn connect_pos_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // TODO: this should also collect all the delegations after the pool decommissioning;
        // see mintlayer/mintlayer-core/issues/909
        let mut check_for_delegation_cleanup: Option<DelegationId> = None;

        // Process tx inputs in terms of pos accounting.
        // Spending `CreateStakePool`, `ProduceBlockFromStake` utxos or an account input
        // should result in either decommissioning a pool or spending share in accounting
        let inputs_undos = tx
            .inputs()
            .iter()
            .filter_map(|input| match input {
                TxInput::Utxo(ref outpoint) => {
                    self.spend_input_from_utxo(tx_source, outpoint).transpose()
                }
                TxInput::Account(outpoint) => {
                    match outpoint.account() {
                        AccountSpending::DelegationBalance(delegation_id, withdraw_amount) => {
                            check_for_delegation_cleanup = Some(*delegation_id);
                            let res = self
                                .spend_input_from_account(
                                    outpoint.nonce(),
                                    outpoint.account().clone().into(),
                                )
                                .and_then(|_| {
                                    // If the input spends from delegation account, this means the user is
                                    // spending part of their share in the pool.
                                    self.pos_accounting_adapter
                                        .operations(tx_source)
                                        .spend_share_from_delegation_id(
                                            *delegation_id,
                                            *withdraw_amount,
                                        )
                                        .map_err(ConnectTransactionError::PoSAccountingError)
                                });
                            Some(res)
                        }
                    }
                }
                TxInput::AccountCommand(..) => None,
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Process tx outputs in terms of pos accounting.
        let input_utxo_outpoint = tx.inputs().iter().find_map(|input| input.utxo_outpoint());
        let outputs_undos = tx
            .outputs()
            .iter()
            .filter_map(|output| match output {
                TxOutput::CreateStakePool(pool_id, data) => match input_utxo_outpoint {
                    Some(input_utxo_outpoint) => {
                        let expected_pool_id = pos_accounting::make_pool_id(input_utxo_outpoint);
                        let res = if expected_pool_id == *pool_id {
                            if data.value() >= self.chain_config.as_ref().min_stake_pool_pledge() {
                                self.pos_accounting_adapter
                                    .operations(tx_source)
                                    .create_pool(*pool_id, data.as_ref().clone().into())
                                    .map_err(ConnectTransactionError::PoSAccountingError)
                            } else {
                                Err(ConnectTransactionError::NotEnoughPledgeToCreateStakePool(
                                    tx.get_id(),
                                    data.value(),
                                    self.chain_config.as_ref().min_stake_pool_pledge(),
                                ))
                            }
                        } else {
                            Err(ConnectTransactionError::UnexpectedPoolId(
                                *pool_id,
                                expected_pool_id,
                            ))
                        };
                        Some(res)
                    }
                    None => Some(Err(
                        ConnectTransactionError::AttemptToCreateStakePoolFromAccounts,
                    )),
                },
                TxOutput::CreateDelegationId(spend_destination, target_pool) => {
                    match input_utxo_outpoint {
                        Some(input_utxo_outpoint) => {
                            let res = self
                                .pos_accounting_adapter
                                .operations(tx_source)
                                .create_delegation_id(
                                    *target_pool,
                                    spend_destination.clone(),
                                    input_utxo_outpoint,
                                )
                                .map(|(_, undo)| undo)
                                .map_err(ConnectTransactionError::PoSAccountingError);
                            Some(res)
                        }
                        None => Some(Err(
                            ConnectTransactionError::AttemptToCreateDelegationFromAccounts,
                        )),
                    }
                }
                TxOutput::DelegateStaking(amount, delegation_id) => {
                    let res = self
                        .pos_accounting_adapter
                        .operations(tx_source)
                        .delegate_staking(*delegation_id, *amount)
                        .map_err(ConnectTransactionError::PoSAccountingError);
                    Some(res)
                }
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::Burn(_)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_) => None,
            })
            .collect::<Result<Vec<_>, _>>()?;

        // delete delegation if the balance is 0 and the pool has been decommissioned
        let delete_delegation_undo = match check_for_delegation_cleanup {
            Some(delegation_id) => {
                let accounting_view = self.pos_accounting_adapter.accounting_delta();
                let delegation_balance =
                    accounting_view.get_delegation_balance(delegation_id)?.ok_or(
                        ConnectTransactionError::DelegationDataNotFound(delegation_id),
                    )?;
                if delegation_balance == Amount::ZERO {
                    let delegation_data =
                        accounting_view.get_delegation_data(delegation_id)?.ok_or(
                            ConnectTransactionError::DelegationDataNotFound(delegation_id),
                        )?;
                    if !accounting_view.pool_exists(*delegation_data.source_pool())? {
                        // clear the nonce
                        self.account_nonce.insert(
                            AccountType::Delegation(delegation_id),
                            CachedOperation::Erase,
                        );

                        Some(
                            self.pos_accounting_adapter
                                .operations(tx_source)
                                .delete_delegation_id(delegation_id)?,
                        )
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            None => None,
        };

        // Store pos accounting operations undos
        if !inputs_undos.is_empty() || !outputs_undos.is_empty() || delete_delegation_undo.is_some()
        {
            let tx_undos = inputs_undos
                .into_iter()
                .chain(outputs_undos)
                .chain(delete_delegation_undo)
                .collect();
            self.pos_accounting_block_undo
                .get_or_create_block_undo(&tx_source)
                .insert_tx_undo(tx.get_id(), pos_accounting::AccountingTxUndo::new(tx_undos))
                .map_err(ConnectTransactionError::AccountingBlockUndoError)
        } else {
            Ok(())
        }
    }

    fn disconnect_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // decrement nonce if disconnected input spent from an account
        for input in tx.inputs() {
            match input {
                TxInput::Utxo(_) => { /* do nothing */ }
                TxInput::Account(outpoint) => {
                    self.unspend_input_from_account(outpoint.account().clone().into())?;
                }
                TxInput::AccountCommand(_, account_op) => {
                    self.unspend_input_from_account(account_op.clone().into())?;
                }
            };
        }

        self.disconnect_pos_accounting_outputs(tx_source, tx)?;

        self.disconnect_tokens_accounting_outputs(tx_source, tx)?;

        Ok(())
    }

    fn disconnect_pos_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // apply undos to accounting
        let block_undo_fetcher = |id: Id<Block>| {
            self.storage
                .get_accounting_undo(id)
                .map_err(|_| ConnectTransactionError::TxVerifierStorage)
        };
        let undos = self.pos_accounting_block_undo.take_tx_undo(
            &tx_source,
            &tx.get_id(),
            block_undo_fetcher,
        )?;
        if let Some(undos) = undos {
            undos.into_inner().into_iter().rev().try_for_each(|undo| {
                self.pos_accounting_adapter.operations(tx_source).undo(undo)
            })?;
        }

        Ok(())
    }

    fn connect_tokens_outputs(
        &mut self,
        tx_source: &TransactionSourceForConnect,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // Check if v0 tokens are allowed to be used at this height
        let latest_token_version = self
            .chain_config
            .as_ref()
            .chainstate_upgrades()
            .version_at_height(tx_source.expected_block_height())
            .1
            .token_issuance_version();

        match latest_token_version {
            TokenIssuanceVersion::V0 => {
                let was_token_issued_with_token_op =
                    get_issuance_count_via_tokens_op(tx.outputs()) > 0;
                ensure!(
                    !was_token_issued_with_token_op,
                    ConnectTransactionError::TokensError(
                        TokensError::UnsupportedTokenIssuanceVersion(
                            TokenIssuanceVersion::V1,
                            tx.get_id(),
                        ),
                    )
                );
            }
            TokenIssuanceVersion::V1 => {
                let has_tokens_v0_op = tx.outputs().iter().any(|output| match output {
                    TxOutput::Transfer(output_value, _)
                    | TxOutput::Burn(output_value)
                    | TxOutput::LockThenTransfer(output_value, _, _) => match output_value {
                        OutputValue::Coin(_) | OutputValue::TokenV1(_, _) => false,
                        OutputValue::TokenV0(_) => true,
                    },
                    TxOutput::CreateStakePool(_, _)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::IssueNft(_, _, _)
                    | TxOutput::DataDeposit(_) => false,
                });
                ensure!(
                    !has_tokens_v0_op,
                    ConnectTransactionError::TokensError(
                        TokensError::DeprecatedTokenOperationVersion(
                            TokenIssuanceVersion::V0,
                            tx.get_id(),
                        ),
                    )
                );
            }
        };

        self.check_operations_with_frozen_tokens(tx)?;

        let input_undos = tx
            .inputs()
            .iter()
            .filter_map(|input| match input {
                TxInput::Utxo(_) | TxInput::Account(_) => None,
                TxInput::AccountCommand(nonce, account_op) => match account_op {
                    AccountCommand::MintTokens(token_id, amount) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.clone().into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .mint_tokens(*token_id, *amount)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::UnmintTokens(ref token_id) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.clone().into())
                            .and_then(|_| {
                                // actual amount to unmint is determined by the number of burned tokens in the outputs
                                let total_burned =
                                    transferred_amount_check::calculate_tokens_burned_in_outputs(
                                        tx, token_id,
                                    )?;
                                Ok((total_burned > Amount::ZERO).then_some(total_burned))
                            })
                            .transpose()? // return if no tokens were burned
                            .and_then(|total_burned| {
                                self.tokens_accounting_cache
                                    .unmint_tokens(*token_id, total_burned)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::LockTokenSupply(token_id) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.clone().into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .lock_circulating_supply(*token_id)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::FreezeToken(token_id, is_unfreezable) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.clone().into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .freeze_token(*token_id, *is_unfreezable)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::UnfreezeToken(token_id) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.clone().into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .unfreeze_token(*token_id)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                    AccountCommand::ChangeTokenAuthority(token_id, new_authority) => {
                        let res = self
                            .spend_input_from_account(*nonce, account_op.clone().into())
                            .and_then(|_| {
                                self.tokens_accounting_cache
                                    .change_authority(*token_id, new_authority.clone())
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            });
                        Some(res)
                    }
                },
            })
            .collect::<Result<Vec<_>, _>>()?;

        let output_undos = tx
            .outputs()
            .iter()
            .filter_map(|output| match output {
                TxOutput::Transfer(_, _)
                | TxOutput::Burn(_)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_) => None,
                TxOutput::IssueFungibleToken(issuance_data) => {
                    let result = make_token_id(tx.inputs())
                        .ok_or(ConnectTransactionError::TokensError(
                            TokensError::TokenIdCantBeCalculated,
                        ))
                        .and_then(
                            |token_id| -> Result<tokens_accounting::TokenAccountingUndo, _> {
                                let data = tokens_accounting::TokenData::FungibleToken(
                                    issuance_data.as_ref().clone().into(),
                                );
                                self.tokens_accounting_cache
                                    .issue_token(token_id, data)
                                    .map_err(ConnectTransactionError::TokensAccountingError)
                            },
                        );
                    Some(result)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Store accounting operations undos
        if !input_undos.is_empty() || !output_undos.is_empty() {
            let tx_undos = input_undos.into_iter().chain(output_undos).collect();
            self.tokens_accounting_block_undo
                .get_or_create_block_undo(&tx_source.into())
                .insert_tx_undo(tx.get_id(), tokens_accounting::TxUndo::new(tx_undos))
                .map_err(ConnectTransactionError::TokensAccountingBlockUndoError)
        } else {
            Ok(())
        }
    }

    fn check_operations_with_frozen_tokens(
        &self,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        tx.outputs()
            .iter()
            .try_for_each(|output| -> Result<(), ConnectTransactionError> {
                match output {
                    TxOutput::Transfer(output_value, _)
                    | TxOutput::Burn(output_value)
                    | TxOutput::LockThenTransfer(output_value, _, _) => {
                        match output_value {
                            OutputValue::Coin(_) | OutputValue::TokenV0(_) => Ok(()),
                            OutputValue::TokenV1(ref token_id, _) => {
                                // TODO: when NFTs are stored in accounting None should become an error
                                if let Some(token_data) = self.get_token_data(token_id)? {
                                    match token_data {
                                        tokens_accounting::TokenData::FungibleToken(data) => {
                                            ensure!(
                                                !data.is_frozen(),
                                                ConnectTransactionError::AttemptToSpendFrozenToken(
                                                    *token_id
                                                )
                                            );
                                        }
                                    };
                                }
                                Ok(())
                            }
                        }
                    }
                    TxOutput::CreateStakePool(_, _)
                    | TxOutput::ProduceBlockFromStake(_, _)
                    | TxOutput::CreateDelegationId(_, _)
                    | TxOutput::DelegateStaking(_, _)
                    | TxOutput::IssueFungibleToken(_)
                    | TxOutput::IssueNft(_, _, _)
                    | TxOutput::DataDeposit(_) => Ok(()),
                }
            })
    }

    fn disconnect_tokens_accounting_outputs(
        &mut self,
        tx_source: TransactionSource,
        tx: &Transaction,
    ) -> Result<(), ConnectTransactionError> {
        // apply undos to accounting
        let block_undo_fetcher = |id: Id<Block>| {
            self.storage
                .get_tokens_accounting_undo(id)
                .map_err(|_| ConnectTransactionError::TxVerifierStorage)
        };
        let undos = self.tokens_accounting_block_undo.take_tx_undo(
            &tx_source,
            &tx.get_id(),
            block_undo_fetcher,
        )?;
        if let Some(undos) = undos {
            undos
                .into_inner()
                .into_iter()
                .rev()
                .try_for_each(|undo| self.tokens_accounting_cache.undo(undo))?;
        }

        Ok(())
    }

    pub fn connect_transaction(
        &mut self,
        tx_source: &TransactionSourceForConnect,
        tx: &SignedTransaction,
        median_time_past: &BlockTimestamp,
    ) -> Result<Fee, ConnectTransactionError> {
        let block_id = tx_source.chain_block_index().map(|c| *c.block_id());

        // Register tokens if tx has issuance data
        self.token_issuance_cache.register(block_id, tx.transaction(), |id| {
            self.storage
                .get_token_aux_data(id)
                .map_err(|_| ConnectTransactionError::TxVerifierStorage)
        })?;

        let issuance_token_id_getter =
            |tx_id: &Id<Transaction>| -> Result<Option<TokenId>, ConnectTransactionError> {
                // issuance transactions are unique, so we use them to get the token id
                self.get_token_id_from_issuance_tx(*tx_id)
                    .map_err(|_| ConnectTransactionError::TxVerifierStorage)
            };

        // check for attempted money printing and invalid inputs/outputs combinations
        let fee = input_output_policy::check_tx_inputs_outputs_policy(
            tx.transaction(),
            self.chain_config.as_ref(),
            tx_source.expected_block_height(),
            &self.pos_accounting_adapter.accounting_delta(),
            &self.utxo_cache,
            issuance_token_id_getter,
        )?;

        // check timelocks of the outputs and make sure there's no premature spending
        timelock_check::check_timelocks(
            &self.storage,
            &self.chain_config,
            &self.utxo_cache,
            tx,
            tx_source,
            median_time_past,
        )?;

        // verify input signatures
        signature_check::verify_signatures(
            self.chain_config.as_ref(),
            &self.utxo_cache,
            tx,
            SignatureDestinationGetter::new_for_transaction(
                &self.tokens_accounting_cache,
                &self.pos_accounting_adapter.accounting_delta(),
                &self.utxo_cache,
            ),
        )?;

        self.connect_pos_accounting_outputs(tx_source.into(), tx.transaction())?;

        self.connect_tokens_outputs(tx_source, tx.transaction())?;

        // spend utxos
        let tx_undo = self
            .utxo_cache
            .connect_transaction(tx.transaction(), tx_source.to_utxo_source())
            .map_err(ConnectTransactionError::from)?;

        // save spent utxos for undo
        self.utxo_block_undo
            .get_or_create_block_undo(&TransactionSource::from(tx_source))
            .insert_tx_undo(tx.transaction().get_id(), tx_undo)?;

        Ok(fee)
    }

    pub fn connect_block_reward(
        &mut self,
        block_index: &BlockIndex,
        reward_transactable: BlockRewardTransactable,
        total_fees: Fee,
    ) -> Result<(), ConnectTransactionError> {
        // TODO: test spending block rewards from chains outside the mainchain
        if let Some(_inputs) = reward_transactable.inputs() {
            // verify input signatures
            signature_check::verify_signatures(
                self.chain_config.as_ref(),
                &self.utxo_cache,
                &reward_transactable,
                SignatureDestinationGetter::new_for_block_reward(&self.utxo_cache),
            )?;
        }

        let block_id = *block_index.block_id();

        // spend inputs of the block reward
        // if block reward has no inputs then only outputs will be added to the utxo set
        let reward_undo = self
            .utxo_cache
            .connect_block_transactable(
                &reward_transactable,
                &block_id.into(),
                block_index.block_height(),
            )
            .map_err(ConnectTransactionError::from)?;

        if let Some(reward_undo) = reward_undo {
            // save spent utxos for undo
            self.utxo_block_undo
                .get_or_create_block_undo(&TransactionSource::Chain(block_id))
                .set_block_reward_undo(reward_undo);
        }

        match block_index.block_header().consensus_data() {
            ConsensusData::None | ConsensusData::PoW(_) => { /* do nothing */ }
            ConsensusData::PoS(pos_data) => {
                // distribute reward among staker and delegators
                let block_subsidy =
                    self.chain_config.as_ref().block_subsidy_at_height(&block_index.block_height());
                let total_reward = (block_subsidy + total_fees.0)
                    .ok_or(ConnectTransactionError::RewardAdditionError(block_id))?;

                let undos = reward_distribution::distribute_pos_reward(
                    &mut self.pos_accounting_adapter,
                    block_id,
                    *pos_data.stake_pool_id(),
                    total_reward,
                )?;

                self.pos_accounting_block_undo
                    .get_or_create_block_undo(&TransactionSource::Chain(block_id))
                    .set_reward_undo(undos);
            }
        };

        Ok(())
    }

    pub fn can_disconnect_transaction(
        &self,
        tx_source: &TransactionSource,
        tx_id: &Id<Transaction>,
    ) -> Result<bool, ConnectTransactionError> {
        let block_undo_fetcher = |id: Id<Block>| {
            self.storage
                .get_undo_data(id)
                .map_err(|_| ConnectTransactionError::UndoFetchFailure)
        };
        match tx_source {
            TransactionSource::Chain(block_id) => {
                let current_block_height = self
                    .storage
                    .get_gen_block_index(&(*block_id).into())?
                    .ok_or_else(|| {
                        ConnectTransactionError::BlockIndexCouldNotBeLoaded((*block_id).into())
                    })?
                    .block_height();
                let best_block_height = self
                    .storage
                    .get_gen_block_index(&self.best_block)?
                    .ok_or(ConnectTransactionError::BlockIndexCouldNotBeLoaded(
                        self.best_block,
                    ))?
                    .block_height();

                if current_block_height < best_block_height {
                    Ok(false)
                } else {
                    Ok(!self
                        .utxo_block_undo
                        .read_block_undo(tx_source, block_undo_fetcher)?
                        .has_children_of(tx_id))
                }
            }
            TransactionSource::Mempool => Ok(!self
                .utxo_block_undo
                .read_block_undo(tx_source, block_undo_fetcher)?
                .has_children_of(tx_id)),
        }
    }

    pub fn disconnect_transaction(
        &mut self,
        tx_source: &TransactionSource,
        tx: &SignedTransaction,
    ) -> Result<(), ConnectTransactionError> {
        let block_undo_fetcher = |id: Id<Block>| {
            self.storage
                .get_undo_data(id)
                .map_err(|_| ConnectTransactionError::UndoFetchFailure)
        };
        let tx_undo = self.utxo_block_undo.take_tx_undo(
            tx_source,
            &tx.transaction().get_id(),
            block_undo_fetcher,
        )?;

        self.disconnect_accounting_outputs(*tx_source, tx.transaction())?;

        self.utxo_cache.disconnect_transaction(tx.transaction(), tx_undo)?;

        // Remove issued tokens v0
        self.token_issuance_cache.unregister(tx.transaction(), |id| {
            self.storage
                .get_token_aux_data(id)
                .map_err(|_| ConnectTransactionError::TxVerifierStorage)
        })?;

        Ok(())
    }

    pub fn disconnect_block_reward(
        &mut self,
        block: &WithId<Block>,
    ) -> Result<(), ConnectTransactionError> {
        let reward_transactable = block.block_reward_transactable();
        let tx_source = TransactionSource::Chain(block.get_id());

        let block_undo_fetcher = |id: Id<Block>| {
            self.storage
                .get_undo_data(id)
                .map_err(|_| ConnectTransactionError::UndoFetchFailure)
        };
        let reward_undo =
            self.utxo_block_undo.take_block_reward_undo(&tx_source, block_undo_fetcher)?;
        self.utxo_cache.disconnect_block_transactable(
            &reward_transactable,
            &block.get_id().into(),
            reward_undo,
        )?;

        match block.header().consensus_data() {
            ConsensusData::None | ConsensusData::PoW(_) => { /*do nothing*/ }
            ConsensusData::PoS(_) => {
                let block_undo_fetcher = |id: Id<Block>| {
                    self.storage
                        .get_accounting_undo(id)
                        .map_err(|_| ConnectTransactionError::TxVerifierStorage)
                };
                let reward_undo = self.pos_accounting_block_undo.take_block_reward_undo(
                    &TransactionSource::Chain(block.get_id()),
                    block_undo_fetcher,
                )?;
                if let Some(reward_undo) = reward_undo {
                    reward_undo.into_inner().into_iter().try_for_each(|undo| {
                        self.pos_accounting_adapter.operations(tx_source).undo(undo)
                    })?;
                }
            }
        }

        Ok(())
    }

    pub fn set_best_block(&mut self, id: Id<GenBlock>) {
        self.utxo_cache.set_best_block(id);
    }

    pub fn consume(self) -> Result<TransactionVerifierDelta, ConnectTransactionError> {
        let (accounting_delta, accounting_block_deltas) = self.pos_accounting_adapter.consume();
        Ok(TransactionVerifierDelta {
            utxo_cache: self.utxo_cache.consume(),
            utxo_block_undo: self.utxo_block_undo.consume(),
            token_issuance_cache: self.token_issuance_cache.consume(),
            accounting_delta,
            pos_accounting_delta_undo: self.pos_accounting_block_undo.consume(),
            pos_accounting_block_deltas: accounting_block_deltas,
            account_nonce: self.account_nonce,
            tokens_accounting_delta: self.tokens_accounting_cache.consume(),
            tokens_accounting_delta_undo: self.tokens_accounting_block_undo.consume(),
        })
    }
}

#[cfg(test)]
mod tests;

// TODO: write tests for block rewards
// TODO: test that total_block_reward = total_tx_fees + consensus_block_reward
