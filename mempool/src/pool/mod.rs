// Copyright (c) 2022-2023 RBB S.r.l
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

use parking_lot::RwLock;
use std::{
    collections::{BTreeMap, BTreeSet},
    mem,
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};
use utxo::UtxosStorageRead;

use chainstate::{
    chainstate_interface::ChainstateInterface,
    tx_verifier::{
        transaction_verifier::{TransactionSourceForConnect, TransactionVerifierDelta},
        TransactionSource,
    },
};
use common::{
    chain::{
        block::timestamp::BlockTimestamp, Block, ChainConfig, GenBlock, SignedTransaction,
        Transaction, TxInput,
    },
    primitives::{amount::Amount, decimal_amount::DisplayAmount, time::Time, BlockHeight, Id},
    time_getter::TimeGetter,
};
use logging::log;
use serialization::Encode;
use utils::{ensure, eventhandler::EventsController, shallow_clone::ShallowClone};

pub use self::feerate::FeeRate;
pub use self::memory_usage_estimator::MemoryUsageEstimator;
use self::{
    entry::{TxDependency, TxEntry, TxEntryWithFee},
    fee::Fee,
    feerate::{INCREMENTAL_RELAY_FEE_RATE, INCREMENTAL_RELAY_THRESHOLD},
    orphans::{OrphanType, TxOrphanPool},
    rolling_fee_rate::RollingFeeRate,
    store::{Conflicts, DescendantScore, MempoolRemovalReason, MempoolStore, TxMempoolEntry},
};
use crate::{
    config,
    error::{
        BlockConstructionError, Error, MempoolConflictError, MempoolPolicyError, OrphanPoolError,
        TxValidationError,
    },
    event::{self, MempoolEvent},
    tx_accumulator::{PackingStrategy, TransactionAccumulator},
    tx_options::{TxOptions, TxTrustPolicy},
    tx_origin::{RemoteTxOrigin, TxOrigin},
    TxStatus,
};

use crate::config::*;

mod collect_txs;
mod entry;
pub mod fee;
mod feerate;
pub mod feerate_points;
pub mod memory_usage_estimator;
mod orphans;
mod reorg;
mod rolling_fee_rate;
mod store;
mod tx_verifier;
mod work_queue;

pub type WorkQueue = work_queue::WorkQueue<Id<Transaction>>;

pub struct Mempool<M> {
    chain_config: Arc<ChainConfig>,
    mempool_config: Arc<MempoolConfig>,
    store: MempoolStore,
    rolling_fee_rate: RwLock<RollingFeeRate>,
    max_size: MempoolMaxSize,
    max_tx_age: Duration,
    chainstate_handle: chainstate::ChainstateHandle,
    clock: TimeGetter,
    memory_usage_estimator: M,
    events_controller: EventsController<MempoolEvent>,
    tx_verifier: tx_verifier::TransactionVerifier,
    orphans: TxOrphanPool,
}

impl<M> std::fmt::Debug for Mempool<M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.store.fmt(f)
    }
}

impl<M> Mempool<M> {
    pub fn new(
        chain_config: Arc<ChainConfig>,
        mempool_config: Arc<MempoolConfig>,
        chainstate_handle: chainstate::ChainstateHandle,
        clock: TimeGetter,
        memory_usage_estimator: M,
    ) -> Self {
        log::trace!("Setting up mempool transaction verifier");
        let tx_verifier = tx_verifier::create(
            chain_config.shallow_clone(),
            chainstate_handle.shallow_clone(),
        );

        log::trace!("Creating mempool object");
        Self {
            chain_config,
            mempool_config,
            store: MempoolStore::new(),
            chainstate_handle,
            max_size: MempoolMaxSize::default(),
            max_tx_age: DEFAULT_MEMPOOL_EXPIRY,
            rolling_fee_rate: RwLock::new(RollingFeeRate::new(clock.get_time())),
            clock,
            memory_usage_estimator,
            events_controller: Default::default(),
            tx_verifier,
            orphans: TxOrphanPool::new(),
        }
    }

    pub fn chainstate_handle(&self) -> &chainstate::ChainstateHandle {
        &self.chainstate_handle
    }

    pub fn blocking_chainstate_handle(
        &self,
    ) -> subsystem::blocking::BlockingHandle<dyn ChainstateInterface> {
        subsystem::blocking::BlockingHandle::new(self.chainstate_handle().shallow_clone())
    }

    // Reset the mempool state, returning the list of transactions previously stored in mempool
    fn reset(&mut self) -> impl Iterator<Item = TxEntry> {
        // Discard the old tx verifier and replace it with a fresh one
        self.tx_verifier = tx_verifier::create(
            self.chain_config.shallow_clone(),
            self.chainstate_handle.shallow_clone(),
        );

        // Clear the store, returning the list of transactions it contained previously
        let pool_txs = mem::replace(&mut self.store, MempoolStore::new()).into_transactions();

        // Clear the orphan pool, returning the list of previous transactions.
        let orphan_txs = mem::replace(&mut self.orphans, TxOrphanPool::new()).into_transactions();

        pool_txs.chain(orphan_txs.map(|entry| entry.map_origin(TxOrigin::from)))
    }

    pub fn best_block_id(&self) -> Id<GenBlock> {
        utxo::UtxosStorageRead::get_best_block_for_utxos(&self.tx_verifier)
            .expect("best block to exist")
    }

    pub fn max_size(&self) -> MempoolMaxSize {
        self.max_size
    }
}

// Rolling-fee-related methods
impl<M: MemoryUsageEstimator> Mempool<M> {
    pub fn memory_usage(&self) -> usize {
        self.memory_usage_estimator.estimate_memory_usage(&self.store)
    }

    fn rolling_fee_halflife(&self) -> Duration {
        let mem_usage = self.memory_usage();
        if mem_usage < self.max_size.as_bytes() / 4 {
            ROLLING_FEE_BASE_HALFLIFE / 4
        } else if mem_usage < self.max_size.as_bytes() / 2 {
            ROLLING_FEE_BASE_HALFLIFE / 2
        } else {
            ROLLING_FEE_BASE_HALFLIFE
        }
    }

    fn update_min_fee_rate(&self, rate: FeeRate) {
        let mut rolling_fee_rate = self.rolling_fee_rate.write();
        (*rolling_fee_rate).set_rolling_minimum_fee_rate(rate);
        rolling_fee_rate.set_block_since_last_rolling_fee_bump(false);
    }

    fn get_update_min_fee_rate(&self) -> FeeRate {
        log::debug!("get_update_min_fee_rate");
        let rolling_fee_rate = *self.rolling_fee_rate.read();
        if !rolling_fee_rate.block_since_last_rolling_fee_bump()
            || rolling_fee_rate.rolling_minimum_fee_rate()
                == FeeRate::from_amount_per_kb(Amount::from_atoms(0))
        {
            return rolling_fee_rate.rolling_minimum_fee_rate();
        } else if self.clock.get_time()
            > (rolling_fee_rate.last_rolling_fee_update() + ROLLING_FEE_DECAY_INTERVAL)
                .expect("Both times come from the same clock, so this cannot happen")
        {
            // Decay the rolling fee
            self.decay_rolling_fee_rate();
            log::debug!(
                "rolling fee rate after decay_rolling_fee_rate {:?}",
                self.rolling_fee_rate,
            );

            if self.rolling_fee_rate.read().rolling_minimum_fee_rate() < INCREMENTAL_RELAY_THRESHOLD
            {
                log::trace!(
                    "rolling fee rate {:?} less than half of the incremental fee rate, dropping the fee",
                    self.rolling_fee_rate.read().rolling_minimum_fee_rate(),
                );
                self.drop_rolling_fee();
                return self.rolling_fee_rate.read().rolling_minimum_fee_rate();
            }
        }

        std::cmp::max(
            self.rolling_fee_rate.read().rolling_minimum_fee_rate(),
            INCREMENTAL_RELAY_FEE_RATE,
        )
    }

    fn drop_rolling_fee(&self) {
        let mut rolling_fee_rate = self.rolling_fee_rate.write();
        (*rolling_fee_rate)
            .set_rolling_minimum_fee_rate(FeeRate::from_amount_per_kb(Amount::from_atoms(0)));
    }

    fn decay_rolling_fee_rate(&self) {
        let halflife = self.rolling_fee_halflife();
        let time = self.clock.get_time();
        let mut rolling_fee_rate = self.rolling_fee_rate.write();
        *rolling_fee_rate = (*rolling_fee_rate).decay_fee(halflife, time);
    }
}

// Entry Creation
impl<M> Mempool<M> {
    pub fn contains_transaction(&self, tx_id: &Id<Transaction>) -> bool {
        self.store.contains(tx_id)
    }

    pub fn transaction(&self, id: &Id<Transaction>) -> Option<&SignedTransaction> {
        self.store.get_entry(id).map(TxMempoolEntry::transaction)
    }

    pub fn contains_orphan_transaction(&self, id: &Id<Transaction>) -> bool {
        self.orphans.contains(id)
    }

    pub fn orphan_transaction(&self, id: &Id<Transaction>) -> Option<&SignedTransaction> {
        self.orphans.get(id).map(TxEntry::transaction)
    }
}

/// Result of transaction validation
enum ValidationOutcome {
    /// Transaction is valid for acceptance to mempool
    Valid {
        transaction: TxEntryWithFee,
        conflicts: Conflicts,
        delta: TransactionVerifierDelta,
    },

    /// Transaction is valid of acceptance to orphan pool.
    /// It may or may not end up being valid, depending on the validity of the missing inputs.
    Orphan {
        transaction: TxEntry<RemoteTxOrigin>,
    },
}

/// Result of transaction validation
enum VerificationOutcome {
    /// Transaction is valid for acceptance to mempool
    Valid {
        transaction: TxEntryWithFee,
        delta: TransactionVerifierDelta,
    },

    /// Transaction is valid of acceptance to orphan pool.
    /// It may or may not end up being valid, depending on the validity of the missing inputs.
    Orphan {
        transaction: TxEntry,
        orphan_type: OrphanType,
    },
}

// Transaction Validation
impl<M: MemoryUsageEstimator> Mempool<M> {
    /// Verify transaction according to consensus rules and check mempool rules
    fn validate_transaction(&self, transaction: TxEntry) -> Result<ValidationOutcome, Error> {
        // This validation function is based on Bitcoin Core's MemPoolAccept::PreChecks.
        // However, as of this stage it does not cover everything covered in Bitcoin Core
        //
        // Currently, the items we want covered which are NOT yet covered are:
        //
        // - Checking if a transaction is "standard" (see `IsStandardTx`, `AreInputsStandard` in Bitcoin Core). We have yet to decide on Mintlayer's
        // definition of "standard"
        //
        // - Bitcoin Core does not relay transactions smaller than 82 bytes (see
        // MIN_STANDARD_TX_NONWITNESS_SIZE in Bitcoin Core's policy.h)
        //
        // - Checking the signature operations cost (Bitcoin Core: `GetTransactionSigOpCost`)
        //
        // - We have yet to understand and implement this comment pertaining to chain limits and
        // calculation of in-mempool ancestors:
        // https://github.com/bitcoin/bitcoin/blob/7c08d81e119570792648fe95bbacddbb1d5f9ae2/src/validation.cpp#L829
        //
        // - Bitcoin Core's `EntriesAndTxidsDisjoint` check
        //
        // - Bitcoin Core's `PolicyScriptChecks`
        //
        // - Bitcoin Core's `ConsensusScriptChecks`

        // Deviations from Bitcoin Core
        //
        // - In our FeeRate calculations, we use the `encoded_size`of a transaction. In contrast,
        // see Bitcoin Core's `CTxMemPoolEntry::GetTxSize()`, which takes into account sigops cost
        // and witness data. This deviation is not intentional, but rather the result of wanting to
        // get a basic implementation working. TODO: weigh what notion of size/weight we wish to
        // use and whether to follow Bitcoin Core in this regard
        //
        // We don't have a notion of MAX_MONEY like Bitcoin Core does, so we also don't have a
        // `MoneyRange` check like the one found in Bitcoin Core's `CheckTransaction`

        self.check_preliminary_mempool_policy(&transaction)?;

        let outcome = match self.verify_transaction(transaction)? {
            VerificationOutcome::Valid { transaction, delta } => {
                let conflicts = self.check_mempool_policy(&transaction)?;
                ValidationOutcome::Valid {
                    transaction,
                    conflicts,
                    delta,
                }
            }
            VerificationOutcome::Orphan {
                transaction,
                orphan_type,
            } => {
                let transaction = self.check_orphan_pool_policy(transaction, orphan_type)?;
                ValidationOutcome::Orphan { transaction }
            }
        };

        Ok(outcome)
    }

    /// Verify transaction according to consensus rules
    fn verify_transaction(
        &self,
        transaction: TxEntry,
    ) -> Result<VerificationOutcome, TxValidationError> {
        let chainstate_handle = self.blocking_chainstate_handle();

        let is_ibd = chainstate_handle.call(|chainstate| chainstate.is_initial_block_download())?;
        ensure!(!is_ibd, TxValidationError::AddedDuringIBD);

        for attempt_idx in 0..MAX_TX_ADDITION_ATTEMPTS {
            let (tip, current_best) = chainstate_handle.call(|chainstate| {
                let tip = chainstate.get_best_block_id()?;
                let tip_index =
                    chainstate.get_gen_block_index(&tip)?.expect("tip block index to exist");
                Ok::<_, chainstate::ChainstateError>((tip, tip_index))
            })??;

            let mut tx_verifier = self.tx_verifier.derive_child();

            log::trace!(
                "Verifying tx {:?}, attempt #{}, tip = {:?}, tx_verifier's best block for utxos = {:?}",
                transaction.tx_id(),
                attempt_idx,
                tip,
                tx_verifier.get_best_block_for_utxos()?
            );

            let verifier_time =
                self.clock.get_time().saturating_duration_add(config::FUTURE_TIMELOCK_TOLERANCE);
            let effective_height = (current_best.block_height()
                + config::FUTURE_TIMELOCK_TOLERANCE_BLOCKS)
                .expect("Block height overflow");

            let res = tx_verifier.connect_transaction(
                &TransactionSourceForConnect::for_mempool_with_height(
                    &current_best,
                    effective_height,
                ),
                transaction.transaction(),
                &BlockTimestamp::from_time(verifier_time),
            );

            let cur_tip = chainstate_handle.call(|c| c.get_best_block_id())??;
            if tip != cur_tip {
                log::debug!(
                    "Tip has changed from {tip:?} to {cur_tip:?} when verifying tx {:?}",
                    transaction.tx_id()
                );
                continue;
            }

            let result = match res {
                Ok(fee) => {
                    let fee = fee
                        .map_into_block_fees(
                            self.chain_config.as_ref(),
                            current_best.block_height(),
                        )
                        .map_err(|e| {
                            TxValidationError::TxValidation(
                                chainstate::ConnectTransactionError::ConstrainedValueAccumulatorError(
                                    e,
                                    (*transaction.tx_id()).into(),
                                ),
                            )
                        })?;
                    let transaction = TxEntryWithFee::new(transaction, fee.into());
                    let delta = tx_verifier.consume()?;
                    VerificationOutcome::Valid { transaction, delta }
                }
                Err(err) => {
                    let orphan_type = OrphanType::from_error(&err).ok_or(err)?;
                    VerificationOutcome::Orphan {
                        transaction,
                        orphan_type,
                    }
                }
            };

            return Ok(result);
        }

        Err(TxValidationError::TipMoved)
    }

    // Cheap mempool policy checks that run before anything else
    fn check_preliminary_mempool_policy(&self, entry: &TxEntry) -> Result<(), MempoolPolicyError> {
        let tx = entry.transaction();

        ensure!(
            !tx.transaction().inputs().is_empty(),
            MempoolPolicyError::NoInputs,
        );

        ensure!(
            !tx.transaction().outputs().is_empty(),
            MempoolPolicyError::NoOutputs,
        );

        ensure!(
            entry.size().get() <= self.chain_config.max_tx_size_for_mempool(),
            MempoolPolicyError::ExceedsMaxBlockSize,
        );

        Ok(())
    }

    // Check the transaction against the mempool inclusion policy
    fn check_mempool_policy(
        &self,
        entry: &TxEntryWithFee,
    ) -> Result<Conflicts, MempoolPolicyError> {
        self.pays_minimum_relay_fees(entry)?;
        self.pays_minimum_mempool_fee(entry)?;

        if ENABLE_RBF {
            self.rbf_checks(entry)
        } else {
            // Without RBF enabled, any conflicting transaction results in an error
            ensure!(
                self.conflicting_tx_ids(entry.tx_entry()).next().is_none(),
                MempoolConflictError::Irreplacable
            );
            Ok(Conflicts::new(BTreeSet::new()))
        }
    }

    fn check_orphan_pool_policy(
        &self,
        transaction: TxEntry,
        orphan_type: OrphanType,
    ) -> Result<TxEntry<RemoteTxOrigin>, OrphanPoolError> {
        // Only remote transactions are allowed in the orphan pool
        let transaction = transaction
            .try_map_origin(|origin| match origin {
                TxOrigin::Local(o) => Err(OrphanPoolError::NotSupportedForLocalOrigin(o)),
                TxOrigin::Remote(o) => Ok(o),
            })
            .map_err(|(_, e)| e)?;

        // Avoid too large transactions in orphan pool. The orphan pool is limited by the number of
        // transactions but we don't want it to take up too much space due to large txns either.
        let size: usize = transaction.size().into();
        ensure!(
            size <= config::MAX_ORPHAN_TX_SIZE,
            OrphanPoolError::TooLarge(size, config::MAX_ORPHAN_TX_SIZE),
        );

        // Account nonces are supposed to be consecutive. If the distance between the expected and
        // given nonce is too large, the transaction is not accepted into the orphan pool.
        if let OrphanType::AccountNonceGap(gap) = orphan_type {
            ensure!(
                gap <= config::MAX_ORPHAN_ACCOUNT_GAP,
                OrphanPoolError::NonceGapTooLarge(gap),
            );
        }

        self.orphan_rbf_checks(&transaction)?;

        Ok(transaction)
    }

    fn pays_minimum_mempool_fee(&self, tx: &TxEntryWithFee) -> Result<(), MempoolPolicyError> {
        let decimals = self.chain_config.coin_decimals();
        let tx_fee = tx.fee();
        let minimum_fee = self.get_update_minimum_mempool_fee(tx.transaction())?;
        log::debug!("pays_minimum_mempool_fee tx_fee = {tx_fee:?}, minimum_fee = {minimum_fee:?}");
        ensure!(
            tx_fee >= minimum_fee,
            MempoolPolicyError::RollingFeeThresholdNotMet {
                minimum_fee: DisplayAmount::from_amount_full(minimum_fee.into(), decimals),
                tx_fee: DisplayAmount::from_amount_full(tx_fee.into(), decimals),
            }
        );
        Ok(())
    }

    fn get_update_minimum_mempool_fee(
        &self,
        tx: &SignedTransaction,
    ) -> Result<Fee, MempoolPolicyError> {
        let minimum_fee_rate = self.get_update_min_fee_rate();
        log::debug!("minimum fee rate {:?}", minimum_fee_rate);
        let res = minimum_fee_rate.compute_fee(tx.encoded_size());
        log::debug!("minimum_mempool_fee for tx: {:?}", res);
        res
    }

    fn get_minimum_relay_fee(&self, tx: &SignedTransaction) -> Result<Fee, MempoolPolicyError> {
        self.mempool_config.min_tx_relay_fee_rate.compute_fee(tx.encoded_size())
    }

    fn pays_minimum_relay_fees(&self, tx: &TxEntryWithFee) -> Result<(), MempoolPolicyError> {
        let decimals = self.chain_config.coin_decimals();
        let tx_fee = tx.fee();
        let min_relay_fee = self.get_minimum_relay_fee(tx.transaction())?;
        log::debug!("tx_fee: {:?}, min_relay_fee: {:?}", tx_fee, min_relay_fee);
        ensure!(
            tx_fee >= min_relay_fee,
            MempoolPolicyError::InsufficientFeesToRelay {
                tx_fee: DisplayAmount::from_amount_full(tx_fee.into(), decimals),
                min_relay_fee: DisplayAmount::from_amount_full(min_relay_fee.into(), decimals),
            }
        );
        Ok(())
    }

    fn conflicting_tx_ids<'a, O: crate::tx_origin::IsOrigin>(
        &'a self,
        entry: &'a TxEntry<O>,
    ) -> impl 'a + Iterator<Item = &'a Id<Transaction>> {
        entry.requires().filter_map(|dep| self.store.find_conflicting_tx(&dep))
    }

    fn spends_unconfirmed(&self, input: &TxInput) -> bool {
        // TODO: if TxInput spends from an account there is no way to know tx_id
        match input {
            TxInput::Utxo(outpoint) => outpoint
                .source_id()
                .get_tx_id()
                .map_or(false, |tx_id| self.contains_transaction(tx_id)),
            TxInput::Account(..) | TxInput::AccountCommand(..) => false,
        }
    }
}

// RBF checks
impl<M: MemoryUsageEstimator> Mempool<M> {
    fn rbf_checks(&self, tx: &TxEntryWithFee) -> Result<Conflicts, MempoolPolicyError> {
        let conflicts = self
            .conflicting_tx_ids(tx.tx_entry())
            .map(|id_conflict| self.store.get_entry(id_conflict).expect("entry for id"))
            .collect::<Vec<_>>();

        if conflicts.is_empty() {
            Ok(BTreeSet::new().into())
        } else {
            self.do_rbf_checks(tx, &conflicts)
        }
    }

    fn orphan_rbf_checks<O: crate::tx_origin::IsOrigin>(
        &self,
        tx: &TxEntry<O>,
    ) -> Result<(), OrphanPoolError> {
        let mut conflicts = self.conflicting_tx_ids(tx).peekable();
        if conflicts.peek().is_none() {
            // Early exit if there are no conflicts
            return Ok(());
        }

        if ENABLE_RBF {
            // Note: Since RBF is currently disabled, the following is effectively dead code and
            // completely untested. Needs to be reviewed when RBF is re-enabled.
            let conflicts: Vec<_> = conflicts
                .map(|id_conflict| self.store.get_entry(id_conflict).expect("entry for id"))
                .collect();
            self.all_conflicts_replaceable(&conflicts)?;
            self.spends_no_new_unconfirmed_outputs(tx, &conflicts)?;
            self.potential_replacements_within_limit(&conflicts)?;
            Ok(())
        } else {
            Err(OrphanPoolError::MempoolConflict)
        }
    }

    fn do_rbf_checks(
        &self,
        tx: &TxEntryWithFee,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<Conflicts, MempoolPolicyError> {
        // Enforce BIP125 Rule #1.
        self.all_conflicts_replaceable(conflicts)?;
        // It's possible that the replacement pays more fees than its direct conflicts but not more
        // than all conflicts (i.e. the direct conflicts have high-fee descendants). However, if the
        // replacement doesn't pay more fees than its direct conflicts, then we can be sure it's not
        // more economically rational to mine. Before we go digging through the mempool for all
        // transactions that would need to be removed (direct conflicts and all descendants), check
        // that the replacement transaction pays more than its direct conflicts.
        self.pays_more_than_direct_conflicts(tx, conflicts)?;
        // Enforce BIP125 Rule #2.
        self.spends_no_new_unconfirmed_outputs(tx.tx_entry(), conflicts)?;
        // Enforce BIP125 Rule #5.
        self.potential_replacements_within_limit(conflicts)?;
        // Enforce BIP125 Rule #3.
        let conflicts_with_descendants = self.replacements_with_descendants(conflicts);
        let total_conflict_fees =
            self.pays_more_than_conflicts_with_descendants(tx, &conflicts_with_descendants)?;
        // Enforce BIP125 Rule #4.
        self.pays_for_bandwidth(tx, total_conflict_fees)?;
        Ok(Conflicts::from(conflicts_with_descendants))
    }

    fn all_conflicts_replaceable(
        &self,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), MempoolConflictError> {
        ensure!(
            conflicts.iter().all(|entry| entry.is_replaceable(&self.store)),
            MempoolConflictError::Irreplacable,
        );
        Ok(())
    }

    fn pays_for_bandwidth(
        &self,
        tx: &TxEntryWithFee,
        total_conflict_fees: Fee,
    ) -> Result<(), MempoolPolicyError> {
        log::debug!("pays_for_bandwidth: tx fee is {:?}", tx.fee());
        let additional_fees =
            (tx.fee() - total_conflict_fees).ok_or(MempoolPolicyError::AdditionalFeesUnderflow)?;
        let min_relay_fee = self.get_minimum_relay_fee(tx.transaction())?;
        log::debug!(
            "conflict fees: {:?}, additional fee: {:?}, min relay fee {:?}",
            total_conflict_fees,
            additional_fees,
            min_relay_fee
        );
        ensure!(
            additional_fees >= min_relay_fee,
            MempoolPolicyError::InsufficientFeesToRelayRBF
        );
        Ok(())
    }

    fn pays_more_than_conflicts_with_descendants(
        &self,
        tx: &TxEntryWithFee,
        conflicts_with_descendants: &BTreeSet<Id<Transaction>>,
    ) -> Result<Fee, MempoolPolicyError> {
        let conflicts_with_descendants = conflicts_with_descendants.iter().map(|conflict_id| {
            self.store.txs_by_id.get(conflict_id).expect("tx should exist in mempool")
        });

        let total_conflict_fees = conflicts_with_descendants
            .map(|conflict| conflict.fee())
            .sum::<Option<Fee>>()
            .ok_or(MempoolPolicyError::ConflictsFeeOverflow)?;

        let replacement_fee = tx.fee();
        ensure!(
            replacement_fee > total_conflict_fees,
            MempoolPolicyError::TransactionFeeLowerThanConflictsWithDescendants
        );
        Ok(total_conflict_fees)
    }

    fn spends_no_new_unconfirmed_outputs<O: crate::tx_origin::IsOrigin>(
        &self,
        tx: &TxEntry<O>,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), MempoolConflictError> {
        let inputs_spent_by_conflicts = conflicts
            .iter()
            .flat_map(|conflict| conflict.transaction().inputs().iter())
            .collect::<BTreeSet<_>>();

        let spends_new_unconfirmed = tx.transaction().inputs().iter().any(|input| {
            // input spends an unconfirmed output
            let unconfirmed = self.spends_unconfirmed(input);
            // this unconfirmed output is not spent by one of the conflicts
            let new = !inputs_spent_by_conflicts.contains(input);
            unconfirmed && new
        });
        ensure!(
            spends_new_unconfirmed,
            MempoolConflictError::SpendsNewUnconfirmed,
        );
        Ok(())
    }

    fn pays_more_than_direct_conflicts(
        &self,
        tx: &TxEntryWithFee,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), MempoolPolicyError> {
        let replacement_fee = tx.fee();
        conflicts.iter().find(|conflict| conflict.fee() >= replacement_fee).map_or_else(
            || Ok(()),
            |conflict| {
                Err(MempoolPolicyError::ReplacementFeeLowerThanOriginal {
                    replacement_tx: tx.tx_id().to_hash(),
                    replacement_fee,
                    original_fee: conflict.fee(),
                    original_tx: conflict.tx_id().to_hash(),
                })
            },
        )
    }

    fn potential_replacements_within_limit(
        &self,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), MempoolConflictError> {
        let mut num_potential_replacements = 0;
        for conflict in conflicts {
            num_potential_replacements += conflict.count_with_descendants();
            ensure!(
                num_potential_replacements <= MAX_BIP125_REPLACEMENT_CANDIDATES,
                MempoolConflictError::TooManyReplacements,
            );
        }
        Ok(())
    }

    fn replacements_with_descendants(
        &self,
        conflicts: &[&TxMempoolEntry],
    ) -> BTreeSet<Id<Transaction>> {
        conflicts
            .iter()
            .flat_map(|conflict| BTreeSet::from(conflict.unconfirmed_descendants(&self.store)))
            .chain(conflicts.iter().map(|conflict| *conflict.tx_id()))
            .collect()
    }
}

// Transaction Finalization
impl<M: MemoryUsageEstimator> Mempool<M> {
    fn finalize_tx(&mut self, entry: TxEntryWithFee) -> Result<(), Error> {
        let id = *entry.tx_id();
        self.store.add_transaction(entry)?;
        self.remove_expired_transactions();
        ensure!(
            self.store.txs_by_id.contains_key(&id),
            MempoolPolicyError::DescendantOfExpiredTransaction
        );

        self.limit_mempool_size()?;
        ensure!(
            self.store.txs_by_id.contains_key(&id),
            MempoolPolicyError::MempoolFull
        );
        Ok(())
    }

    pub fn set_max_size(&mut self, max_size: MempoolMaxSize) -> Result<(), Error> {
        if max_size > self.max_size {
            self.drop_rolling_fee();
        }
        self.max_size = max_size;
        self.limit_mempool_size()
    }

    fn limit_mempool_size(&mut self) -> Result<(), Error> {
        let removed_fees = self.trim()?;
        if !removed_fees.is_empty() {
            let new_minimum_fee_rate =
                (*removed_fees.iter().max().expect("removed_fees should not be empty")
                    + INCREMENTAL_RELAY_FEE_RATE)
                    .ok_or(MempoolPolicyError::FeeOverflow)?;
            if new_minimum_fee_rate > self.rolling_fee_rate.read().rolling_minimum_fee_rate() {
                self.update_min_fee_rate(new_minimum_fee_rate)
            }
        }

        Ok(())
    }

    fn remove_expired_transactions(&mut self) {
        let expired_ids: Vec<_> = self
            .store
            .txs_by_creation_time
            .iter()
            .map(|(_time, id)| self.store.txs_by_id.get(id).expect("entry should exist"))
            .filter(|entry| {
                let now = self.clock.get_time();
                let expired = now.saturating_sub(entry.creation_time()) > self.max_tx_age;
                if expired {
                    log::trace!(
                        "Evicting tx {} which was created at {:?}. It is now {:?}",
                        entry.tx_id(),
                        entry.creation_time(),
                        now
                    );
                }
                expired
            })
            .map(|entry| *entry.tx_id())
            .collect();

        for tx_id in expired_ids.iter() {
            self.remove_tx_and_descendants(tx_id, MempoolRemovalReason::Expiry);
        }
    }

    fn trim(&mut self) -> Result<Vec<FeeRate>, MempoolPolicyError> {
        let mut removed_fees = Vec::new();
        while !self.store.is_empty() && self.memory_usage() > self.max_size.as_bytes() {
            // TODO sort by descendant score, not by fee
            let removed_id = self
                .store
                .txs_by_descendant_score
                .iter()
                .map(|(_score, entry)| *entry)
                .next()
                .expect("pool not empty");
            let removed = self.store.txs_by_id.get(&removed_id).expect("tx with id should exist");

            log::debug!(
                "Mempool trim: Evicting tx {} which has a descendant score of {:?} and has size {}",
                removed_id,
                removed.descendant_score(),
                removed.size()
            );
            removed_fees.push(FeeRate::from_total_tx_fee(removed.fee(), removed.size())?);
            self.remove_tx_and_descendants(&removed_id, MempoolRemovalReason::SizeLimit);
        }
        Ok(removed_fees)
    }

    fn remove_tx_and_descendants(&mut self, tx_id: &Id<Transaction>, reason: MempoolRemovalReason) {
        let source = TransactionSource::Mempool;

        let result = self.store.drop_tx_and_descendants(tx_id, reason).try_for_each(|entry| {
            self.tx_verifier
                .disconnect_transaction(&source, entry.transaction())
                .map_err(|err| (*entry.tx_id(), err))
        });

        if let Err((disc_id, err)) = result {
            // Transaction disconnection failed. This should never happen because transactions are
            // disconnected leaves first. However, it can happen if the mempool store and the
            // transaction verifier do not agree on inter-transaction dependencies due to a bug. In
            // that case, log that it happened and opt for a nuclear option: refresh the mempool by
            // removing all transactions and re-adding them. Code used during reorgs is utilized to
            // accomplish this.
            //
            // TODO: Ideally, there should be single point of truth regarding inter-transaction
            // dependencies. However, it does not appear to be easy to extract that information
            // from the transaction verifier at the moment. To be addressed in the future.

            log::error!("Disconnecting {disc_id} failed with '{err}' during eviction of {tx_id}");

            if let Err(refresh_err) = reorg::refresh_mempool(self) {
                log::error!("Refreshing mempool failed: {refresh_err}");
            }
        }
    }
}

// Mempool Interface and Event Reactions
impl<M: MemoryUsageEstimator> Mempool<M> {
    /// Add a transaction to mempool
    pub fn add_transaction(
        &mut self,
        tx: SignedTransaction,
        origin: TxOrigin,
        work_queue: &mut WorkQueue,
    ) -> Result<TxStatus, Error> {
        let options = TxOptions::default_for(origin);
        self.add_transaction_with_options(tx, origin, options, work_queue)
    }

    /// Add a transaction to mempool with custom options
    pub fn add_transaction_with_options(
        &mut self,
        tx: SignedTransaction,
        origin: TxOrigin,
        options: TxOptions,
        work_queue: &mut WorkQueue,
    ) -> Result<TxStatus, Error> {
        let creation_time = self.clock.get_time();
        let entry = TxEntry::new(tx, creation_time, origin, options);

        match entry.options().trust_policy() {
            TxTrustPolicy::Trusted => {
                log::warn!(concat!(
                    "Trusted mempool processing policy not yet implemented, ",
                    "transaction will go through all the standard checks",
                ))
            }
            TxTrustPolicy::Untrusted => (),
        }

        self.add_transaction_and_descendants(entry, work_queue)
    }

    /// Add given transaction entry and potentially its descendants sourced from the orphan pool
    fn add_transaction_and_descendants(
        &mut self,
        entry: TxEntry,
        work_queue: &mut WorkQueue,
    ) -> Result<TxStatus, Error> {
        let tx_id = *entry.tx_id();
        let status = self.add_transaction_entry(entry)?;
        self.enqueue_children(&tx_id, work_queue);
        Ok(status)
    }

    /// Enqueue children of a transaction if it's been included in the mempool
    fn enqueue_children(&mut self, tx_id: &Id<Transaction>, work_queue: &mut WorkQueue) {
        if let Some(entry) = self.store.get_entry(tx_id) {
            for orphan in self.orphans.children_of(entry.tx_entry()) {
                let orphan_id = *orphan.tx_id();
                let peer_id = orphan.origin().peer_id();
                if work_queue.insert(peer_id, orphan_id) {
                    log::trace!("Added orphan {orphan_id:?} to peer{peer_id}'s work queue");
                }
            }
        }
    }

    fn add_transaction_entry(&mut self, tx: TxEntry) -> Result<TxStatus, Error> {
        // Note: it's not a good idea to use anything above "trace" here, even to log the
        // transaction id, because this may make our test logs huge,
        // see https://github.com/mintlayer/mintlayer-core/issues/1219#issuecomment-1728176441
        log::trace!("Adding transaction {tx:?}");

        let tx_id = *tx.tx_id();
        let origin = tx.origin();
        let relay_policy = tx.options().relay_policy();

        if self.contains_transaction(&tx_id) {
            return Ok(TxStatus::InMempoolDuplicate);
        }

        match self.validate_transaction(tx) {
            Ok(ValidationOutcome::Valid {
                transaction,
                conflicts,
                delta,
            }) => {
                if ENABLE_RBF {
                    self.store.drop_conflicts(conflicts);
                }
                tx_verifier::flush_to_storage(&mut self.tx_verifier, delta)?;
                self.finalize_tx(transaction)?;
                self.store.assert_valid();

                let event = event::TransactionProcessed::accepted(tx_id, relay_policy, origin);
                self.events_controller.broadcast(event.into());

                Ok(TxStatus::InMempool)
            }
            Ok(ValidationOutcome::Orphan { transaction }) => {
                Ok(self.orphans.insert_and_enforce_limits(transaction, self.clock.get_time())?)
            }
            Err(err) => {
                log::warn!("Transaction {tx_id} rejected: {err}");

                let event = event::TransactionProcessed::rejected(tx_id, err.clone(), origin);
                self.events_controller.broadcast(event.into());
                Err(err)
            }
        }
    }

    pub fn get_all(&self) -> Vec<SignedTransaction> {
        self.store
            .txs_by_descendant_score
            .iter()
            .map(|(_score, id)| self.store.get_entry(id).expect("entry").transaction().clone())
            .collect()
    }

    pub fn collect_txs(
        &self,
        tx_accumulator: Box<dyn TransactionAccumulator>,
        transaction_ids: Vec<Id<Transaction>>,
        packing_strategy: PackingStrategy,
    ) -> Result<Option<Box<dyn TransactionAccumulator>>, BlockConstructionError> {
        collect_txs::collect_txs(self, tx_accumulator, transaction_ids, packing_strategy)
    }

    pub fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>) {
        self.events_controller.subscribe_to_events(handler)
    }

    pub fn process_chainstate_event(
        &mut self,
        evt: chainstate::ChainstateEvent,
        work_queue: &mut WorkQueue,
    ) -> Result<(), reorg::ReorgError> {
        log::info!("mempool: Processing chainstate event {evt:?}");
        match evt {
            chainstate::ChainstateEvent::NewTip(block_id, block_height) => {
                self.on_new_tip(block_id, block_height, work_queue)?;
            }
        }
        Ok(())
    }

    pub fn on_new_tip(
        &mut self,
        block_id: Id<Block>,
        block_height: BlockHeight,
        work_queue: &mut WorkQueue,
    ) -> Result<(), reorg::ReorgError> {
        log::info!(
            "New block tip: {:?} at height {}",
            block_id.as_hash(),
            block_height.into_int()
        );
        reorg::handle_new_tip(self, block_id, work_queue)?;
        let event = event::NewTip::new(block_id, block_height);
        self.events_controller.broadcast(event.into());
        Ok(())
    }

    pub fn on_peer_disconnected(&mut self, peer_id: p2p_types::PeerId) {
        self.orphans.remove_by_origin(RemoteTxOrigin::new(peer_id));
    }

    pub fn get_fee_rate(&self, in_top_x_mb: usize) -> FeeRate {
        let min_feerate = std::cmp::max(
            self.rolling_fee_rate.read().rolling_minimum_fee_rate(),
            *self.mempool_config.min_tx_relay_fee_rate,
        );
        let mut total_size = 0;
        self.store
            .txs_by_descendant_score
            .iter()
            .rev()
            .find(|(_score, tx_id)| {
                total_size += self.store.txs_by_id.get(tx_id).map_or(0, |tx| tx.size().into());
                (total_size / 1_000_000) >= in_top_x_mb
            })
            .map_or(min_feerate, |(score, _txs)| score.to_feerate(min_feerate))
    }

    pub fn get_fee_rate_points(
        &self,
        num_points: NonZeroUsize,
    ) -> Result<Vec<(usize, FeeRate)>, MempoolPolicyError> {
        let min_feerate = std::cmp::max(
            self.rolling_fee_rate.read().rolling_minimum_fee_rate(),
            *self.mempool_config.min_tx_relay_fee_rate,
        );
        let min_score = DescendantScore::new(min_feerate);

        let size_to_score: BTreeMap<_, _> = self
            .store
            .txs_by_descendant_score
            .iter()
            .rev()
            .map(|(score, tx_id)| {
                let size = self.store.txs_by_id.get(tx_id).map_or(0, |tx| tx.size().into());
                (score, size)
            })
            .chain(std::iter::once((&min_score, 1)))
            .scan(0, |accumulated_size, (score, size)| {
                *accumulated_size += size;

                Some((*accumulated_size, *score))
            })
            .collect();

        let last = size_to_score.keys().next_back().expect("not empty");
        let first = size_to_score.keys().next().expect("not empty");
        let points = feerate_points::generate_equidistant_span(*first, *last, num_points.get());

        if points.len() >= size_to_score.len() {
            Ok(size_to_score
                .into_iter()
                .map(|(point, score)| (point, score.to_feerate(min_feerate)))
                .collect())
        } else {
            points
                .into_iter()
                .map(|point| {
                    let score = feerate_points::find_interpolated_value(&size_to_score, point)
                        .ok_or(MempoolPolicyError::FeeOverflow)?;
                    Ok((point, score.to_feerate(min_feerate)))
                })
                .collect()
        }
    }

    pub fn perform_work_unit(&mut self, work_queue: &mut WorkQueue) {
        log::trace!("Performing orphan processing work");

        let orphan_id = work_queue.perform(|peer, orphan_id| {
            log::debug!("Processing orphan tx {orphan_id:?} coming from peer{peer}");

            let orphan = match self.orphans.entry(&orphan_id) {
                Some(orphan) => orphan,
                None => {
                    // The orphan may have been kicked out of the pool in the meantime.
                    // Return with `None` in that case to indicate we've not really done any work.
                    log::debug!("Orphan tx {orphan_id:?} no longer in the pool");
                    return None;
                }
            };

            if orphan.is_ready() {
                // Take the transaction out of orphan pool and pass it to mempool processing code.
                let orphan = orphan.take().map_origin(TxOrigin::from);
                let result = self.add_transaction_entry(orphan);
                log::debug!("Orphan tx {orphan_id:?} processed: {result:?}");
            } else {
                // Not all prerequisites are satisfied. The tx stays in the orphan pool.
                log::debug!("Orphan tx {orphan_id:?} not ready");
            }

            Some(orphan_id)
        });

        if let Some(orphan_id) = orphan_id {
            self.enqueue_children(&orphan_id, work_queue);
        }
    }
}

#[cfg(test)]
mod tests;
