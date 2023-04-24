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
use std::{collections::BTreeSet, num::NonZeroUsize, sync::Arc, time::Duration};

use chainstate::{
    chainstate_interface::ChainstateInterface,
    tx_verifier::transaction_verifier::{TransactionSourceForConnect, TransactionVerifierDelta},
};
use common::{
    chain::{block::timestamp::BlockTimestamp, Block, ChainConfig, SignedTransaction, Transaction},
    primitives::{amount::Amount, BlockHeight, Id, Idable},
    time_getter::TimeGetter,
};
use logging::log;
use serialization::Encode;
use utils::{
    ensure, eventhandler::EventsController, shallow_clone::ShallowClone, tap_error_log::LogError,
};

use crate::{
    error::{Error, MempoolPolicyError, TxValidationError},
    get_memory_usage::GetMemoryUsage,
    tx_accumulator::TransactionAccumulator,
    MempoolEvent,
};
use feerate::{FeeRate, INCREMENTAL_RELAY_FEE_RATE, INCREMENTAL_RELAY_THRESHOLD};
use rolling_fee_rate::RollingFeeRate;
use spends_unconfirmed::SpendsUnconfirmed;
use store::{Conflicts, MempoolRemovalReason, MempoolStore, TxMempoolEntry};
use tx_with_fee::TxWithFee;

use crate::config::*;

use self::fee::Fee;

pub mod fee;
mod feerate;
mod rolling_fee_rate;
mod spends_unconfirmed;
mod store;
mod tx_verifier;
mod tx_with_fee;

fn get_relay_fee(tx: &SignedTransaction) -> Fee {
    // TODO we should never reach the expect, but should this be an error anyway?
    Amount::from_atoms(u128::try_from(tx.encoded_size() * RELAY_FEE_PER_BYTE).expect("Overflow"))
        .into()
}

pub struct Mempool<M> {
    #[allow(unused)]
    chain_config: Arc<ChainConfig>,
    store: MempoolStore,
    rolling_fee_rate: RwLock<RollingFeeRate>,
    max_size: usize,
    max_tx_age: Duration,
    chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
    clock: TimeGetter,
    memory_usage_estimator: M,
    events_controller: EventsController<MempoolEvent>,
    tx_verifier: tx_verifier::TransactionVerifier,
}

impl<M> std::fmt::Debug for Mempool<M>
where
    M: GetMemoryUsage + 'static + Send + Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.store)
    }
}

impl<M> GetMemoryUsage for Mempool<M>
where
    M: GetMemoryUsage + Send + Sync,
{
    fn get_memory_usage(&self) -> usize {
        self.memory_usage_estimator.get_memory_usage()
    }
}

impl<M> Mempool<M>
where
    M: GetMemoryUsage + Send + Sync,
{
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
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
            store: MempoolStore::new(),
            chainstate_handle,
            max_size: MAX_MEMPOOL_SIZE_BYTES,
            max_tx_age: DEFAULT_MEMPOOL_EXPIRY,
            // TODO research whether we really need parking lot
            rolling_fee_rate: RwLock::new(RollingFeeRate::new(clock.get_time())),
            clock,
            memory_usage_estimator,
            events_controller: Default::default(),
            tx_verifier,
        }
    }

    pub fn chainstate_handle(&self) -> &subsystem::Handle<Box<dyn ChainstateInterface>> {
        &self.chainstate_handle
    }
}

// Rolling-fee-related methods
impl<M> Mempool<M>
where
    M: GetMemoryUsage + Send + Sync,
{
    fn rolling_fee_halflife(&self) -> Time {
        let mem_usage = self.get_memory_usage();
        if mem_usage < self.max_size / 4 {
            ROLLING_FEE_BASE_HALFLIFE / 4
        } else if mem_usage < self.max_size / 2 {
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
            || rolling_fee_rate.rolling_minimum_fee_rate() == FeeRate::new(Amount::from_atoms(0))
        {
            return rolling_fee_rate.rolling_minimum_fee_rate();
        } else if self.clock.get_time()
            > rolling_fee_rate.last_rolling_fee_update() + ROLLING_FEE_DECAY_INTERVAL
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
        (*rolling_fee_rate).set_rolling_minimum_fee_rate(FeeRate::new(Amount::from_atoms(0)));
    }

    fn decay_rolling_fee_rate(&self) {
        let halflife = self.rolling_fee_halflife();
        let time = self.clock.get_time();
        let mut rolling_fee_rate = self.rolling_fee_rate.write();
        *rolling_fee_rate = (*rolling_fee_rate).decay_fee(halflife, time);
    }
}

// Entry Creation
impl<M> Mempool<M>
where
    M: GetMemoryUsage + Send + Sync,
{
    fn create_entry(&self, tx: TxWithFee) -> Result<TxMempoolEntry, MempoolPolicyError> {
        let (tx, fee) = tx.into_tx_and_fee();

        // Genesis transaction has no parent, hence the first filter_map
        let parents = tx
            .transaction()
            .inputs()
            .iter()
            .filter_map(|input| input.outpoint().tx_id().get_tx_id().cloned())
            .filter_map(|id| self.store.txs_by_id.contains_key(&id).then_some(id))
            .collect::<BTreeSet<_>>();
        let ancestor_ids =
            TxMempoolEntry::unconfirmed_ancestors_from_parents(parents.clone(), &self.store)?;
        let ancestors = BTreeSet::from(ancestor_ids)
            .into_iter()
            .map(|id| self.store.get_entry(&id).expect("ancestors to exist"))
            .cloned()
            .collect();

        let time = self.clock.get_time();
        TxMempoolEntry::new(tx, fee, parents, ancestors, time)
    }
}

// Transaction Validation
impl<M> Mempool<M>
where
    M: GetMemoryUsage + Send + Sync,
{
    fn validate_transaction(
        &self,
        tx: SignedTransaction,
    ) -> Result<(Conflicts, TxWithFee, TransactionVerifierDelta), Error> {
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

        self.check_preliminary_mempool_policy(&tx)?;

        let (tx, delta) = self.verify_transaction(tx)?;

        let conflicts = self.check_mempool_policy(&tx)?;

        Ok((conflicts, tx, delta))
    }

    // Verify the transaction with respect to the consensus rules
    fn verify_transaction(
        &self,
        tx: SignedTransaction,
    ) -> Result<(TxWithFee, TransactionVerifierDelta), TxValidationError> {
        let chainstate_handle =
            subsystem::blocking::BlockingHandle::new(self.chainstate_handle().shallow_clone());

        for _ in 0..MAX_TX_ADDITION_ATTEMPTS {
            let (tip, current_best) = chainstate_handle.call(|chainstate| {
                let tip = chainstate.get_best_block_id()?;
                let tip_index =
                    chainstate.get_gen_block_index(&tip)?.expect("tip block index to exist");
                Ok::<_, chainstate::ChainstateError>((tip, tip_index))
            })??;

            let mut tx_verifier = self.tx_verifier.derive_child();

            let fee = tx_verifier.connect_transaction(
                &TransactionSourceForConnect::Mempool {
                    current_best: &current_best,
                },
                &tx,
                &BlockTimestamp::from_duration_since_epoch(self.clock.get_time()),
            )?;

            let final_tip = chainstate_handle.call(|c| c.get_best_block_id())??;
            if tip == final_tip {
                let tx = TxWithFee::new_with_fee(tx, fee.into());
                let delta = tx_verifier.consume()?;
                return Ok((tx, delta));
            }
        }

        Err(TxValidationError::TipMoved)
    }

    // Cheap mempool policy checks that run before anything else
    fn check_preliminary_mempool_policy(
        &self,
        tx: &SignedTransaction,
    ) -> Result<(), MempoolPolicyError> {
        ensure!(
            !tx.transaction().inputs().is_empty(),
            MempoolPolicyError::NoInputs,
        );

        ensure!(
            !tx.transaction().outputs().is_empty(),
            MempoolPolicyError::NoOutputs,
        );

        // TODO: see this issue:
        // https://github.com/mintlayer/mintlayer-core/issues/331
        ensure!(
            tx.encoded_size() <= MAX_BLOCK_SIZE_BYTES,
            MempoolPolicyError::ExceedsMaxBlockSize,
        );

        // TODO: Taken from the previous implementation. Is this correct?
        ensure!(
            !self.contains_transaction(&tx.transaction().get_id()),
            MempoolPolicyError::TransactionAlreadyInMempool
        );

        Ok(())
    }

    // Check the transaction against the mempool inclusion policy
    fn check_mempool_policy(&self, tx: &TxWithFee) -> Result<Conflicts, MempoolPolicyError> {
        self.pays_minimum_relay_fees(tx)?;
        self.pays_minimum_mempool_fee(tx)?;

        if ENABLE_RBF {
            self.rbf_checks(tx)
        } else {
            // Without RBF enabled, any conflicting transaction results in an error
            ensure!(
                self.conflicting_tx_ids(tx.tx()).next().is_none(),
                MempoolPolicyError::ConflictWithIrreplaceableTransaction
            );
            Ok(Conflicts::new(BTreeSet::new()))
        }
    }

    fn pays_minimum_mempool_fee(&self, tx: &TxWithFee) -> Result<(), MempoolPolicyError> {
        let tx_fee = tx.fee();
        let minimum_fee = self.get_update_minimum_mempool_fee(tx.tx())?;
        log::debug!("pays_minimum_mempool_fee tx_fee = {tx_fee:?}, minimum_fee = {minimum_fee:?}");
        ensure!(
            tx_fee >= minimum_fee,
            MempoolPolicyError::RollingFeeThresholdNotMet {
                minimum_fee,
                tx_fee,
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

    fn pays_minimum_relay_fees(&self, tx: &TxWithFee) -> Result<(), MempoolPolicyError> {
        let tx_fee = tx.fee();
        let relay_fee = get_relay_fee(tx.tx());
        log::debug!("tx_fee: {:?}, relay_fee: {:?}", tx_fee, relay_fee);
        ensure!(
            tx_fee >= relay_fee,
            MempoolPolicyError::InsufficientFeesToRelay { tx_fee, relay_fee }
        );
        Ok(())
    }

    fn conflicting_tx_ids<'a>(
        &'a self,
        tx: &'a SignedTransaction,
    ) -> impl 'a + Iterator<Item = Id<Transaction>> {
        tx.transaction()
            .inputs()
            .iter()
            .filter_map(|input| self.store.find_conflicting_tx(input.outpoint()))
    }
}

// RBF checks
impl<M> Mempool<M>
where
    M: GetMemoryUsage + Send + Sync,
{
    fn rbf_checks(&self, tx: &TxWithFee) -> Result<Conflicts, MempoolPolicyError> {
        let conflicts = self
            .conflicting_tx_ids(tx.tx())
            .map(|id_conflict| self.store.get_entry(&id_conflict).expect("entry for id"))
            .collect::<Vec<_>>();

        if conflicts.is_empty() {
            Ok(BTreeSet::new().into())
        } else {
            self.do_rbf_checks(tx, &conflicts)
        }
    }

    fn do_rbf_checks(
        &self,
        tx: &TxWithFee,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<Conflicts, MempoolPolicyError> {
        for entry in conflicts {
            // Enforce BIP125 Rule #1.

            ensure!(
                entry.is_replaceable(&self.store),
                MempoolPolicyError::ConflictWithIrreplaceableTransaction
            );
        }
        // It's possible that the replacement pays more fees than its direct conflicts but not more
        // than all conflicts (i.e. the direct conflicts have high-fee descendants). However, if the
        // replacement doesn't pay more fees than its direct conflicts, then we can be sure it's not
        // more economically rational to mine. Before we go digging through the mempool for all
        // transactions that would need to be removed (direct conflicts and all descendants), check
        // that the replacement transaction pays more than its direct conflicts.
        self.pays_more_than_direct_conflicts(tx, conflicts)?;
        // Enforce BIP125 Rule #2.
        self.spends_no_new_unconfirmed_outputs(tx, conflicts)?;
        // Enforce BIP125 Rule #5.
        let conflicts_with_descendants = self.potential_replacements_within_limit(conflicts)?;
        // Enforce BIP125 Rule #3.
        let total_conflict_fees =
            self.pays_more_than_conflicts_with_descendants(tx, &conflicts_with_descendants)?;
        // Enforce BIP125 Rule #4.
        self.pays_for_bandwidth(tx, total_conflict_fees)?;
        Ok(Conflicts::from(conflicts_with_descendants))
    }

    fn pays_for_bandwidth(
        &self,
        tx: &TxWithFee,
        total_conflict_fees: Fee,
    ) -> Result<(), MempoolPolicyError> {
        log::debug!("pays_for_bandwidth: tx fee is {:?}", tx.fee());
        let additional_fees =
            (tx.fee() - total_conflict_fees).ok_or(MempoolPolicyError::AdditionalFeesUnderflow)?;
        let relay_fee = get_relay_fee(tx.tx());
        log::debug!(
            "conflict fees: {:?}, additional fee: {:?}, relay_fee {:?}",
            total_conflict_fees,
            additional_fees,
            relay_fee
        );
        ensure!(
            additional_fees >= relay_fee,
            MempoolPolicyError::InsufficientFeesToRelayRBF
        );
        Ok(())
    }

    fn pays_more_than_conflicts_with_descendants(
        &self,
        tx: &TxWithFee,
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

    fn spends_no_new_unconfirmed_outputs(
        &self,
        tx: &TxWithFee,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), MempoolPolicyError> {
        let outpoints_spent_by_conflicts = conflicts
            .iter()
            .flat_map(|conflict| {
                conflict.tx().transaction().inputs().iter().map(|input| input.outpoint())
            })
            .collect::<BTreeSet<_>>();

        tx.tx()
            .transaction()
            .inputs()
            .iter()
            .find(|input| {
                // input spends an unconfirmed output
                input.spends_unconfirmed(self) &&
                // this unconfirmed output is not spent by one of the conflicts
                !outpoints_spent_by_conflicts.contains(&input.outpoint())
            })
            .map_or(Ok(()), |_| {
                Err(MempoolPolicyError::SpendsNewUnconfirmedOutput)
            })
    }

    fn pays_more_than_direct_conflicts(
        &self,
        tx: &TxWithFee,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), MempoolPolicyError> {
        let replacement_fee = tx.fee();
        conflicts.iter().find(|conflict| conflict.fee() >= replacement_fee).map_or_else(
            || Ok(()),
            |conflict| {
                Err(MempoolPolicyError::ReplacementFeeLowerThanOriginal {
                    replacement_tx: tx.tx().transaction().get_id().get(),
                    replacement_fee,
                    original_fee: conflict.fee(),
                    original_tx: conflict.tx_id().get(),
                })
            },
        )
    }

    fn potential_replacements_within_limit(
        &self,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<BTreeSet<Id<Transaction>>, MempoolPolicyError> {
        let mut num_potential_replacements = 0;
        for conflict in conflicts {
            num_potential_replacements += conflict.count_with_descendants();
            if num_potential_replacements > MAX_BIP125_REPLACEMENT_CANDIDATES {
                return Err(MempoolPolicyError::TooManyPotentialReplacements);
            }
        }
        let replacements_with_descendants = conflicts
            .iter()
            .flat_map(|conflict| BTreeSet::from(conflict.unconfirmed_descendants(&self.store)))
            .chain(conflicts.iter().map(|conflict| conflict.tx_id()))
            .collect();

        Ok(replacements_with_descendants)
    }
}

// Transaction Finalization
impl<M> Mempool<M>
where
    M: GetMemoryUsage + Send + Sync,
{
    fn finalize_tx(&mut self, tx: TxWithFee) -> Result<(), Error> {
        let entry = self.create_entry(tx)?;
        let id = entry.tx_id();
        self.store.add_tx(entry)?;
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
        let expired: Vec<_> = self
            .store
            .txs_by_creation_time
            .values()
            .flatten()
            .map(|entry_id| self.store.txs_by_id.get(entry_id).expect("entry should exist"))
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
            .cloned()
            .collect();

        for tx_id in expired.iter().map(|entry| entry.tx_id()) {
            self.store.drop_tx_and_descendants(tx_id, MempoolRemovalReason::Expiry)
        }
    }

    fn trim(&mut self) -> Result<Vec<FeeRate>, MempoolPolicyError> {
        let mut removed_fees = Vec::new();
        while !self.store.is_empty() && self.get_memory_usage() > self.max_size {
            // TODO sort by descendant score, not by fee
            let removed_id = self
                .store
                .txs_by_descendant_score
                .values()
                .flatten()
                .next()
                .expect("pool not empty");
            let removed =
                self.store.txs_by_id.get(removed_id).expect("tx with id should exist").clone();

            log::debug!(
                "Mempool trim: Evicting tx {} which has a descendant score of {:?} and has size {}",
                removed.tx_id(),
                removed.descendant_score(),
                removed.size()
            );
            removed_fees.push(FeeRate::from_total_tx_fee(
                removed.fee(),
                NonZeroUsize::new(removed.size()).expect("transaction cannot have zero size"),
            )?);
            self.store
                .drop_tx_and_descendants(removed.tx_id(), MempoolRemovalReason::SizeLimit);
        }
        Ok(removed_fees)
    }
}

// Mempool Interface and Event Reactions
impl<M> Mempool<M>
where
    M: GetMemoryUsage + Send + Sync,
{
    pub fn add_transaction(&mut self, tx: SignedTransaction) -> Result<(), Error> {
        log::debug!("Adding transaction {:?}", tx.transaction().get_id());
        log::trace!("Adding transaction {tx:?}");

        let (conflicts, tx, delta) =
            self.validate_transaction(tx).log_err_pfx("Transaction rejected")?;
        if ENABLE_RBF {
            self.store.drop_conflicts(conflicts);
        }

        tx_verifier::flush_to_storage(&mut self.tx_verifier, delta)?;
        self.finalize_tx(tx)?;
        self.store.assert_valid();
        Ok(())
    }

    pub fn get_all(&self) -> Vec<SignedTransaction> {
        self.store
            .txs_by_descendant_score
            .values()
            .flatten()
            .map(|id| self.store.get_entry(id).expect("entry").tx())
            .cloned()
            .collect()
    }

    pub fn collect_txs(
        &self,
        mut tx_accumulator: Box<dyn TransactionAccumulator>,
    ) -> Box<dyn TransactionAccumulator> {
        let mut tx_iter = self.store.txs_by_ancestor_score.values().flatten().rev();
        // TODO implement Iterator for MempoolStore so we don't need to use `expect` here
        while !tx_accumulator.done() {
            if let Some(tx_id) = tx_iter.next() {
                let next_tx = self.store.txs_by_id.get(tx_id).expect("tx to exist");
                log::debug!(
                    "collect_txs: next tx has ancestor score {:?}",
                    next_tx.ancestor_score()
                );

                match tx_accumulator.add_tx(next_tx.tx().clone(), next_tx.fee()) {
                    Ok(_) => (),
                    Err(err) => log::error!(
                        "CRITICAL: Failed to add transaction {} from mempool. Error: {}",
                        next_tx.tx().transaction().get_id(),
                        err
                    ),
                }
            } else {
                break;
            }
        }
        tx_accumulator
    }

    pub fn contains_transaction(&self, tx_id: &Id<Transaction>) -> bool {
        self.store.txs_by_id.contains_key(tx_id)
    }

    pub fn transaction(&self, id: &Id<Transaction>) -> Option<&SignedTransaction> {
        self.store.txs_by_id.get(id).map(|e| e.tx())
    }

    pub fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>) {
        self.events_controller.subscribe_to_events(handler)
    }

    pub fn process_chainstate_event(&mut self, evt: chainstate::ChainstateEvent) {
        log::info!("mempool: Processing chainstate event {evt:?}");
        match evt {
            chainstate::ChainstateEvent::NewTip(block_id, block_height) => {
                self.new_tip_set(block_id, block_height);
            }
        }
    }

    pub fn new_tip_set(&mut self, block_id: Id<Block>, block_height: BlockHeight) {
        // TODO: turn on mempool new tip broadcasts when ready
        // self.events_controller.broadcast(MempoolEvent::NewTip(block_id, block_height));

        log::info!("new tip with block_id {block_id:?} and block_height {block_height:?}");

        self.rolling_fee_rate.write().set_block_since_last_rolling_fee_bump(true);

        // Take all the mempool previous transactions
        let old_store = std::mem::replace(&mut self.store, MempoolStore::new());

        // Discard the old tx verifier and replace it with a fresh one
        self.tx_verifier = tx_verifier::create(
            self.chain_config.shallow_clone(),
            self.chainstate_handle.shallow_clone(),
        );

        // Re-populate the verifier with transactions
        for tx in old_store.into_transactions() {
            let tx_id = tx.transaction().get_id();
            if let Err(e) = self.add_transaction(tx) {
                log::trace!("Evicting {tx_id} from mempool: {e:?}")
            }
        }
    }
}

#[cfg(test)]
mod tests;
