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

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use common::chain::Block;
use common::primitives::BlockHeight;
use tokio::sync::mpsc;

use chainstate::chainstate_interface::ChainstateInterface;
use common::chain::signed_transaction::SignedTransaction;
use common::chain::tokens::OutputValue;
use common::chain::ChainConfig;
use common::time_getter::TimeGetter;
use parking_lot::RwLock;
use serialization::Encode;

use common::chain::transaction::Transaction;
use common::primitives::amount::Amount;
use common::primitives::Id;
use common::primitives::Idable;

use logging::log;

use utils::ensure;
use utils::eventhandler::EventsController;
use utils::newtype;
use utils::tap_error_log::LogError;

use crate::error::Error;
use crate::error::TxValidationError;
use crate::get_memory_usage::GetMemoryUsage;
use crate::get_memory_usage::MemoryUsage;
use crate::mempool_interface_impl::mempool_method_call::MempoolMethodCall;
use crate::tx_accumulator::TransactionAccumulator;
use crate::MempoolEvent;
use feerate::FeeRate;
use feerate::INCREMENTAL_RELAY_FEE_RATE;
use feerate::INCREMENTAL_RELAY_THRESHOLD;
use rolling_fee_rate::RollingFeeRate;
use spends_unconfirmed::SpendsUnconfirmed;
use store::MempoolRemovalReason;
use store::MempoolStore;
use store::TxMempoolEntry;

pub use crate::interface::mempool_interface::MempoolInterface;

use crate::config::*;

mod feerate;
mod rolling_fee_rate;
mod spends_unconfirmed;
mod store;

#[async_trait::async_trait]
impl<M> TryGetFee for Mempool<M>
where
    M: GetMemoryUsage + Send + std::marker::Sync,
{
    // TODO this calculation is already done in ChainState, reuse it
    async fn try_get_fee(&self, tx: &SignedTransaction) -> Result<Amount, TxValidationError> {
        let tx_clone = tx.clone();
        let chainstate_input_values = self
            .chainstate_handle
            .call(move |this| this.get_inputs_outpoints_values(tx_clone.transaction()))
            .await??;

        let mut input_values = Vec::<Amount>::new();
        for (i, chainstate_input_value) in chainstate_input_values.iter().enumerate() {
            if let Some(value) = chainstate_input_value {
                input_values.push(*value)
            } else {
                let value = self.store.get_unconfirmed_outpoint_value(
                    tx.transaction().inputs().get(i).expect("index").outpoint(),
                )?;
                input_values.push(value);
            }
        }

        let sum_inputs = input_values
            .iter()
            .cloned()
            .sum::<Option<_>>()
            .ok_or(TxValidationError::InputValuesOverflow)?;
        let sum_outputs = tx
            .transaction()
            .outputs()
            .iter()
            .filter_map(|output| match output.value() {
                OutputValue::Coin(coin) => Some(*coin),
                OutputValue::Token(_) => None,
            })
            .sum::<Option<_>>()
            .ok_or(TxValidationError::OutputValuesOverflow)?;
        (sum_inputs - sum_outputs).ok_or(TxValidationError::InputsBelowOutputs)
    }
}

fn get_relay_fee(tx: &SignedTransaction) -> Amount {
    // TODO we should never reach the expect, but should this be an error anyway?
    Amount::from_atoms(u128::try_from(tx.encoded_size() * RELAY_FEE_PER_BYTE).expect("Overflow"))
}

#[async_trait::async_trait]
trait TryGetFee {
    async fn try_get_fee(&self, tx: &SignedTransaction) -> Result<Amount, TxValidationError>;
}

newtype! {
    #[derive(Debug)]
    struct Ancestors(BTreeSet<Id<Transaction>>);
}

newtype! {
    #[derive(Debug)]
    struct Descendants(BTreeSet<Id<Transaction>>);
}

newtype! {
    #[derive(Debug)]
    struct Conflicts(BTreeSet<Id<Transaction>>);
}

pub struct Mempool<M: GetMemoryUsage + 'static + Send + std::marker::Sync> {
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
    receiver: mpsc::UnboundedReceiver<MempoolMethodCall>,
}

impl<M> std::fmt::Debug for Mempool<M>
where
    M: GetMemoryUsage + 'static + Send + std::marker::Sync,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.store)
    }
}

impl<M> Mempool<M>
where
    M: GetMemoryUsage + Send + std::marker::Sync,
{
    pub fn new(
        chain_config: Arc<ChainConfig>,
        chainstate_handle: subsystem::Handle<Box<dyn ChainstateInterface>>,
        clock: TimeGetter,
        memory_usage_estimator: M,
        receiver: tokio::sync::mpsc::UnboundedReceiver<MempoolMethodCall>,
    ) -> Self {
        Self {
            chain_config,
            store: MempoolStore::new(),
            chainstate_handle,
            max_size: MAX_MEMPOOL_SIZE_BYTES,
            max_tx_age: DEFAULT_MEMPOOL_EXPIRY,
            // TODO research whether we really need parking lot
            rolling_fee_rate: parking_lot::RwLock::new(RollingFeeRate::new(clock.get_time())),
            clock,
            memory_usage_estimator,
            events_controller: Default::default(),
            receiver,
        }
    }

    pub async fn subscribe_to_chainstate_events(
        &mut self,
    ) -> crate::Result<mpsc::UnboundedReceiver<(Id<Block>, BlockHeight)>> {
        let (tx, rx) = mpsc::unbounded_channel();
        let subscribe_func =
            Arc::new(
                move |chainstate_event: chainstate::ChainstateEvent| match chainstate_event {
                    chainstate::ChainstateEvent::NewTip(block_id, block_height) => {
                        log::info!(
                            "Received a new tip with block id {:?} and block height {:?}",
                            block_id,
                            block_height
                        );
                        if let Err(e) = tx.send((block_id, block_height)) {
                            log::error!("Mempool Event Handler closed: {:?}", e)
                        }
                    }
                },
            );

        self.chainstate_handle
            .call_mut(|this| this.subscribe_to_events(subscribe_func))
            .await
            .map_err(|_| crate::error::Error::SubsystemFailure)?;
        Ok(rx)
    }

    pub fn new_tip_set(&mut self, block_id: Id<Block>, block_height: BlockHeight) {
        log::info!(
            "new tip with block_id {:?} and block_height {:?}",
            block_id,
            block_height
        );
        // TODO(Roy) handle the new tip
        let mut rolling_fee_rate = self.rolling_fee_rate.write();
        (*rolling_fee_rate).set_block_since_last_rolling_fee_bump(true);
    }
    //

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

    fn get_memory_usage(&self) -> usize {
        self.memory_usage_estimator.get_memory_usage()
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
                self.rolling_fee_rate
            );

            if self.rolling_fee_rate.read().rolling_minimum_fee_rate() < INCREMENTAL_RELAY_THRESHOLD
            {
                log::trace!("rolling fee rate {:?} less than half of the incremental fee rate, dropping the fee", self.rolling_fee_rate.read().rolling_minimum_fee_rate());
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

    async fn verify_inputs_available(
        &self,
        tx: &SignedTransaction,
    ) -> Result<(), TxValidationError> {
        let tx_clone = tx.clone();
        let chainstate_inputs = self
            .chainstate_handle
            .call(move |this| this.available_inputs(tx_clone.transaction()))
            .await??;
        tx.transaction()
            .inputs()
            .iter()
            .find(|input| {
                !chainstate_inputs.contains(&Some((*input).clone()))
                    && !self.store.contains_outpoint(input.outpoint())
            })
            .map_or_else(
                || Ok(()),
                |input| {
                    Err(TxValidationError::OutPointNotFound {
                        outpoint: input.outpoint().clone(),
                        tx_id: tx.transaction().get_id(),
                    })
                },
            )
    }

    async fn create_entry(
        &self,
        tx: SignedTransaction,
    ) -> Result<TxMempoolEntry, TxValidationError> {
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
        let ancestors = ancestor_ids
            .0
            .into_iter()
            .map(|id| self.store.get_entry(&id).expect("ancestors to exist"))
            .cloned()
            .collect();

        let fee = self.try_get_fee(&tx).await?;
        let time = self.clock.get_time();
        TxMempoolEntry::new(tx, fee, parents, ancestors, time)
    }

    fn get_update_minimum_mempool_fee(
        &self,
        tx: &SignedTransaction,
    ) -> Result<Amount, TxValidationError> {
        let minimum_fee_rate = self.get_update_min_fee_rate();
        log::debug!("minimum fee rate {:?}", minimum_fee_rate);
        /*log::debug!(
            "tx_size: {:?}, tx_fee {:?}",
            tx.encoded_size(),
            self.try_get_fee(tx)?
        );
        */
        let res = minimum_fee_rate.compute_fee(tx.encoded_size());
        log::debug!("minimum_mempool_fee for tx: {:?}", res);
        res
    }

    async fn validate_transaction(
        &self,
        tx: &SignedTransaction,
    ) -> Result<Conflicts, TxValidationError> {
        // This validation function is based on Bitcoin Core's MemPoolAccept::PreChecks.
        // However, as of this stage it does not cover everything covered in Bitcoin Core
        //
        // Currently, the items we want covered which are NOT yet covered are:
        //
        // - Checking if a transaction is "standard" (see `IsStandardTx`, `AreInputsStandard` in Bitcoin Core). We have yet to decide on Mintlayer's
        // definition of "standard"
        //
        // - Time locks:  Briefly, the corresponding functions in Bitcoin Core are `CheckFinalTx` and
        // `CheckSequenceLocks`. See mempool/src/time_lock_notes.txt for more details on our
        // brainstorming on this topic thus far.
        //
        // - Bitcoin Core does not relay transactions smaller than 82 bytes (see
        // MIN_STANDARD_TX_NONWITNESS_SIZE in Bitcoin Core's policy.h)
        //
        // - Checking that coinbase inputs have matured
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

        if tx.transaction().inputs().is_empty() {
            return Err(TxValidationError::NoInputs);
        }

        if tx.transaction().outputs().is_empty() {
            return Err(TxValidationError::NoOutputs);
        }

        let outpoints = tx.transaction().inputs().iter().map(|input| input.outpoint()).cloned();

        if has_duplicate_entry(outpoints) {
            return Err(TxValidationError::DuplicateInputs);
        }

        // TODO see this issue:
        // https://github.com/mintlayer/mintlayer-core/issues/331
        if tx.encoded_size() > MAX_BLOCK_SIZE_BYTES {
            return Err(TxValidationError::ExceedsMaxBlockSize);
        }

        if self.contains_transaction(&tx.transaction().get_id()) {
            return Err(TxValidationError::TransactionAlreadyInMempool);
        }

        let conflicts = self.rbf_checks(tx).await?;

        self.verify_inputs_available(tx).await?;

        self.pays_minimum_relay_fees(tx).await?;

        self.pays_minimum_mempool_fee(tx).await?;

        Ok(conflicts)
    }

    async fn pays_minimum_mempool_fee(
        &self,
        tx: &SignedTransaction,
    ) -> Result<(), TxValidationError> {
        let tx_fee = self.try_get_fee(tx).await?;
        let minimum_fee = self.get_update_minimum_mempool_fee(tx)?;
        log::debug!(
            "pays_minimum_mempool_fee tx_fee = {:?}, minimum_fee = {:?}",
            tx_fee,
            minimum_fee
        );
        ensure!(
            tx_fee >= minimum_fee,
            TxValidationError::RollingFeeThresholdNotMet {
                minimum_fee,
                tx_fee,
            }
        );
        Ok(())
    }

    async fn pays_minimum_relay_fees(
        &self,
        tx: &SignedTransaction,
    ) -> Result<(), TxValidationError> {
        let tx_fee = self.try_get_fee(tx).await?;
        let relay_fee = get_relay_fee(tx);
        log::debug!("tx_fee: {:?}, relay_fee: {:?}", tx_fee, relay_fee);
        ensure!(
            tx_fee >= relay_fee,
            TxValidationError::InsufficientFeesToRelay { tx_fee, relay_fee }
        );
        Ok(())
    }

    async fn rbf_checks(&self, tx: &SignedTransaction) -> Result<Conflicts, TxValidationError> {
        let conflicts = tx
            .transaction()
            .inputs()
            .iter()
            .filter_map(|input| self.store.find_conflicting_tx(input.outpoint()))
            .map(|id_conflict| self.store.get_entry(&id_conflict).expect("entry for id"))
            .collect::<Vec<_>>();

        if conflicts.is_empty() {
            Ok(Conflicts(BTreeSet::new()))
        } else {
            self.do_rbf_checks(tx, &conflicts).await
        }
    }

    async fn do_rbf_checks(
        &self,
        tx: &SignedTransaction,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<Conflicts, TxValidationError> {
        for entry in conflicts {
            // Enforce BIP125 Rule #1.

            ensure!(
                entry.is_replaceable(&self.store),
                TxValidationError::ConflictWithIrreplaceableTransaction
            );
        }
        // It's possible that the replacement pays more fees than its direct conflicts but not more
        // than all conflicts (i.e. the direct conflicts have high-fee descendants). However, if the
        // replacement doesn't pay more fees than its direct conflicts, then we can be sure it's not
        // more economically rational to mine. Before we go digging through the mempool for all
        // transactions that would need to be removed (direct conflicts and all descendants), check
        // that the replacement transaction pays more than its direct conflicts.
        self.pays_more_than_direct_conflicts(tx, conflicts).await?;
        // Enforce BIP125 Rule #2.
        self.spends_no_new_unconfirmed_outputs(tx, conflicts)?;
        // Enforce BIP125 Rule #5.
        let conflicts_with_descendants = self.potential_replacements_within_limit(conflicts)?;
        // Enforce BIP125 Rule #3.
        let total_conflict_fees = self
            .pays_more_than_conflicts_with_descendants(tx, &conflicts_with_descendants)
            .await?;
        // Enforce BIP125 Rule #4.
        self.pays_for_bandwidth(tx, total_conflict_fees).await?;
        Ok(Conflicts::from(conflicts_with_descendants))
    }

    async fn pays_for_bandwidth(
        &self,
        tx: &SignedTransaction,
        total_conflict_fees: Amount,
    ) -> Result<(), TxValidationError> {
        log::debug!(
            "pays_for_bandwidth: tx fee is {:?}",
            self.try_get_fee(tx).await?
        );
        let additional_fees = (self.try_get_fee(tx).await? - total_conflict_fees)
            .ok_or(TxValidationError::AdditionalFeesUnderflow)?;
        let relay_fee = get_relay_fee(tx);
        log::debug!(
            "conflict fees: {:?}, additional fee: {:?}, relay_fee {:?}",
            total_conflict_fees,
            additional_fees,
            relay_fee
        );
        ensure!(
            additional_fees >= relay_fee,
            TxValidationError::InsufficientFeesToRelayRBF
        );
        Ok(())
    }

    async fn pays_more_than_conflicts_with_descendants(
        &self,
        tx: &SignedTransaction,
        conflicts_with_descendants: &BTreeSet<Id<Transaction>>,
    ) -> Result<Amount, TxValidationError> {
        let conflicts_with_descendants = conflicts_with_descendants.iter().map(|conflict_id| {
            self.store.txs_by_id.get(conflict_id).expect("tx should exist in mempool")
        });

        let total_conflict_fees = conflicts_with_descendants
            .map(|conflict| conflict.fee())
            .sum::<Option<Amount>>()
            .ok_or(TxValidationError::ConflictsFeeOverflow)?;

        let replacement_fee = self.try_get_fee(tx).await?;
        ensure!(
            replacement_fee > total_conflict_fees,
            TxValidationError::TransactionFeeLowerThanConflictsWithDescendants
        );
        Ok(total_conflict_fees)
    }

    fn spends_no_new_unconfirmed_outputs(
        &self,
        tx: &SignedTransaction,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), TxValidationError> {
        let outpoints_spent_by_conflicts = conflicts
            .iter()
            .flat_map(|conflict| {
                conflict.tx().transaction().inputs().iter().map(|input| input.outpoint())
            })
            .collect::<BTreeSet<_>>();

        tx.transaction()
            .inputs()
            .iter()
            .find(|input| {
                // input spends an unconfirmed output
                input.spends_unconfirmed(self) &&
                // this unconfirmed output is not spent by one of the conflicts
                !outpoints_spent_by_conflicts.contains(&input.outpoint())
            })
            .map_or(Ok(()), |_| {
                Err(TxValidationError::SpendsNewUnconfirmedOutput)
            })
    }

    async fn pays_more_than_direct_conflicts(
        &self,
        tx: &SignedTransaction,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), TxValidationError> {
        let replacement_fee = self.try_get_fee(tx).await?;
        conflicts.iter().find(|conflict| conflict.fee() >= replacement_fee).map_or_else(
            || Ok(()),
            |conflict| {
                Err(TxValidationError::ReplacementFeeLowerThanOriginal {
                    replacement_tx: tx.transaction().get_id().get(),
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
    ) -> Result<BTreeSet<Id<Transaction>>, TxValidationError> {
        let mut num_potential_replacements = 0;
        for conflict in conflicts {
            num_potential_replacements += conflict.count_with_descendants();
            if num_potential_replacements > MAX_BIP125_REPLACEMENT_CANDIDATES {
                return Err(TxValidationError::TooManyPotentialReplacements);
            }
        }
        let replacements_with_descendants = conflicts
            .iter()
            .flat_map(|conflict| conflict.unconfirmed_descendants(&self.store).0)
            .chain(conflicts.iter().map(|conflict| conflict.tx_id()))
            .collect();

        Ok(replacements_with_descendants)
    }

    async fn finalize_tx(&mut self, tx: SignedTransaction) -> Result<(), Error> {
        let entry = self.create_entry(tx).await?;
        let id = entry.tx_id();
        self.store.add_tx(entry)?;
        self.remove_expired_transactions();
        ensure!(
            self.store.txs_by_id.contains_key(&id),
            TxValidationError::DescendantOfExpiredTransaction
        );

        self.limit_mempool_size()?;
        ensure!(self.store.txs_by_id.contains_key(&id), Error::MempoolFull);
        Ok(())
    }

    fn limit_mempool_size(&mut self) -> Result<(), Error> {
        let removed_fees = self.trim()?;
        if !removed_fees.is_empty() {
            let new_minimum_fee_rate =
                (*removed_fees.iter().max().expect("removed_fees should not be empty")
                    + INCREMENTAL_RELAY_FEE_RATE)
                    .ok_or(TxValidationError::FeeOverflow)?;
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
                    true
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        for tx_id in expired.iter().map(|entry| entry.tx_id()) {
            self.store.drop_tx_and_descendants(tx_id, MempoolRemovalReason::Expiry)
        }
    }

    fn trim(&mut self) -> Result<Vec<FeeRate>, TxValidationError> {
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

#[derive(Clone)]
pub struct SystemUsageEstimator;
impl GetMemoryUsage for SystemUsageEstimator {
    fn get_memory_usage(&self) -> MemoryUsage {
        //TODO implement real usage estimation here
        0
    }
}

impl<M> Mempool<M>
where
    M: GetMemoryUsage + Send + std::marker::Sync,
{
    pub async fn run(mut self) -> Result<(), Error> {
        tokio::spawn(async move {
            let event_receiver =
                self.subscribe_to_chainstate_events().await.log_err().expect("chainstate dead");
            self.mempool_event_loop(event_receiver).await
        });
        Ok(())
    }

    pub async fn mempool_event_loop(
        mut self,
        mut chainstate_event_receiver: mpsc::UnboundedReceiver<(Id<Block>, BlockHeight)>,
    ) {
        loop {
            tokio::select! {
                Some((block_id, block_height)) = chainstate_event_receiver.recv() =>{
                    self.new_tip_set(block_id, block_height)
                },
                Some(method_call) = self.receiver.recv() => self.handle_mempool_method_call(method_call).await
            }
        }
    }

    pub async fn handle_mempool_method_call(&mut self, method_call: MempoolMethodCall) {
        match method_call {
            MempoolMethodCall::AddTransaction { tx, rtx } => {
                if let Err(e) = rtx.send(self.add_transaction(tx).await) {
                    logging::log::error!("AddTransaction: Error sending response: {:?}", e);
                }
            }
            MempoolMethodCall::GetAll { rtx } => {
                if let Err(e) = rtx.send(self.get_all()) {
                    logging::log::error!("GetAll: Error sending response: {:?}", e);
                }
            }
            MempoolMethodCall::CollectTxs {
                tx_accumulator,
                rtx,
            } => {
                if let Err(e) = rtx.send(self.collect_txs(tx_accumulator)) {
                    logging::log::error!(
                        "CollectTxs: Error sending response: {:?}",
                        e.transactions()
                    );
                }
            }
            MempoolMethodCall::ContainsTransaction { tx_id, rtx } => {
                if let Err(e) = rtx.send(self.contains_transaction(&tx_id)) {
                    logging::log::error!("ContainsTransaction: Error sending response: {:?}", e);
                }
            }
            MempoolMethodCall::SubscribeToEvents { handler, rtx } => {
                self.subscribe_to_events(handler);
                if let Err(e) = rtx.send(()) {
                    logging::log::error!("SubscribeToEvents: Error sending response: {:?}", e);
                }
            }
        }
    }

    pub async fn add_transaction(&mut self, tx: SignedTransaction) -> Result<(), Error> {
        let conflicts = self.validate_transaction(&tx).await?;
        self.store.drop_conflicts(conflicts);
        self.finalize_tx(tx).await?;
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

    fn subscribe_to_events(&mut self, handler: Arc<dyn Fn(MempoolEvent) + Send + Sync>) {
        self.events_controller.subscribe_to_events(handler)
    }
}

fn has_duplicate_entry<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Ord,
{
    let mut uniq = BTreeSet::new();
    iter.into_iter().any(move |x| !uniq.insert(x))
}

#[cfg(test)]
mod tests;
