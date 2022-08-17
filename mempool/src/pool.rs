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

use std::cell::Cell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::time::Duration;

use common::chain::tokens::OutputValue;
use mockall::*;
use serialization::Encode;

use common::chain::transaction::Transaction;
use common::chain::transaction::TxInput;
use common::chain::OutPoint;
use common::primitives::amount::Amount;
use common::primitives::id::WithId;
use common::primitives::Id;
use common::primitives::Idable;

use logging::log;

use utils::ensure;
use utils::newtype;

use crate::error::Error;
use crate::error::TxValidationError;
use crate::feerate::FeeRate;
use crate::feerate::INCREMENTAL_RELAY_FEE_RATE;
use crate::feerate::INCREMENTAL_RELAY_THRESHOLD;
use store::MempoolStore;
use store::TxMempoolEntry;

mod store;

const ROLLING_FEE_BASE_HALFLIFE: Time = Duration::new(60 * 60 * 12, 1);
// TODO this willbe defined elsewhere (some of limits.rs file)
const MAX_BLOCK_SIZE_BYTES: usize = 1_000_000;

const MAX_BIP125_REPLACEMENT_CANDIDATES: usize = 100;

// TODO this should really be taken from some global node settings
const RELAY_FEE_PER_BYTE: usize = 1;

const MAX_MEMPOOL_SIZE_BYTES: usize = 300_000_000;

const DEFAULT_MEMPOOL_EXPIRY: Duration = Duration::new(336 * 60 * 60, 0);

const ROLLING_FEE_DECAY_INTERVAL: Time = Duration::new(10, 0);

pub(crate) type MemoryUsage = usize;

#[automock]
pub trait GetMemoryUsage {
    fn get_memory_usage(&self) -> MemoryUsage;
}

pub(crate) type Time = Duration;
pub trait GetTime {
    fn get_time(&self) -> Time;
}

impl<C, T, M> TryGetFee for Mempool<C, T, M>
where
    C: ChainState,
    T: GetTime,
    M: GetMemoryUsage,
{
    // TODO this calculation is already done in ChainState, reuse it
    fn try_get_fee(&self, tx: &Transaction) -> Result<Amount, TxValidationError> {
        let inputs = tx
            .inputs()
            .iter()
            .map(|input| {
                let outpoint = input.outpoint();
                self.chain_state
                    .get_outpoint_value(outpoint)
                    .or_else(|_| self.store.get_unconfirmed_outpoint_value(outpoint))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let sum_inputs = inputs
            .iter()
            .cloned()
            .sum::<Option<_>>()
            .ok_or(TxValidationError::InputValuesOverflow)?;
        let sum_outputs = tx
            .outputs()
            .iter()
            .map(|output| match output.value() {
                OutputValue::Coin(coin) => *coin,
            })
            .sum::<Option<_>>()
            .ok_or(TxValidationError::OutputValuesOverflow)?;
        (sum_inputs - sum_outputs).ok_or(TxValidationError::InputsBelowOutputs)
    }
}

fn get_relay_fee(tx: &Transaction) -> Amount {
    // TODO we should never reach the expect, but should this be an error anyway?
    Amount::from_atoms(u128::try_from(tx.encoded_size() * RELAY_FEE_PER_BYTE).expect("Overflow"))
}

pub trait MempoolInterface<C, T, M> {
    fn add_transaction(&mut self, tx: Transaction) -> Result<(), Error>;
    fn get_all(&self) -> Vec<&Transaction>;

    // Returns `true` if the mempool contains a transaction with the given id, `false` otherwise.
    fn contains_transaction(&self, tx: &Id<Transaction>) -> bool;

    // Drops a transaction from the mempool, updating its in-mempool parents and children. This
    // operation removes the transaction from all indices, as well as updating the state (fee,
    // count with descendants) of the transaction's ancestors. In addition, outpoints spent by this
    // transaction are no longer marked as spent
    fn drop_transaction(&mut self, tx: &Id<Transaction>);

    // Add/remove transactions to/from the mempool according to a new tip
    fn new_tip_set(&mut self, chain_state: C);
}

pub trait ChainState: Debug {
    fn contains_outpoint(&self, outpoint: &OutPoint) -> bool;
    fn get_outpoint_value(&self, outpoint: &OutPoint) -> Result<Amount, anyhow::Error>;
}

trait TryGetFee {
    fn try_get_fee(&self, tx: &Transaction) -> Result<Amount, TxValidationError>;
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

#[derive(Clone, Copy, Debug)]
struct RollingFeeRate {
    block_since_last_rolling_fee_bump: bool,
    rolling_minimum_fee_rate: FeeRate,
    last_rolling_fee_update: Time,
}

impl RollingFeeRate {
    #[allow(clippy::float_arithmetic)]
    fn decay_fee(mut self, halflife: Time, current_time: Time) -> Self {
        log::trace!(
            "decay_fee: old fee rate:  {:?}\nCurrent time: {:?}\nLast Rolling Fee Update: {:?}\nHalflife: {:?}",
            self.rolling_minimum_fee_rate,
            self.last_rolling_fee_update,
            current_time,
            halflife,
        );

        let divisor = ((current_time.as_secs() - self.last_rolling_fee_update.as_secs()) as f64
            / (halflife.as_secs() as f64))
            .exp2();
        self.rolling_minimum_fee_rate = FeeRate::new(Amount::from_atoms(
            (self.rolling_minimum_fee_rate.atoms_per_kb() as f64 / divisor) as u128,
        ));

        log::trace!(
            "decay_fee: new fee rate:  {:?}",
            self.rolling_minimum_fee_rate
        );
        self.last_rolling_fee_update = current_time;
        self
    }
}

impl RollingFeeRate {
    pub(crate) fn new(creation_time: Time) -> Self {
        Self {
            block_since_last_rolling_fee_bump: false,
            rolling_minimum_fee_rate: FeeRate::new(Amount::from_atoms(0)),
            last_rolling_fee_update: creation_time,
        }
    }
}

#[derive(Debug)]
pub struct Mempool<C: ChainState, T: GetTime, M: GetMemoryUsage> {
    store: MempoolStore,
    rolling_fee_rate: Cell<RollingFeeRate>,
    max_size: usize,
    max_tx_age: Duration,
    chain_state: C,
    clock: T,
    memory_usage_estimator: M,
}

impl<C, T, M> Mempool<C, T, M>
where
    C: ChainState,
    T: GetTime,
    M: GetMemoryUsage,
{
    pub(crate) fn new(chain_state: C, clock: T, memory_usage_estimator: M) -> Self {
        Self {
            store: MempoolStore::new(),
            chain_state,
            max_size: MAX_MEMPOOL_SIZE_BYTES,
            max_tx_age: DEFAULT_MEMPOOL_EXPIRY,
            rolling_fee_rate: Cell::new(RollingFeeRate::new(clock.get_time())),
            clock,
            memory_usage_estimator,
        }
    }

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

    pub(crate) fn update_min_fee_rate(&self, rate: FeeRate) {
        let mut rolling_fee_rate = self.rolling_fee_rate.get();
        rolling_fee_rate.rolling_minimum_fee_rate = rate;
        rolling_fee_rate.block_since_last_rolling_fee_bump = false;
        self.rolling_fee_rate.set(rolling_fee_rate)
    }

    pub(crate) fn get_update_min_fee_rate(&self) -> FeeRate {
        let rolling_fee_rate = self.rolling_fee_rate.get();
        if !rolling_fee_rate.block_since_last_rolling_fee_bump
            || rolling_fee_rate.rolling_minimum_fee_rate == FeeRate::new(Amount::from_atoms(0))
        {
            return rolling_fee_rate.rolling_minimum_fee_rate;
        } else if self.clock.get_time()
            > rolling_fee_rate.last_rolling_fee_update + ROLLING_FEE_DECAY_INTERVAL
        {
            // Decay the rolling fee
            self.decay_rolling_fee_rate();
            log::debug!(
                "rolling fee rate after decay_rolling_fee_rate {:?}",
                self.rolling_fee_rate
            );

            if self.rolling_fee_rate.get().rolling_minimum_fee_rate < *INCREMENTAL_RELAY_THRESHOLD {
                log::trace!("rolling fee rate {:?} less than half of the incremental fee rate, dropping the fee", self.rolling_fee_rate.get().rolling_minimum_fee_rate);
                self.drop_rolling_fee();
                return self.rolling_fee_rate.get().rolling_minimum_fee_rate;
            }
        }

        std::cmp::max(
            self.rolling_fee_rate.get().rolling_minimum_fee_rate,
            *INCREMENTAL_RELAY_FEE_RATE,
        )
    }

    fn drop_rolling_fee(&self) {
        let mut rolling_fee_rate = self.rolling_fee_rate.get();
        rolling_fee_rate.rolling_minimum_fee_rate = FeeRate::new(Amount::from_atoms(0));
        self.rolling_fee_rate.set(rolling_fee_rate)
    }

    fn decay_rolling_fee_rate(&self) {
        let halflife = self.rolling_fee_halflife();
        let time = self.clock.get_time();
        self.rolling_fee_rate.set(self.rolling_fee_rate.get().decay_fee(halflife, time));
    }

    fn verify_inputs_available(&self, tx: &Transaction) -> Result<(), TxValidationError> {
        tx.inputs()
            .iter()
            .map(TxInput::outpoint)
            .find(|outpoint| !self.outpoint_available(outpoint))
            .map_or_else(
                || Ok(()),
                |outpoint| {
                    Err(TxValidationError::OutPointNotFound {
                        outpoint: outpoint.clone(),
                        tx_id: tx.get_id(),
                    })
                },
            )
    }

    fn outpoint_available(&self, outpoint: &OutPoint) -> bool {
        self.store.contains_outpoint(outpoint) || self.chain_state.contains_outpoint(outpoint)
    }

    fn create_entry(&self, tx: Transaction) -> Result<TxMempoolEntry, TxValidationError> {
        let parents = tx
            .inputs()
            .iter()
            .map(|input| *input.outpoint().tx_id().get_tx_id().expect("Not coinbase"))
            .filter_map(|id| self.store.txs_by_id.contains_key(&id.get()).then(|| id))
            .collect::<BTreeSet<_>>();

        let fee = self.try_get_fee(&tx)?;
        let time = self.clock.get_time();
        Ok(TxMempoolEntry::new(tx, fee, parents, time))
    }

    fn get_update_minimum_mempool_fee(&self, tx: &Transaction) -> Amount {
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

    fn validate_transaction(&self, tx: &Transaction) -> Result<Conflicts, TxValidationError> {
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

        if tx.inputs().is_empty() {
            return Err(TxValidationError::NoInputs);
        }

        if tx.outputs().is_empty() {
            return Err(TxValidationError::NoOutputs);
        }

        let outpoints = tx.inputs().iter().map(|input| input.outpoint()).cloned();

        if has_duplicate_entry(outpoints) {
            return Err(TxValidationError::DuplicateInputs);
        }

        // TODO see this issue:
        // https://github.com/mintlayer/mintlayer-core/issues/331
        if tx.encoded_size() > MAX_BLOCK_SIZE_BYTES {
            return Err(TxValidationError::ExceedsMaxBlockSize);
        }

        if self.contains_transaction(&tx.get_id()) {
            return Err(TxValidationError::TransactionAlreadyInMempool);
        }

        let conflicts = self.rbf_checks(tx)?;

        self.verify_inputs_available(tx)?;

        self.pays_minimum_relay_fees(tx)?;

        self.pays_minimum_mempool_fee(tx)?;

        Ok(conflicts)
    }

    fn pays_minimum_mempool_fee(&self, tx: &Transaction) -> Result<(), TxValidationError> {
        let tx_fee = self.try_get_fee(tx)?;
        let minimum_fee = self.get_update_minimum_mempool_fee(tx);
        ensure!(
            tx_fee >= minimum_fee,
            TxValidationError::RollingFeeThresholdNotMet {
                minimum_fee,
                tx_fee,
            }
        );
        Ok(())
    }

    fn pays_minimum_relay_fees(&self, tx: &Transaction) -> Result<(), TxValidationError> {
        let tx_fee = self.try_get_fee(tx)?;
        let relay_fee = get_relay_fee(tx);
        log::debug!("tx_fee: {:?}, relay_fee: {:?}", tx_fee, relay_fee);
        ensure!(
            tx_fee >= relay_fee,
            TxValidationError::InsufficientFeesToRelay { tx_fee, relay_fee }
        );
        Ok(())
    }

    fn rbf_checks(&self, tx: &Transaction) -> Result<Conflicts, TxValidationError> {
        let conflicts = tx
            .inputs()
            .iter()
            .filter_map(|input| self.store.find_conflicting_tx(input.outpoint()))
            .map(|id_conflict| self.store.get_entry(&id_conflict).expect("entry for id"))
            .collect::<Vec<_>>();

        if conflicts.is_empty() {
            Ok(Conflicts(BTreeSet::new()))
        } else {
            self.do_rbf_checks(tx, &conflicts)
        }
    }

    fn do_rbf_checks(
        &self,
        tx: &Transaction,
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
        tx: &Transaction,
        total_conflict_fees: Amount,
    ) -> Result<(), TxValidationError> {
        log::debug!("pays_for_bandwidth: tx fee is {:?}", self.try_get_fee(tx)?);
        let additional_fees = (self.try_get_fee(tx)? - total_conflict_fees)
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

    fn pays_more_than_conflicts_with_descendants(
        &self,
        tx: &Transaction,
        conflicts_with_descendants: &BTreeSet<Id<Transaction>>,
    ) -> Result<Amount, TxValidationError> {
        let conflicts_with_descendants = conflicts_with_descendants.iter().map(|conflict_id| {
            self.store
                .txs_by_id
                .get(&conflict_id.get())
                .expect("tx should exist in mempool")
        });

        let total_conflict_fees = conflicts_with_descendants
            .map(|conflict| conflict.fee)
            .sum::<Option<Amount>>()
            .ok_or(TxValidationError::ConflictsFeeOverflow)?;

        let replacement_fee = self.try_get_fee(tx)?;
        ensure!(
            replacement_fee > total_conflict_fees,
            TxValidationError::TransactionFeeLowerThanConflictsWithDescendants
        );
        Ok(total_conflict_fees)
    }

    fn spends_no_new_unconfirmed_outputs(
        &self,
        tx: &Transaction,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), TxValidationError> {
        let outpoints_spent_by_conflicts = conflicts
            .iter()
            .flat_map(|conflict| conflict.tx.inputs().iter().map(|input| input.outpoint()))
            .collect::<BTreeSet<_>>();

        tx.inputs()
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

    fn pays_more_than_direct_conflicts(
        &self,
        tx: &Transaction,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), TxValidationError> {
        let replacement_fee = self.try_get_fee(tx)?;
        conflicts.iter().find(|conflict| conflict.fee >= replacement_fee).map_or_else(
            || Ok(()),
            |conflict| {
                Err(TxValidationError::ReplacementFeeLowerThanOriginal {
                    replacement_tx: tx.get_id().get(),
                    replacement_fee,
                    original_fee: conflict.fee,
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

    fn finalize_tx(&mut self, tx: Transaction) -> Result<(), Error> {
        let entry = self.create_entry(tx)?;
        let id = entry.tx.get_id().get();
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
        let removed_fees = self.trim();
        if !removed_fees.is_empty() {
            let new_minimum_fee_rate =
                *removed_fees.iter().max().expect("removed_fees should not be empty")
                    + *INCREMENTAL_RELAY_FEE_RATE;
            if new_minimum_fee_rate > self.rolling_fee_rate.get().rolling_minimum_fee_rate {
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
            .map(|entry_id| self.store.txs_by_id.get(&entry_id.get()).expect("entry should exist"))
            .filter(|entry| {
                let now = self.clock.get_time();
                let expired = now.saturating_sub(entry.creation_time) > self.max_tx_age;
                if expired {
                    log::trace!(
                        "Evicting tx {} which was created at {:?}. It is now {:?}",
                        entry.tx_id(),
                        entry.creation_time,
                        now
                    );
                    true
                } else {
                    false
                }
            })
            .cloned()
            .collect();

        for tx_id in expired.iter().map(|entry| entry.tx.get_id()) {
            self.store.drop_tx_and_descendants(tx_id)
        }
    }

    fn trim(&mut self) -> Vec<FeeRate> {
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
            let removed = self
                .store
                .txs_by_id
                .get(&removed_id.get())
                .expect("tx with id should exist")
                .clone();

            log::debug!(
                "Mempool trim: Evicting tx {} which has a descendant score of {:?} and has size {}",
                removed.tx_id(),
                removed.fees_with_descendants,
                removed.tx.encoded_size()
            );
            removed_fees.push(FeeRate::from_total_tx_fee(
                removed.fee,
                removed.tx.encoded_size(),
            ));
            self.store.drop_tx_and_descendants(removed.tx.get_id());
        }
        removed_fees
    }
}

trait SpendsUnconfirmed<C, T, M>
where
    C: ChainState,
    T: GetTime,
    M: GetMemoryUsage,
{
    fn spends_unconfirmed(&self, mempool: &Mempool<C, T, M>) -> bool;
}

impl<C, T, M> SpendsUnconfirmed<C, T, M> for TxInput
where
    C: ChainState,
    T: GetTime,
    M: GetMemoryUsage,
{
    fn spends_unconfirmed(&self, mempool: &Mempool<C, T, M>) -> bool {
        mempool.contains_transaction(self.outpoint().tx_id().get_tx_id().expect("Not coinbase"))
    }
}

#[derive(Clone)]
struct SystemClock;
impl GetTime for SystemClock {
    fn get_time(&self) -> Duration {
        common::primitives::time::get()
    }
}

#[derive(Clone)]
struct SystemUsageEstimator;
impl GetMemoryUsage for SystemUsageEstimator {
    fn get_memory_usage(&self) -> MemoryUsage {
        //TODO implement real usage estimation here
        0
    }
}

impl<C, T, M> MempoolInterface<C, T, M> for Mempool<C, T, M>
where
    C: ChainState,
    T: GetTime,
    M: GetMemoryUsage,
{
    fn new_tip_set(&mut self, chain_state: C) {
        self.chain_state = chain_state;
        self.rolling_fee_rate.set({
            let mut rolling_fee_rate = self.rolling_fee_rate.get();
            // TODO Not sure we should set the flag to true when a block is disconnected/during a
            // reorg
            rolling_fee_rate.block_since_last_rolling_fee_bump = true;
            rolling_fee_rate
        })
    }
    //

    fn add_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
        let conflicts = self.validate_transaction(&tx)?;
        self.store.drop_conflicts(conflicts);
        self.finalize_tx(tx)?;
        Ok(())
    }

    fn get_all(&self) -> Vec<&Transaction> {
        self.store
            .txs_by_descendant_score
            .values()
            .flatten()
            .map(|id| WithId::get(&self.store.get_entry(id).expect("entry").tx))
            .collect()
    }

    fn contains_transaction(&self, tx_id: &Id<Transaction>) -> bool {
        self.store.txs_by_id.contains_key(&tx_id.get())
    }

    // TODO Consider returning an error
    fn drop_transaction(&mut self, tx_id: &Id<Transaction>) {
        self.store.remove_tx(tx_id);
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
