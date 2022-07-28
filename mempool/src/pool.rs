use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Debug;
use std::time::Duration;

use mockall::*;
use serialization::Encode;

use common::chain::transaction::Transaction;
use common::chain::transaction::TxInput;
use common::chain::OutPoint;
use common::primitives::amount::Amount;
use common::primitives::Id;
use common::primitives::Idable;
use common::primitives::H256;

use logging::log;

use utils::newtype;

use crate::error::Error;
use crate::error::TxValidationError;
use crate::feerate::FeeRate;
use crate::feerate::INCREMENTAL_RELAY_FEE_RATE;
use crate::feerate::INCREMENTAL_RELAY_THRESHOLD;

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

impl<C, T, M> TryGetFee for MempoolImpl<C, T, M>
where
    C: ChainState,
    T: GetTime,
    M: GetMemoryUsage,
{
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
            .map(|output| output.value())
            .sum::<Option<_>>()
            .ok_or(TxValidationError::OutputValuesOverflow)?;
        (sum_inputs - sum_outputs).ok_or(TxValidationError::InputsBelowOutputs)
    }
}

fn get_relay_fee(tx: &Transaction) -> Amount {
    // TODO we should never reach the expect, but should this be an error anyway?
    Amount::from_atoms(u128::try_from(tx.encoded_size() * RELAY_FEE_PER_BYTE).expect("Overflow"))
}

pub trait Mempool<C, T, M> {
    fn create(chain_state: C, clock: T, memory_usage_estimator: M) -> Self;
    fn add_transaction(&mut self, tx: Transaction) -> Result<(), Error>;
    fn get_all(&self) -> Vec<&Transaction>;
    fn contains_transaction(&self, tx: &Id<Transaction>) -> bool;
    fn drop_transaction(&mut self, tx: &Id<Transaction>);
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
    struct Ancestors(BTreeSet<H256>);
}

newtype! {
    #[derive(Debug)]
    struct Descendants(BTreeSet<H256>);
}

newtype! {
    #[derive(Debug)]
    struct Conflicts(BTreeSet<H256>);
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct TxMempoolEntry {
    tx: Transaction,
    fee: Amount,
    parents: BTreeSet<H256>,
    children: BTreeSet<H256>,
    count_with_descendants: usize,
    fees_with_descendants: Amount,
    creation_time: Time,
}

impl TxMempoolEntry {
    fn new(
        tx: Transaction,
        fee: Amount,
        parents: BTreeSet<H256>,
        creation_time: Time,
    ) -> TxMempoolEntry {
        Self {
            tx,
            fee,
            parents,
            children: BTreeSet::default(),
            count_with_descendants: 1,
            creation_time,
            fees_with_descendants: fee,
        }
    }

    fn count_with_descendants(&self) -> usize {
        self.count_with_descendants
    }

    fn tx_id(&self) -> H256 {
        self.tx.get_id().get()
    }

    fn unconfirmed_parents(&self) -> impl Iterator<Item = &H256> {
        self.parents.iter()
    }

    fn unconfirmed_children(&self) -> impl Iterator<Item = &H256> {
        self.children.iter()
    }

    fn get_children_mut(&mut self) -> &mut BTreeSet<H256> {
        &mut self.children
    }

    fn get_parents_mut(&mut self) -> &mut BTreeSet<H256> {
        &mut self.parents
    }

    fn is_replaceable(&self, store: &MempoolStore) -> bool {
        self.tx.is_replaceable()
            || self
                .unconfirmed_ancestors(store)
                .0
                .iter()
                .any(|ancestor| store.get_entry(ancestor).expect("entry").tx.is_replaceable())
    }

    fn unconfirmed_ancestors(&self, store: &MempoolStore) -> Ancestors {
        let mut visited = Ancestors(BTreeSet::new());
        self.unconfirmed_ancestors_inner(&mut visited, store);
        visited
    }

    fn unconfirmed_ancestors_inner(&self, visited: &mut Ancestors, store: &MempoolStore) {
        for parent in self.parents.iter() {
            if visited.insert(*parent) {
                store
                    .get_entry(parent)
                    .expect("entry")
                    .unconfirmed_ancestors_inner(visited, store);
            }
        }
    }

    fn unconfirmed_descendants(&self, store: &MempoolStore) -> Descendants {
        let mut visited = Descendants(BTreeSet::new());
        self.unconfirmed_descendants_inner(&mut visited, store);
        visited
    }

    fn unconfirmed_descendants_inner(&self, visited: &mut Descendants, store: &MempoolStore) {
        for child in self.children.iter() {
            if visited.insert(*child) {
                store
                    .get_entry(child)
                    .expect("entry")
                    .unconfirmed_descendants_inner(visited, store);
            }
        }
    }
}

impl PartialOrd for TxMempoolEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(other.tx_id().cmp(&self.tx_id()))
    }
}

impl Ord for TxMempoolEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.tx_id().cmp(&self.tx_id())
    }
}

newtype! {
    #[derive(Debug, PartialEq, Eq, Ord, PartialOrd)]
    struct DescendantScore(Amount);
}

#[derive(Clone, Copy, Debug)]
struct RollingFeeRate {
    block_since_last_rolling_fee_bump: bool,
    rolling_minimum_fee_rate: FeeRate,
    last_rolling_fee_update: Time,
}

impl RollingFeeRate {
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
pub struct MempoolImpl<C: ChainState, T: GetTime, M: GetMemoryUsage> {
    store: MempoolStore,
    rolling_fee_rate: Cell<RollingFeeRate>,
    max_size: usize,
    max_tx_age: Duration,
    chain_state: C,
    clock: T,
    memory_usage_estimator: M,
}

#[derive(Debug)]
struct MempoolStore {
    // This is the "main" data structure storing Mempool entries. All other structures in the
    // MempoolStore contain ids (hashes) of entries, sorted according to some order of interest.
    txs_by_id: HashMap<H256, TxMempoolEntry>,

    // Mempool entries sorted by descendant score.
    // We keep this index so that when the mempool grows full, we know which transactions are the
    // most economically reasonable to evict. When an entry is removed from the mempool for
    // fullness reasons, it must be removed together with all of its descendants (as these descendants
    // would no longer be valid to mine). Entries with a lower descendant score will be evicted
    // first.
    //
    // FIXME currently, the descendant score is the sum fee of the transaction to gether with all
    // of its descendants. If we wish to follow Bitcoin Core, we should use:
    // max(feerate(tx, tx_with_descendants)),
    // Where feerate is computed as fee(tx)/size(tx)
    // Note that if we wish to follow Bitcoin Bore, "size" is not simply the encoded size, but
    // rather a value that takes into account witdess and sigop data (see CTxMemPoolEntry::GetTxSize).
    txs_by_descendant_score: BTreeMap<DescendantScore, BTreeSet<H256>>,

    // Entries that have remained in the mempool for a long time (see DEFAULT_MEMPOOL_EXPIRY) are
    // evicted. To efficiently know which entries to evict, we store the mempool entries sorted by
    // their creation time, from earliest to latest.
    txs_by_creation_time: BTreeMap<Time, BTreeSet<H256>>,

    // TODO add txs_by_ancestor_score index, which will be used by the block production subsystem
    // to select the best transactions for the next block
    //
    // We keep the information of which outpoints are spent by entries currently in the mempool.
    // This allows us to recognize conflicts (double-spends) and handle them
    spender_txs: BTreeMap<OutPoint, H256>,
}

impl MempoolStore {
    fn new() -> Self {
        Self {
            txs_by_descendant_score: BTreeMap::new(),
            txs_by_id: HashMap::new(),
            txs_by_creation_time: BTreeMap::new(),
            spender_txs: BTreeMap::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.txs_by_id.is_empty()
        // TODO maybe add some asserts here
    }

    // Checks whether the outpoint is to be created by an unconfirmed tx
    fn contains_outpoint(&self, outpoint: &OutPoint) -> bool {
        matches!(self.txs_by_id.get(&outpoint.tx_id().get_tx_id().expect("Not Coinbase").get()),
            Some(entry) if entry.tx.outputs().len() > outpoint.output_index() as usize)
    }

    fn get_unconfirmed_outpoint_value(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Amount, TxValidationError> {
        let tx_id = *outpoint.tx_id().get_tx_id().expect("Not coinbase");
        let err = || TxValidationError::OutPointNotFound {
            outpoint: outpoint.clone(),
            tx_id,
        };
        self.txs_by_id
            .get(&tx_id.get())
            .ok_or_else(err)
            .and_then(|entry| {
                entry.tx.outputs().get(outpoint.output_index() as usize).ok_or_else(err)
            })
            .map(|output| output.value())
    }

    fn get_entry(&self, id: &H256) -> Option<&TxMempoolEntry> {
        self.txs_by_id.get(id)
    }

    fn append_to_parents(&mut self, entry: &TxMempoolEntry) {
        for parent in entry.unconfirmed_parents() {
            self.txs_by_id
                .get_mut(parent)
                .expect("append_to_parents")
                .get_children_mut()
                .insert(entry.tx_id());
        }
    }

    fn remove_from_parents(&mut self, entry: &TxMempoolEntry) {
        for parent in entry.unconfirmed_parents() {
            self.txs_by_id
                .get_mut(parent)
                .expect("remove_from_parents")
                .get_children_mut()
                .remove(&entry.tx_id());
        }
    }

    fn remove_from_children(&mut self, entry: &TxMempoolEntry) {
        for child in entry.unconfirmed_children() {
            self.txs_by_id
                .get_mut(child)
                .expect("remove_from_children")
                .get_parents_mut()
                .remove(&entry.tx_id());
        }
    }

    fn update_ancestor_state_for_add(&mut self, entry: &TxMempoolEntry) -> Result<(), Error> {
        for ancestor in entry.unconfirmed_ancestors(self).0 {
            let ancestor = self.txs_by_id.get_mut(&ancestor).expect("ancestor");
            ancestor.fees_with_descendants = (ancestor.fees_with_descendants + entry.fee)
                .ok_or(TxValidationError::AncestorFeeUpdateOverflow)?;
            ancestor.count_with_descendants += 1;
        }
        Ok(())
    }

    fn update_ancestor_state_for_drop(&mut self, entry: &TxMempoolEntry) {
        for ancestor in entry.unconfirmed_ancestors(self).0 {
            let ancestor = self.txs_by_id.get_mut(&ancestor).expect("ancestor");
            ancestor.fees_with_descendants =
                (ancestor.fees_with_descendants - entry.fee).expect("fee with descendants");
            ancestor.count_with_descendants -= 1;
        }
    }

    fn mark_outpoints_as_spent(&mut self, entry: &TxMempoolEntry) {
        let id = entry.tx_id();
        for outpoint in entry.tx.inputs().iter().map(|input| input.outpoint()) {
            self.spender_txs.insert(outpoint.clone(), id);
        }
    }

    fn unspend_outpoints(&mut self, entry: &TxMempoolEntry) {
        self.spender_txs.retain(|_, id| *id != entry.tx_id())
    }

    fn add_tx(&mut self, entry: TxMempoolEntry) -> Result<(), Error> {
        self.append_to_parents(&entry);
        self.update_ancestor_state_for_add(&entry)?;
        self.mark_outpoints_as_spent(&entry);

        let creation_time = entry.creation_time;
        let tx_id = entry.tx_id();

        self.txs_by_id.insert(tx_id, entry.clone());

        self.add_to_descendant_score_index(&entry);
        self.txs_by_creation_time.entry(creation_time).or_default().insert(tx_id);
        assert!(self.txs_by_id.get(&tx_id).is_some());
        Ok(())
    }

    fn add_to_descendant_score_index(&mut self, entry: &TxMempoolEntry) {
        self.refresh_ancestors(entry);
        self.txs_by_descendant_score
            .entry(entry.fees_with_descendants.into())
            .or_default()
            .insert(entry.tx_id());
    }

    fn refresh_ancestors(&mut self, entry: &TxMempoolEntry) {
        // Since the ancestors of `entry` have had their descendant score modified, their ordering
        // in txs_by_descendant_score may no longer be correct. We thus remove all ancestors and
        // reinsert them, taking the new, updated fees into account
        let ancestors = entry.unconfirmed_ancestors(self);
        for entries in self.txs_by_descendant_score.values_mut() {
            entries.retain(|id| !ancestors.contains(id))
        }
        for ancestor_id in ancestors.0 {
            let ancestor = self.txs_by_id.get(&ancestor_id).expect("Inconsistent mempool state");
            self.txs_by_descendant_score
                .entry(ancestor.fees_with_descendants.into())
                .or_default()
                .insert(ancestor_id);
        }

        self.txs_by_descendant_score.retain(|_score, txs| !txs.is_empty());
    }

    fn remove_tx(&mut self, tx_id: &Id<Transaction>) {
        log::info!("remove_tx: {}", tx_id.get());
        if let Some(entry) = self.txs_by_id.remove(&tx_id.get()) {
            self.update_for_drop(&entry);
            self.update_ancestor_state_for_drop(&entry);
            self.drop_tx(&entry);
        } else {
            assert!(!self.txs_by_descendant_score.values().flatten().any(|id| *id == tx_id.get()));
            assert!(!self.spender_txs.iter().any(|(_, id)| *id == tx_id.get()));
        }
    }

    fn update_for_drop(&mut self, entry: &TxMempoolEntry) {
        self.remove_from_parents(entry);
        self.remove_from_children(entry);
    }

    fn drop_tx(&mut self, entry: &TxMempoolEntry) {
        self.remove_from_descendant_score_index(entry);
        self.txs_by_creation_time.entry(entry.creation_time).and_modify(|entries| {
            entries.remove(&entry.tx_id()).then(|| ()).expect("Inconsistent mempool store")
        });
        self.unspend_outpoints(entry)
    }

    fn remove_from_descendant_score_index(&mut self, entry: &TxMempoolEntry) {
        self.refresh_ancestors(entry);
        self.txs_by_descendant_score
            .entry(entry.fees_with_descendants.into())
            .or_default()
            .remove(&entry.tx_id());
        if self
            .txs_by_descendant_score
            .get(&entry.fees_with_descendants.into())
            .expect("key must exist")
            .is_empty()
        {
            self.txs_by_descendant_score.remove(&entry.fees_with_descendants.into());
        }
    }

    fn drop_conflicts(&mut self, conflicts: Conflicts) {
        for conflict in conflicts.0 {
            self.remove_tx(&Id::new(conflict))
        }
    }

    fn drop_tx_and_descendants(&mut self, tx_id: Id<Transaction>) {
        if let Some(entry) = self.txs_by_id.get(&tx_id.get()).cloned() {
            let descendants = entry.unconfirmed_descendants(self);
            log::trace!(
                "Dropping tx {} which has {} descendants",
                tx_id.get(),
                descendants.len()
            );
            self.remove_tx(&entry.tx.get_id());
            for descendant_id in descendants.0 {
                // It may be that this descendant has several ancestors and has already been removed
                if let Some(descendant) = self.txs_by_id.get(&descendant_id).cloned() {
                    self.remove_tx(&descendant.tx.get_id())
                }
            }
        }
    }

    fn find_conflicting_tx(&self, outpoint: &OutPoint) -> Option<H256> {
        self.spender_txs.get(outpoint).cloned()
    }
}

impl<C, T, M> MempoolImpl<C, T, M>
where
    C: ChainState,
    T: GetTime,
    M: GetMemoryUsage,
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
            .map(|input| input.outpoint().tx_id().get_tx_id().expect("Not coinbase").get())
            .filter_map(|id| self.store.txs_by_id.contains_key(&id).then(|| id))
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
        (tx_fee >= minimum_fee)
            .then(|| ())
            .ok_or(TxValidationError::RollingFeeThresholdNotMet {
                minimum_fee,
                tx_fee,
            })
    }

    fn pays_minimum_relay_fees(&self, tx: &Transaction) -> Result<(), TxValidationError> {
        let tx_fee = self.try_get_fee(tx)?;
        let relay_fee = get_relay_fee(tx);
        log::debug!("tx_fee: {:?}, relay_fee: {:?}", tx_fee, relay_fee);
        (tx_fee >= relay_fee)
            .then(|| ())
            .ok_or(TxValidationError::InsufficientFeesToRelay { tx_fee, relay_fee })
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
            entry
                .is_replaceable(&self.store)
                .then(|| ())
                .ok_or(TxValidationError::ConflictWithIrreplaceableTransaction)?;
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
        (additional_fees >= relay_fee)
            .then(|| ())
            .ok_or(TxValidationError::InsufficientFeesToRelayRBF)
    }

    fn pays_more_than_conflicts_with_descendants(
        &self,
        tx: &Transaction,
        conflicts_with_descendants: &BTreeSet<H256>,
    ) -> Result<Amount, TxValidationError> {
        let conflicts_with_descendants = conflicts_with_descendants.iter().map(|conflict_id| {
            self.store.txs_by_id.get(conflict_id).expect("tx should exist in mempool")
        });

        let total_conflict_fees = conflicts_with_descendants
            .map(|conflict| conflict.fee)
            .sum::<Option<Amount>>()
            .ok_or(TxValidationError::ConflictsFeeOverflow)?;

        let replacement_fee = self.try_get_fee(tx)?;
        (replacement_fee > total_conflict_fees)
            .then(|| ())
            .ok_or(TxValidationError::TransactionFeeLowerThanConflictsWithDescendants)?;
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
                    original_tx: conflict.tx_id(),
                })
            },
        )
    }

    fn potential_replacements_within_limit(
        &self,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<BTreeSet<H256>, TxValidationError> {
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
        self.store
            .txs_by_id
            .contains_key(&id)
            .then(|| ())
            .ok_or(TxValidationError::DescendantOfExpiredTransaction)?;

        self.limit_mempool_size()?;
        self.store.txs_by_id.contains_key(&id).then(|| ()).ok_or(Error::MempoolFull)
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
            .map(|entry_id| self.store.txs_by_id.get(entry_id).expect("entry should exist"))
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
            let removed =
                self.store.txs_by_id.get(removed_id).expect("tx with id should exist").clone();

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
    fn spends_unconfirmed(&self, mempool: &MempoolImpl<C, T, M>) -> bool;
}

impl<C, T, M> SpendsUnconfirmed<C, T, M> for TxInput
where
    C: ChainState,
    T: GetTime,
    M: GetMemoryUsage,
{
    fn spends_unconfirmed(&self, mempool: &MempoolImpl<C, T, M>) -> bool {
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

impl<C, T, M> Mempool<C, T, M> for MempoolImpl<C, T, M>
where
    C: ChainState,
    T: GetTime,
    M: GetMemoryUsage,
{
    fn create(chain_state: C, clock: T, memory_usage_estimator: M) -> Self {
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
            .map(|id| &self.store.get_entry(id).expect("entry").tx)
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
