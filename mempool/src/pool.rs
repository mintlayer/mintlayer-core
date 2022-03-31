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
pub trait GetMemoryUsage: 'static {
    fn get_memory_usage(&self) -> MemoryUsage;
}

pub(crate) type Time = Duration;
pub trait GetTime: Clone + 'static {
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

pub trait ChainState: Debug + 'static {
    fn contains_outpoint(&self, outpoint: &OutPoint) -> bool;
    fn get_outpoint_value(&self, outpoint: &OutPoint) -> Result<Amount, anyhow::Error>;
}

trait TryGetFee {
    fn try_get_fee(&self, tx: &Transaction) -> Result<Amount, TxValidationError>;
}

newtype!(
    #[derive(Debug)]
    struct Ancestors(BTreeSet<H256>)
);

newtype!(
    #[derive(Debug)]
    struct Descendants(BTreeSet<H256>)
);

newtype!(
    #[derive(Debug)]
    struct Conflicts(BTreeSet<H256>)
);

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
            if visited.0.contains(parent) {
                continue;
            } else {
                visited.0.insert(*parent);
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
            if visited.0.contains(child) {
                continue;
            } else {
                visited.0.insert(*child);
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

newtype!(
    #[derive(Debug, PartialEq, Eq, Ord, PartialOrd)]
    struct DescendantScore(Amount)
);

#[derive(Clone, Copy, Debug)]
struct RollingFeeRate {
    block_since_last_rolling_fee_bump: bool,
    rolling_minimum_fee_rate: FeeRate,
    last_rolling_fee_update: Time,
}

impl RollingFeeRate {
    fn decay_fee(mut self, halflife: Time, current_time: Time) -> Result<Self, TxValidationError> {
        log::trace!(
            "decay_fee: old fee rate:  {:?}\nCurrent time: {:?}\nLast Rolling Fee Update: {:?}\nHalflife: {:?}",
            self.rolling_minimum_fee_rate,
            self.last_rolling_fee_update,
            current_time,
            halflife,
        );

        let divisor = 2f64.powf(
            (current_time.as_secs() - self.last_rolling_fee_update.as_secs()) as f64
                / (halflife.as_secs() as f64),
        );
        self.rolling_minimum_fee_rate =
            FeeRate::new(self.rolling_minimum_fee_rate.tokens_per_byte().div_by_float(divisor));

        log::trace!(
            "decay_fee: new fee rate:  {:?}",
            self.rolling_minimum_fee_rate
        );
        self.last_rolling_fee_update = current_time;
        Ok(self)
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
    txs_by_id: HashMap<H256, TxMempoolEntry>,
    txs_by_descendant_score: BTreeMap<DescendantScore, BTreeSet<H256>>,
    txs_by_creation_time: BTreeMap<Time, BTreeSet<H256>>,
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

    pub(crate) fn get_update_min_fee_rate(&self) -> Result<FeeRate, TxValidationError> {
        let rolling_fee_rate = self.rolling_fee_rate.get();
        if !rolling_fee_rate.block_since_last_rolling_fee_bump
            || rolling_fee_rate.rolling_minimum_fee_rate == FeeRate::new(Amount::from_atoms(0))
        {
            return Ok(rolling_fee_rate.rolling_minimum_fee_rate);
        } else if self.clock.get_time()
            > rolling_fee_rate.last_rolling_fee_update + ROLLING_FEE_DECAY_INTERVAL
        {
            // Decay the rolling fee
            self.decay_rolling_fee_rate()?;
            log::debug!(
                "rolling fee rate after decay_rolling_fee_rate {:?}",
                self.rolling_fee_rate
            );

            if self.rolling_fee_rate.get().rolling_minimum_fee_rate
                < (*INCREMENTAL_RELAY_FEE_RATE / FeeRate::new(Amount::from_atoms(2)))
                    .expect("not division by zero")
            {
                log::trace!("rolling fee rate {:?} less than half of the incremental fee rate, dropping the fee", self.rolling_fee_rate.get().rolling_minimum_fee_rate);
                self.drop_rolling_fee();
                return Ok(self.rolling_fee_rate.get().rolling_minimum_fee_rate);
            }
        }

        Ok(std::cmp::max(
            self.rolling_fee_rate.get().rolling_minimum_fee_rate,
            *INCREMENTAL_RELAY_FEE_RATE,
        ))
    }

    fn drop_rolling_fee(&self) {
        let mut rolling_fee_rate = self.rolling_fee_rate.get();
        rolling_fee_rate.rolling_minimum_fee_rate = FeeRate::new(Amount::from_atoms(0));
        self.rolling_fee_rate.set(rolling_fee_rate)
    }

    fn decay_rolling_fee_rate(&self) -> Result<(), TxValidationError> {
        let halflife = self.rolling_fee_halflife();
        let time = self.clock.get_time();
        self.rolling_fee_rate
            .set(self.rolling_fee_rate.get().decay_fee(halflife, time)?);
        Ok(())
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

    fn get_update_minimum_mempool_fee(
        &self,
        tx: &Transaction,
    ) -> Result<Amount, TxValidationError> {
        let minimum_fee_rate = self.get_update_min_fee_rate()?;
        log::debug!("minimum fee rate {:?}", minimum_fee_rate);
        log::debug!("tx_size: {:?}", tx.encoded_size());

        minimum_fee_rate.compute_fee(tx.encoded_size())
    }

    fn validate_transaction(&self, tx: &Transaction) -> Result<Conflicts, TxValidationError> {
        if tx.inputs().is_empty() {
            return Err(TxValidationError::NoInputs);
        }

        if tx.outputs().is_empty() {
            return Err(TxValidationError::NoOutputs);
        }

        // TODO consier a MAX_MONEY check reminiscent of bitcoin's
        // TODO consider rejecting non-standard transactions (for some definition of standard)

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
        let minimum_fee = self.get_update_minimum_mempool_fee(tx)?;
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
        eprintln!("tx_fee: {:?}, relay_fee: {:?}", tx_fee, relay_fee);
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
        let additional_fees = (self.try_get_fee(tx)? - total_conflict_fees)
            .ok_or(TxValidationError::AdditionalFeesUnderflow)?;
        let relay_fee = get_relay_fee(tx);
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

    fn finalize_tx(&mut self, tx: Transaction, conflicts: Conflicts) -> Result<(), Error> {
        self.store.drop_conflicts(conflicts);
        let entry = self.create_entry(tx)?;
        let id = entry.tx.get_id().get();
        self.store.add_tx(entry)?;
        self.limit_mempool_size()?;
        self.store.txs_by_id.contains_key(&id).then(|| ()).ok_or(Error::MempoolFull)
    }

    fn limit_mempool_size(&mut self) -> Result<(), Error> {
        self.remove_expired_transactions();
        let removed_fees = self.trim()?;
        if !removed_fees.is_empty() {
            let new_minimum_fee_rate =
                (*removed_fees.iter().max().expect("removed_fees should not be empty")
                    + *INCREMENTAL_RELAY_FEE_RATE)
                    .ok_or(TxValidationError::FeeRateError)?;
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
                if now - entry.creation_time > self.max_tx_age {
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

    fn trim(&mut self) -> Result<Vec<FeeRate>, Error> {
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
            removed_fees.push(FeeRate::of_tx(removed.fee, removed.tx.encoded_size())?);
            self.store.drop_tx_and_descendants(removed.tx.get_id());
        }
        Ok(removed_fees)
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
        self.finalize_tx(tx, conflicts)?;
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
mod tests {
    use super::*;
    use common::chain::signature::inputsig::InputWitness;
    use common::chain::transaction::{Destination, TxInput, TxOutput};
    use common::chain::OutPointSourceId;
    use common::chain::OutputPurpose;
    use core::panic;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    const DUMMY_WITNESS_MSG: &[u8] = b"dummy_witness_msg";

    #[derive(Debug, PartialEq, Eq, Clone)]
    struct ValuedOutPoint {
        outpoint: OutPoint,
        value: Amount,
    }

    impl std::cmp::PartialOrd for ValuedOutPoint {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            other.value.partial_cmp(&self.value)
        }
    }

    impl std::cmp::Ord for ValuedOutPoint {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            other.value.cmp(&self.value)
        }
    }

    fn dummy_input() -> TxInput {
        let outpoint_source_id = OutPointSourceId::Transaction(Id::new(H256::zero()));
        let output_index = 0;
        let witness = DUMMY_WITNESS_MSG.to_vec();
        TxInput::new(
            outpoint_source_id,
            output_index,
            InputWitness::NoSignature(Some(witness)),
        )
    }

    fn dummy_output() -> TxOutput {
        let value = Amount::from_atoms(0);
        let purpose = OutputPurpose::Transfer(Destination::AnyoneCanSpend);
        TxOutput::new(value, purpose)
    }

    fn estimate_tx_size(num_inputs: usize, num_outputs: usize) -> usize {
        let inputs = (0..num_inputs).into_iter().map(|_| dummy_input()).collect();
        let outputs = (0..num_outputs).into_iter().map(|_| dummy_output()).collect();
        let flags = 0;
        let locktime = 0;
        let size = Transaction::new(flags, inputs, outputs, locktime).unwrap().encoded_size();
        // Take twice the encoded size of the dummy tx.Real Txs are larger than these dummy ones,
        // but taking 3 times the size seems to ensure our txs won't fail the minimum relay fee
        // validation (see the function `pays_minimum_relay_fees`)
        let result = 3 * size;
        log::debug!(
            "estimated size for tx with {} inputs and {} outputs: {}",
            num_inputs,
            num_outputs,
            result
        );
        result
    }

    #[test]
    fn dummy_size() {
        logging::init_logging::<&str>(None);
        log::debug!("1, 1: {}", estimate_tx_size(1, 1));
        log::debug!("1, 2: {}", estimate_tx_size(1, 2));
        log::debug!("1, 400: {}", estimate_tx_size(1, 400));
    }

    #[test]
    fn real_size() -> anyhow::Result<()> {
        let mempool = setup();
        let tx = TxGenerator::new()
            .with_num_inputs(1)
            .with_num_outputs(400)
            .generate_tx(&mempool)?;
        log::debug!("real size of tx {}", tx.encoded_size());
        Ok(())
    }

    fn valued_outpoint(
        tx_id: &Id<Transaction>,
        outpoint_index: u32,
        output: &TxOutput,
    ) -> ValuedOutPoint {
        let outpoint_source_id = OutPointSourceId::Transaction(*tx_id);
        let outpoint = OutPoint::new(outpoint_source_id, outpoint_index);
        let value = output.value();
        ValuedOutPoint { outpoint, value }
    }

    pub(crate) fn create_genesis_tx() -> Transaction {
        const TOTAL_SUPPLY: u128 = 10_000_000_000_000;
        let genesis_message = b"".to_vec();
        let outpoint_source_id = OutPointSourceId::Transaction(Id::new(H256::zero()));
        let input = TxInput::new(
            outpoint_source_id,
            0,
            InputWitness::NoSignature(Some(genesis_message)),
        );
        let output = TxOutput::new(
            Amount::from_atoms(TOTAL_SUPPLY),
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        );
        Transaction::new(0, vec![input], vec![output], 0)
            .expect("Failed to create genesis coinbase transaction")
    }

    impl TxMempoolEntry {
        fn outpoints_created(&self) -> BTreeSet<ValuedOutPoint> {
            let id = self.tx.get_id();
            std::iter::repeat(id)
                .zip(self.tx.outputs().iter().enumerate())
                .map(|(id, (index, output))| valued_outpoint(&id, index as u32, output))
                .collect()
        }
    }

    impl MempoolStore {
        fn unconfirmed_outpoints(&self) -> BTreeSet<ValuedOutPoint> {
            self.txs_by_id
                .values()
                .cloned()
                .flat_map(|entry| entry.outpoints_created())
                .collect()
        }
    }

    impl<T, M> MempoolImpl<ChainStateMock, T, M>
    where
        T: GetTime,
        M: GetMemoryUsage,
    {
        fn available_outpoints(&self, allow_double_spend: bool) -> BTreeSet<ValuedOutPoint> {
            let mut available = self
                .store
                .unconfirmed_outpoints()
                .into_iter()
                .chain(self.chain_state.confirmed_outpoints())
                .collect::<BTreeSet<_>>();
            if !allow_double_spend {
                available.retain(|valued_outpoint| {
                    !self.store.spender_txs.contains_key(&valued_outpoint.outpoint)
                });
            }
            available
        }

        fn get_input_value(&self, input: &TxInput) -> anyhow::Result<Amount> {
            let allow_double_spend = true;
            self.available_outpoints(allow_double_spend)
                .iter()
                .find_map(|valued_outpoint| {
                    (valued_outpoint.outpoint == *input.outpoint()).then(|| valued_outpoint.value)
                })
                .ok_or_else(|| anyhow::anyhow!("No such unconfirmed output"))
        }

        fn get_minimum_rolling_fee(&self) -> FeeRate {
            self.rolling_fee_rate.get().rolling_minimum_fee_rate
        }

        fn process_block(&mut self, tx_id: &Id<Transaction>) -> anyhow::Result<()> {
            let mut chain_state = self.chain_state.clone();
            chain_state.add_confirmed_tx(
                self.store
                    .txs_by_id
                    .get(&tx_id.get())
                    .cloned()
                    .ok_or_else(|| {
                        anyhow::anyhow!("process_block: tx {} not found in mempool", tx_id.get())
                    })?
                    .tx,
            );
            log::debug!("Setting tip to {:?}", chain_state);
            self.new_tip_set(chain_state);
            self.drop_transaction(tx_id);
            Ok(())
        }
    }

    #[derive(Debug, Clone)]
    pub(crate) struct ChainStateMock {
        confirmed_txs: HashMap<H256, Transaction>,
        available_outpoints: BTreeSet<OutPoint>,
    }

    impl ChainStateMock {
        pub(crate) fn new() -> Self {
            let genesis_tx = create_genesis_tx();
            let outpoint_source_id = OutPointSourceId::Transaction(genesis_tx.get_id());
            let outpoints = genesis_tx
                .outputs()
                .iter()
                .enumerate()
                .map(|(index, _)| OutPoint::new(outpoint_source_id.clone(), index as u32))
                .collect();
            Self {
                confirmed_txs: std::iter::once((genesis_tx.get_id().get(), genesis_tx)).collect(),
                available_outpoints: outpoints,
            }
        }

        fn confirmed_txs(&self) -> &HashMap<H256, Transaction> {
            &self.confirmed_txs
        }

        fn confirmed_outpoints(&self) -> BTreeSet<ValuedOutPoint> {
            self.available_outpoints
                .iter()
                .map(|outpoint| {
                    let tx_id = outpoint
                        .tx_id()
                        .get_tx_id()
                        .cloned()
                        .expect("Outpoints in these tests are created from TXs");
                    let index = outpoint.output_index();
                    let tx =
                        self.confirmed_txs.get(&tx_id.get()).expect("Inconsistent Chain State");
                    let output = tx
                        .outputs()
                        .get(index as usize)
                        .expect("Inconsistent Chain State: output not found");

                    valued_outpoint(&tx_id, index, output)
                })
                .collect()
        }

        fn add_confirmed_tx(&mut self, tx: Transaction) {
            let outpoints_spent: BTreeSet<_> =
                tx.inputs().iter().map(|input| input.outpoint()).collect();
            let outpoints_created: BTreeSet<_> = tx
                .outputs()
                .iter()
                .enumerate()
                .map(|(i, _)| OutPoint::new(OutPointSourceId::Transaction(tx.get_id()), i as u32))
                .collect();
            self.available_outpoints.extend(outpoints_created);
            self.available_outpoints.retain(|outpoint| !outpoints_spent.contains(outpoint));
            self.confirmed_txs.insert(tx.get_id().get(), tx);
        }
    }

    impl ChainState for ChainStateMock {
        fn contains_outpoint(&self, outpoint: &OutPoint) -> bool {
            self.available_outpoints.iter().any(|value| *value == *outpoint)
        }

        fn get_outpoint_value(&self, outpoint: &OutPoint) -> Result<Amount, anyhow::Error> {
            self.confirmed_txs
                .get(&outpoint.tx_id().get_tx_id().expect("Not coinbase").get())
                .ok_or_else(|| anyhow::anyhow!("tx for outpoint sought in chain state, not found"))
                .and_then(|tx| {
                    tx.outputs()
                        .get(outpoint.output_index() as usize)
                        .ok_or_else(|| anyhow::anyhow!("outpoint index out of bounds"))
                        .map(|output| output.value())
                })
        }
    }

    /* FIXME The second call in the following flow sometimes returns TransactionAlreadyInMempool
    let tx1 = TxGenerator::new(&mempool).generate_tx()?;
    mempool.add_transaction(tx1)?;

    let tx2 = TxGenerator::new(&mempool).generate_tx()?;
    mempool.add_transaction(tx2)?;
    */
    struct TxGenerator {
        coin_pool: BTreeSet<ValuedOutPoint>,
        num_inputs: usize,
        num_outputs: usize,
        tx_fee: Option<Amount>,
        replaceable: bool,
        allow_double_spend: bool,
    }

    impl TxGenerator {
        fn with_num_inputs(mut self, num_inputs: usize) -> Self {
            self.num_inputs = num_inputs;
            self
        }

        fn with_num_outputs(mut self, num_outputs: usize) -> Self {
            self.num_outputs = num_outputs;
            self
        }

        fn replaceable(mut self) -> Self {
            self.replaceable = true;
            self
        }

        fn with_fee(mut self, fee: Amount) -> Self {
            self.tx_fee = Some(fee);
            self
        }

        fn new() -> Self {
            Self {
                coin_pool: BTreeSet::new(),
                num_inputs: 1,
                num_outputs: 1,
                tx_fee: None,
                replaceable: false,
                allow_double_spend: false,
            }
        }

        fn generate_tx<T: GetTime, M: GetMemoryUsage>(
            &mut self,
            mempool: &MempoolImpl<ChainStateMock, T, M>,
        ) -> anyhow::Result<Transaction> {
            self.coin_pool = mempool.available_outpoints(self.allow_double_spend);
            let fee = if let Some(tx_fee) = self.tx_fee {
                tx_fee
            } else {
                Amount::from_atoms(get_relay_fee_from_tx_size(estimate_tx_size(
                    self.num_inputs,
                    self.num_outputs,
                )))
            };
            log::debug!(
                "Trying to build a tx with {} inputs, {} outputs, and a fee of {:?}",
                self.num_inputs,
                self.num_outputs,
                fee
            );
            let valued_inputs = self.generate_tx_inputs(fee)?;
            let outputs = self.generate_tx_outputs(&valued_inputs, fee)?;
            let locktime = 0;
            let flags = if self.replaceable { 1 } else { 0 };
            let (inputs, _): (Vec<TxInput>, Vec<Amount>) = valued_inputs.into_iter().unzip();
            let spent_outpoints =
                inputs.iter().map(|input| input.outpoint()).collect::<BTreeSet<_>>();
            self.coin_pool.retain(|outpoint| {
                !spent_outpoints.iter().any(|spent| **spent == outpoint.outpoint)
            });
            let tx = Transaction::new(flags, inputs, outputs.clone(), locktime)
                .map_err(anyhow::Error::from)?;
            self.coin_pool.extend(
                std::iter::repeat(tx.get_id())
                    .zip(outputs.iter().enumerate())
                    .map(|(id, (i, output))| valued_outpoint(&id, i as u32, output)),
            );

            Ok(tx)
        }

        fn generate_tx_inputs(&mut self, fee: Amount) -> anyhow::Result<Vec<(TxInput, Amount)>> {
            Ok(self
                .get_unspent_outpoints(self.num_inputs, fee)?
                .iter()
                .map(|valued_outpoint| {
                    let ValuedOutPoint { outpoint, value } = valued_outpoint;
                    (
                        TxInput::new(
                            outpoint.tx_id(),
                            outpoint.output_index(),
                            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
                        ),
                        *value,
                    )
                })
                .collect())
        }

        fn generate_tx_outputs(
            &self,
            inputs: &[(TxInput, Amount)],
            tx_fee: Amount,
        ) -> anyhow::Result<Vec<TxOutput>> {
            if self.num_outputs == 0 {
                return Ok(vec![]);
            }

            let inputs: Vec<_> = inputs.to_owned();
            let (inputs, values): (Vec<TxInput>, Vec<Amount>) = inputs.into_iter().unzip();
            if inputs.is_empty() {
                return Ok(vec![]);
            }
            let sum_of_inputs =
                values.into_iter().sum::<Option<_>>().expect("Overflow in sum of input values");

            let total_to_spend = (sum_of_inputs - tx_fee).ok_or_else(||anyhow::anyhow!(
                "generate_tx_outputs: underflow computing total_to_spend - sum_of_inputs = {:?}, fee = {:?}", sum_of_inputs, tx_fee
            ))?;

            let value = (sum_of_inputs / u128::try_from(self.num_outputs).expect("conversion"))
                .expect("not dividing by zero");

            let mut left_to_spend = total_to_spend;
            let mut outputs = Vec::new();

            for _ in 0..self.num_outputs - 1 {
                outputs.push(TxOutput::new(
                    value,
                    OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                ));
                left_to_spend = (left_to_spend - value).expect("subtraction failed");
            }

            outputs.push(TxOutput::new(
                left_to_spend,
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ));
            Ok(outputs)
        }

        fn get_unspent_outpoints(
            &self,
            num_outputs: usize,
            fee: Amount,
        ) -> anyhow::Result<Vec<ValuedOutPoint>> {
            log::debug!(
                "get_unspent_outpoints: num_outputs: {}, fee: {:?}",
                num_outputs,
                fee
            );
            let num_available_outpoints = self.coin_pool.len();
            let outpoints: Vec<_> = (num_available_outpoints >= num_outputs)
                .then(|| self.coin_pool.iter().take(num_outputs).cloned().collect())
                .ok_or_else(|| anyhow::anyhow!("no outpoints left"))?;
            let sum_of_outputs = outpoints
                .iter()
                .map(|valued_outpoint| valued_outpoint.value)
                .sum::<Option<_>>()
                .expect("sum error");
            if fee > sum_of_outputs {
                Err(anyhow::Error::msg(
                    "get_unspent_outpoints:: fee is {:?} but sum of outputs is {:?}",
                ))
            } else {
                Ok(outpoints)
            }
        }
    }

    fn get_relay_fee_from_tx_size(tx_size: usize) -> u128 {
        u128::try_from(tx_size * RELAY_FEE_PER_BYTE).expect("relay fee overflow")
    }

    #[test]
    fn add_single_tx() -> anyhow::Result<()> {
        let mut mempool = setup();

        let genesis_tx = mempool
            .chain_state
            .confirmed_txs()
            .values()
            .next()
            .expect("genesis tx not found");

        let outpoint_source_id = OutPointSourceId::Transaction(genesis_tx.get_id());

        let flags = 0;
        let locktime = 0;
        let input = TxInput::new(
            outpoint_source_id,
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );
        let relay_fee = Amount::from_atoms(get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE));
        let tx = tx_spend_input(&mempool, input, relay_fee, flags, locktime)?;

        let tx_clone = tx.clone();
        let tx_id = tx.get_id();
        mempool.add_transaction(tx)?;
        assert!(mempool.contains_transaction(&tx_id));
        let all_txs = mempool.get_all();
        assert_eq!(all_txs, vec![&tx_clone]);
        mempool.drop_transaction(&tx_id);
        assert!(!mempool.contains_transaction(&tx_id));
        let all_txs = mempool.get_all();
        assert_eq!(all_txs, Vec::<&Transaction>::new());
        Ok(())
    }

    #[test]
    fn txs_sorted() -> anyhow::Result<()> {
        let mut mempool = setup();
        let mut tx_generator = TxGenerator::new();
        let target_txs = 10;

        for _ in 0..target_txs {
            match tx_generator.generate_tx(&mempool) {
                Ok(tx) => {
                    mempool.add_transaction(tx.clone())?;
                }
                _ => break,
            }
        }

        let fees = mempool
            .get_all()
            .iter()
            .map(|tx| mempool.try_get_fee(tx))
            .collect::<Result<Vec<_>, _>>()?;
        let mut fees_sorted = fees.clone();
        fees_sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(fees, fees_sorted);
        Ok(())
    }

    #[test]
    fn tx_no_inputs() -> anyhow::Result<()> {
        let mut mempool = setup();
        let tx = TxGenerator::new()
            .with_num_inputs(0)
            .with_fee(Amount::from_atoms(0))
            .generate_tx(&mempool)
            .expect("generate_tx failed");
        assert!(matches!(
            mempool.add_transaction(tx),
            Err(Error::TxValidationError(TxValidationError::NoInputs))
        ));
        Ok(())
    }

    fn setup() -> MempoolImpl<ChainStateMock, SystemClock, SystemUsageEstimator> {
        logging::init_logging::<&str>(None);
        MempoolImpl::create(
            ChainStateMock::new(),
            SystemClock {},
            SystemUsageEstimator {},
        )
    }

    #[test]
    fn tx_no_outputs() -> anyhow::Result<()> {
        let mut mempool = setup();
        let tx = TxGenerator::new()
            .with_num_outputs(0)
            .generate_tx(&mempool)
            .expect("generate_tx failed");
        assert!(matches!(
            mempool.add_transaction(tx),
            Err(Error::TxValidationError(TxValidationError::NoOutputs))
        ));
        Ok(())
    }

    #[test]
    fn tx_duplicate_inputs() -> anyhow::Result<()> {
        let mut mempool = setup();

        let genesis_tx = mempool
            .chain_state
            .confirmed_txs()
            .values()
            .next()
            .expect("genesis tx not found");

        let outpoint_source_id = OutPointSourceId::Transaction(genesis_tx.get_id());
        let input = TxInput::new(
            outpoint_source_id.clone(),
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );
        let witness = b"attempted_double_spend".to_vec();
        let duplicate_input = TxInput::new(
            outpoint_source_id,
            0,
            InputWitness::NoSignature(Some(witness)),
        );
        let flags = 0;
        let locktime = 0;
        let outputs = tx_spend_input(&mempool, input.clone(), None, flags, locktime)?
            .outputs()
            .clone();
        let inputs = vec![input, duplicate_input];
        let tx = Transaction::new(flags, inputs, outputs, locktime)?;

        assert!(matches!(
            mempool.add_transaction(tx),
            Err(Error::TxValidationError(TxValidationError::DuplicateInputs))
        ));
        Ok(())
    }

    #[test]
    fn tx_already_in_mempool() -> anyhow::Result<()> {
        let mut mempool = setup();

        let genesis_tx = mempool
            .chain_state
            .confirmed_txs()
            .values()
            .next()
            .expect("genesis tx not found");

        let outpoint_source_id = OutPointSourceId::Transaction(genesis_tx.get_id());
        let input = TxInput::new(
            outpoint_source_id,
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );

        let flags = 0;
        let locktime = 0;
        let tx = tx_spend_input(&mempool, input, None, flags, locktime)?;

        mempool.add_transaction(tx.clone())?;
        assert!(matches!(
            mempool.add_transaction(tx),
            Err(Error::TxValidationError(
                TxValidationError::TransactionAlreadyInMempool
            ))
        ));
        Ok(())
    }

    #[test]
    fn outpoint_not_found() -> anyhow::Result<()> {
        let mut mempool = setup();

        let genesis_tx = mempool
            .chain_state
            .confirmed_txs()
            .values()
            .next()
            .expect("genesis tx not found");

        let outpoint_source_id = OutPointSourceId::Transaction(genesis_tx.get_id());

        let good_input = TxInput::new(
            outpoint_source_id.clone(),
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );
        let flags = 0;
        let locktime = 0;
        let outputs =
            tx_spend_input(&mempool, good_input, None, flags, locktime)?.outputs().clone();

        let bad_outpoint_index = 1;
        let bad_input = TxInput::new(
            outpoint_source_id,
            bad_outpoint_index,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );

        let inputs = vec![bad_input];
        let tx = Transaction::new(flags, inputs, outputs, locktime)?;

        assert!(matches!(
            mempool.add_transaction(tx),
            Err(Error::TxValidationError(
                TxValidationError::OutPointNotFound { .. }
            ))
        ));

        Ok(())
    }

    #[test]
    fn tx_too_big() -> anyhow::Result<()> {
        let mut mempool = setup();
        let tx = TxGenerator::new()
            .with_num_outputs(400_000)
            .generate_tx(&mempool)
            .expect("generate_tx failed");
        assert!(matches!(
            mempool.add_transaction(tx),
            Err(Error::TxValidationError(
                TxValidationError::ExceedsMaxBlockSize
            ))
        ));
        Ok(())
    }

    fn test_replace_tx(original_fee: Amount, replacement_fee: Amount) -> Result<(), Error> {
        let mut mempool = setup();
        let outpoint = mempool
            .available_outpoints(true)
            .iter()
            .next()
            .expect("there should be an outpoint since setup creates the genesis transaction")
            .outpoint
            .clone();

        let outpoint_source_id =
            OutPointSourceId::from(*outpoint.tx_id().get_tx_id().expect("Not Coinbase"));

        let input = TxInput::new(
            outpoint_source_id,
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );
        let flags = 1;
        let locktime = 0;
        let original = tx_spend_input(&mempool, input.clone(), original_fee, flags, locktime)
            .expect("should be able to spend here");
        let original_id = original.get_id();
        mempool.add_transaction(original)?;

        let flags = 0;
        let replacement = tx_spend_input(&mempool, input, replacement_fee, flags, locktime)
            .expect("should be able to spend here");
        mempool.add_transaction(replacement)?;
        assert!(!mempool.contains_transaction(&original_id));

        Ok(())
    }

    #[test]
    fn tx_replace() -> anyhow::Result<()> {
        let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
        let replacement_fee = Amount::from_atoms(relay_fee + 100);
        test_replace_tx(Amount::from_atoms(100), replacement_fee)?;
        let res = test_replace_tx(Amount::from_atoms(100), Amount::from_atoms(relay_fee + 99));
        assert!(matches!(
            res,
            Err(Error::TxValidationError(
                TxValidationError::InsufficientFeesToRelayRBF
            ))
        ));
        let res = test_replace_tx(Amount::from_atoms(100), Amount::from_atoms(100));
        assert!(matches!(
            res,
            Err(Error::TxValidationError(
                TxValidationError::ReplacementFeeLowerThanOriginal { .. }
            ))
        ));
        let res = test_replace_tx(Amount::from_atoms(100), Amount::from_atoms(90));
        assert!(matches!(
            res,
            Err(Error::TxValidationError(
                TxValidationError::ReplacementFeeLowerThanOriginal { .. }
            ))
        ));
        Ok(())
    }

    #[test]
    fn tx_replace_child() -> anyhow::Result<()> {
        let mut mempool = setup();
        let tx = TxGenerator::new()
            .replaceable()
            .generate_tx(&mempool)
            .expect("generate_replaceable_tx");
        mempool.add_transaction(tx.clone())?;

        let outpoint_source_id = OutPointSourceId::Transaction(tx.get_id());
        let child_tx_input = TxInput::new(
            outpoint_source_id,
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );
        // We want to test that even though child_tx doesn't signal replaceability directly, it is replaceable because its parent signalled replaceability
        // replaced
        let flags = 0;
        let locktime = 0;
        let child_tx = tx_spend_input(
            &mempool,
            child_tx_input.clone(),
            Amount::from_atoms(100),
            flags,
            locktime,
        )?;
        mempool.add_transaction(child_tx)?;

        let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
        let replacement_fee = Amount::from_atoms(relay_fee + 100);
        let replacement_tx =
            tx_spend_input(&mempool, child_tx_input, replacement_fee, flags, locktime)?;
        mempool.add_transaction(replacement_tx)?;
        Ok(())
    }

    // To test our validation of BIP125 Rule#4 (replacement transaction pays for its own bandwidth), we need to know the necessary relay fee before creating the transaction. The relay fee depends on the size of the transaction. The usual way to get the size of a transaction is to call `tx.encoded_size` but we cannot do this until we have created the transaction itself. To get around this cycle, we have precomputed the size of all transaction created by `tx_spend_input`. This value will be the same for all transactions created by this function.
    const TX_SPEND_INPUT_SIZE: usize = 84;

    fn tx_spend_input<T: GetTime, M: GetMemoryUsage>(
        mempool: &MempoolImpl<ChainStateMock, T, M>,
        input: TxInput,
        fee: impl Into<Option<Amount>>,
        flags: u32,
        locktime: u32,
    ) -> anyhow::Result<Transaction> {
        let fee = fee.into().map_or_else(
            || Amount::from_atoms(get_relay_fee_from_tx_size(estimate_tx_size(1, 2))),
            std::convert::identity,
        );
        tx_spend_several_inputs(mempool, &[input], fee, flags, locktime)
    }

    fn tx_spend_several_inputs<T: GetTime, M: GetMemoryUsage>(
        mempool: &MempoolImpl<ChainStateMock, T, M>,
        inputs: &[TxInput],
        fee: Amount,
        flags: u32,
        locktime: u32,
    ) -> anyhow::Result<Transaction> {
        let input_value = inputs
            .iter()
            .map(|input| mempool.get_input_value(input))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .sum::<Option<_>>()
            .ok_or_else(|| {
                let msg = String::from("tx_spend_input: overflow");
                log::error!("{}", msg);
                anyhow::Error::msg(msg)
            })?;

        let available_for_spending = (input_value - fee).ok_or_else(|| {
            let msg = format!(
                "tx_spend_several_inputs: input_value ({:?}) lower than fee ({:?})",
                input_value, fee
            );
            log::error!("{}", msg);
            anyhow::Error::msg(msg)
        })?;
        let spent = (available_for_spending / 2).expect("division error");

        let change = (available_for_spending - spent).ok_or_else(|| {
            let msg = String::from("Error computing change");
            anyhow::Error::msg(msg)
        })?;

        Transaction::new(
            flags,
            inputs.to_owned(),
            vec![
                TxOutput::new(spent, OutputPurpose::Transfer(Destination::AnyoneCanSpend)),
                TxOutput::new(change, OutputPurpose::Transfer(Destination::AnyoneCanSpend)),
            ],
            locktime,
        )
        .map_err(Into::into)
    }

    #[test]
    fn one_ancestor_signal_is_enough() -> anyhow::Result<()> {
        let mut mempool = setup();
        let tx = TxGenerator::new()
            .with_num_outputs(2)
            .generate_tx(&mempool)
            .expect("generate_replaceable_tx");

        mempool.add_transaction(tx.clone())?;

        let flags_replaceable = 1;
        let flags_irreplaceable = 0;
        let locktime = 0;

        let outpoint_source_id = OutPointSourceId::Transaction(tx.get_id());
        let ancestor_with_signal = tx_spend_input(
            &mempool,
            TxInput::new(
                outpoint_source_id.clone(),
                0,
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            ),
            None,
            flags_replaceable,
            locktime,
        )?;

        let ancestor_without_signal = tx_spend_input(
            &mempool,
            TxInput::new(
                outpoint_source_id,
                1,
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            ),
            None,
            flags_irreplaceable,
            locktime,
        )?;

        mempool.add_transaction(ancestor_with_signal.clone())?;
        mempool.add_transaction(ancestor_without_signal.clone())?;

        let input_with_replaceable_parent = TxInput::new(
            OutPointSourceId::Transaction(ancestor_with_signal.get_id()),
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );

        let input_with_irreplaceable_parent = TxInput::new(
            OutPointSourceId::Transaction(ancestor_without_signal.get_id()),
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );

        // TODO compute minimum necessary relay fee instead of just overestimating it
        let original_fee = Amount::from_atoms(200);
        let dummy_output = TxOutput::new(
            original_fee,
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        );
        let replaced_tx = tx_spend_several_inputs(
            &mempool,
            &[input_with_irreplaceable_parent.clone(), input_with_replaceable_parent],
            original_fee,
            flags_irreplaceable,
            locktime,
        )?;
        let replaced_tx_id = replaced_tx.get_id();

        mempool.add_transaction(replaced_tx)?;

        let replacing_tx = Transaction::new(
            flags_irreplaceable,
            vec![input_with_irreplaceable_parent],
            vec![dummy_output],
            locktime,
        )?;

        mempool.add_transaction(replacing_tx)?;
        assert!(!mempool.contains_transaction(&replaced_tx_id));

        Ok(())
    }

    #[test]
    fn tx_mempool_entry() -> anyhow::Result<()> {
        use common::primitives::time;
        let mut mempool = setup();
        // Input different flag values just to make the hashes of these dummy transactions
        // different
        let txs = (1..=6)
            .into_iter()
            .map(|i| Transaction::new(i, vec![], vec![], 0).unwrap_or_else(|_| panic!("tx {}", i)))
            .collect::<Vec<_>>();
        let fee = Amount::from_atoms(0);

        // Generation 1
        let tx1_parents = BTreeSet::default();
        let entry1 =
            TxMempoolEntry::new(txs.get(0).unwrap().clone(), fee, tx1_parents, time::get());
        let tx2_parents = BTreeSet::default();
        let entry2 =
            TxMempoolEntry::new(txs.get(1).unwrap().clone(), fee, tx2_parents, time::get());

        // Generation 2
        let tx3_parents = vec![entry1.tx_id(), entry2.tx_id()].into_iter().collect();
        let entry3 =
            TxMempoolEntry::new(txs.get(2).unwrap().clone(), fee, tx3_parents, time::get());

        // Generation 3
        let tx4_parents = vec![entry3.tx_id()].into_iter().collect();
        let tx5_parents = vec![entry3.tx_id()].into_iter().collect();
        let entry4 =
            TxMempoolEntry::new(txs.get(3).unwrap().clone(), fee, tx4_parents, time::get());
        let entry5 =
            TxMempoolEntry::new(txs.get(4).unwrap().clone(), fee, tx5_parents, time::get());

        // Generation 4
        let tx6_parents =
            vec![entry3.tx_id(), entry4.tx_id(), entry5.tx_id()].into_iter().collect();
        let entry6 =
            TxMempoolEntry::new(txs.get(5).unwrap().clone(), fee, tx6_parents, time::get());

        let entries = vec![entry1, entry2, entry3, entry4, entry5, entry6];
        let ids = entries.clone().into_iter().map(|entry| entry.tx_id()).collect::<Vec<_>>();

        for entry in entries.into_iter() {
            mempool.store.add_tx(entry)?;
        }

        let entry1 = mempool.store.get_entry(ids.get(0).expect("index")).expect("entry");
        let entry2 = mempool.store.get_entry(ids.get(1).expect("index")).expect("entry");
        let entry3 = mempool.store.get_entry(ids.get(2).expect("index")).expect("entry");
        let entry4 = mempool.store.get_entry(ids.get(3).expect("index")).expect("entry");
        let entry5 = mempool.store.get_entry(ids.get(4).expect("index")).expect("entry");
        let entry6 = mempool.store.get_entry(ids.get(5).expect("index")).expect("entry");
        assert_eq!(entry1.unconfirmed_ancestors(&mempool.store).0.len(), 0);
        assert_eq!(entry2.unconfirmed_ancestors(&mempool.store).0.len(), 0);
        assert_eq!(entry3.unconfirmed_ancestors(&mempool.store).0.len(), 2);
        assert_eq!(entry4.unconfirmed_ancestors(&mempool.store).0.len(), 3);
        assert_eq!(entry5.unconfirmed_ancestors(&mempool.store).0.len(), 3);
        assert_eq!(entry6.unconfirmed_ancestors(&mempool.store).0.len(), 5);

        assert_eq!(entry1.count_with_descendants(), 5);
        assert_eq!(entry2.count_with_descendants(), 5);
        assert_eq!(entry3.count_with_descendants(), 4);
        assert_eq!(entry4.count_with_descendants(), 2);
        assert_eq!(entry5.count_with_descendants(), 2);
        assert_eq!(entry6.count_with_descendants(), 1);

        Ok(())
    }

    fn test_bip125_max_replacements<T: GetTime, M: GetMemoryUsage>(
        mempool: &mut MempoolImpl<ChainStateMock, T, M>,
        num_potential_replacements: usize,
    ) -> anyhow::Result<()> {
        let tx = TxGenerator::new()
            .with_num_outputs(num_potential_replacements - 1)
            .replaceable()
            .generate_tx(mempool)
            .expect("generate_tx failed");
        let input = tx.inputs().first().expect("one input").clone();
        let outputs = tx.outputs().clone();
        let tx_id = tx.get_id();
        mempool.add_transaction(tx)?;

        let flags = 0;
        let locktime = 0;
        let outpoint_source_id = OutPointSourceId::Transaction(tx_id);
        let fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
        for (index, _) in outputs.iter().enumerate() {
            let input = TxInput::new(
                outpoint_source_id.clone(),
                index.try_into().unwrap(),
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            );
            let tx = tx_spend_input(mempool, input, Amount::from_atoms(fee), flags, locktime)?;
            mempool.add_transaction(tx)?;
        }
        let mempool_size_before_replacement = mempool.store.txs_by_id.len();

        let replacement_fee = Amount::from_atoms(1000) * fee;
        let replacement_tx = tx_spend_input(mempool, input, replacement_fee, flags, locktime)?;
        mempool.add_transaction(replacement_tx).map_err(anyhow::Error::from)?;
        let mempool_size_after_replacement = mempool.store.txs_by_id.len();

        assert_eq!(
            mempool_size_after_replacement,
            mempool_size_before_replacement - num_potential_replacements + 1
        );
        Ok(())
    }

    #[test]
    fn too_many_conflicts() -> anyhow::Result<()> {
        let mut mempool = setup();
        let num_potential_replacements = MAX_BIP125_REPLACEMENT_CANDIDATES + 1;
        let err = test_bip125_max_replacements(&mut mempool, num_potential_replacements)
            .expect_err("expected error TooManyPotentialReplacements")
            .downcast()
            .expect("failed to downcast");
        assert!(matches!(
            err,
            Error::TxValidationError(TxValidationError::TooManyPotentialReplacements)
        ));
        Ok(())
    }

    #[test]
    fn not_too_many_conflicts() -> anyhow::Result<()> {
        let mut mempool = setup();
        let num_potential_replacements = MAX_BIP125_REPLACEMENT_CANDIDATES;
        test_bip125_max_replacements(&mut mempool, num_potential_replacements)
    }

    #[test]
    fn spends_new_unconfirmed() -> anyhow::Result<()> {
        let mut mempool = setup();
        let tx = TxGenerator::new()
            .with_num_outputs(2)
            .replaceable()
            .generate_tx(&mempool)
            .expect("generate_replaceable_tx");
        let outpoint_source_id = OutPointSourceId::Transaction(tx.get_id());
        mempool.add_transaction(tx)?;

        let input1 = TxInput::new(
            outpoint_source_id.clone(),
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );
        let input2 = TxInput::new(
            outpoint_source_id,
            1,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );

        let locktime = 0;
        let flags = 0;
        let original_fee = Amount::from_atoms(100);
        let replaced_tx = tx_spend_input(&mempool, input1.clone(), original_fee, flags, locktime)?;
        mempool.add_transaction(replaced_tx)?;
        let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
        let replacement_fee = Amount::from_atoms(100 + relay_fee);
        let incoming_tx = tx_spend_several_inputs(
            &mempool,
            &[input1, input2],
            replacement_fee,
            flags,
            locktime,
        )?;

        let res = mempool.add_transaction(incoming_tx);
        assert!(matches!(
            res,
            Err(Error::TxValidationError(
                TxValidationError::SpendsNewUnconfirmedOutput
            ))
        ));
        Ok(())
    }

    #[test]
    fn pays_more_than_conflicts_with_descendants() -> anyhow::Result<()> {
        let mut mempool = setup();
        let tx = TxGenerator::new().generate_tx(&mempool).expect("generate_replaceable_tx");
        let tx_id = tx.get_id();
        mempool.add_transaction(tx)?;

        let outpoint_source_id = OutPointSourceId::Transaction(tx_id);
        let input = TxInput::new(
            outpoint_source_id,
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );

        let locktime = 0;
        let rbf = 1;
        let no_rbf = 0;

        // Create transaction that we will attempt to replace
        let original_fee = Amount::from_atoms(100);
        let replaced_tx = tx_spend_input(&mempool, input.clone(), original_fee, rbf, locktime)?;
        let replaced_tx_fee = mempool.try_get_fee(&replaced_tx)?;
        let replaced_id = replaced_tx.get_id();
        mempool.add_transaction(replaced_tx)?;

        // Create some children for this transaction
        let descendant_outpoint_source_id = OutPointSourceId::Transaction(replaced_id);

        let descendant1_fee = Amount::from_atoms(100);
        let descendant1 = tx_spend_input(
            &mempool,
            TxInput::new(
                descendant_outpoint_source_id.clone(),
                0,
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            ),
            descendant1_fee,
            no_rbf,
            locktime,
        )?;
        let descendant1_id = descendant1.get_id();
        mempool.add_transaction(descendant1)?;

        let descendant2_fee = Amount::from_atoms(100);
        let descendant2 = tx_spend_input(
            &mempool,
            TxInput::new(
                descendant_outpoint_source_id,
                1,
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            ),
            descendant2_fee,
            no_rbf,
            locktime,
        )?;
        let descendant2_id = descendant2.get_id();
        mempool.add_transaction(descendant2)?;

        //Create a new incoming transaction that conflicts with `replaced_tx` because it spends
        //`input`. It will be rejected because its fee exactly equals (so is not greater than) the
        //sum of the fees of the conflict together with its descendants
        let insufficient_rbf_fee = [replaced_tx_fee, descendant1_fee, descendant2_fee]
            .into_iter()
            .sum::<Option<_>>()
            .unwrap();
        let incoming_tx = tx_spend_input(
            &mempool,
            input.clone(),
            insufficient_rbf_fee,
            no_rbf,
            locktime,
        )?;

        assert!(matches!(
            mempool.add_transaction(incoming_tx),
            Err(Error::TxValidationError(
                TxValidationError::TransactionFeeLowerThanConflictsWithDescendants
            ))
        ));

        let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
        let sufficient_rbf_fee = insufficient_rbf_fee + Amount::from_atoms(relay_fee);
        let incoming_tx = tx_spend_input(&mempool, input, sufficient_rbf_fee, no_rbf, locktime)?;
        mempool.add_transaction(incoming_tx)?;

        assert!(!mempool.contains_transaction(&replaced_id));
        assert!(!mempool.contains_transaction(&descendant1_id));
        assert!(!mempool.contains_transaction(&descendant2_id));
        Ok(())
    }

    #[derive(Clone)]
    struct MockClock {
        time: Arc<AtomicU64>,
    }

    impl MockClock {
        fn new() -> Self {
            Self {
                time: Arc::new(AtomicU64::new(0)),
            }
        }

        fn set(&self, time: Time) {
            self.time.store(time.as_secs(), Ordering::SeqCst)
        }

        fn increment(&self, inc: Time) {
            self.time.store(
                self.time.load(Ordering::SeqCst) + inc.as_secs(),
                Ordering::SeqCst,
            )
        }
    }

    impl GetTime for MockClock {
        fn get_time(&self) -> Time {
            Duration::new(self.time.load(Ordering::SeqCst), 0)
        }
    }

    #[test]
    fn only_expired_entries_removed() -> anyhow::Result<()> {
        let mock_clock = MockClock::new();

        let mut mempool = MempoolImpl::create(
            ChainStateMock::new(),
            mock_clock.clone(),
            SystemUsageEstimator {},
        );

        let num_inputs = 1;
        let num_outputs = 2;
        let big_fee = get_relay_fee_from_tx_size(estimate_tx_size(num_inputs, num_outputs)) + 100;
        let parent = TxGenerator::new()
            .with_num_inputs(num_inputs)
            .with_num_outputs(num_outputs)
            .with_fee(Amount::from_atoms(big_fee))
            .generate_tx(&mempool)?;
        let parent_id = parent.get_id();
        mempool.add_transaction(parent)?;

        let flags = 0;
        let locktime = 0;
        let outpoint_source_id = OutPointSourceId::Transaction(parent_id);
        let child_0 = tx_spend_input(
            &mempool,
            TxInput::new(
                outpoint_source_id.clone(),
                0,
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            ),
            None,
            flags,
            locktime,
        )?;

        let child_1 = tx_spend_input(
            &mempool,
            TxInput::new(
                outpoint_source_id,
                1,
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            ),
            None,
            flags,
            locktime,
        )?;
        let child_1_id = child_1.get_id();

        let expired_tx_id = child_0.get_id();
        mempool.add_transaction(child_0)?;

        // Simulate the parent being added to a block
        // We have to do this because if we leave this parent in the mempool then it will be
        // expired, and so removed along with both its children, and thus the addition of child_1 to
        // the mempool will fail
        mempool.process_block(&parent_id)?;
        mock_clock.set(DEFAULT_MEMPOOL_EXPIRY + Duration::new(1, 0));

        mempool.add_transaction(child_1)?;
        assert!(!mempool.contains_transaction(&expired_tx_id));
        assert!(mempool.contains_transaction(&child_1_id));
        Ok(())
    }

    #[test]
    fn rolling_fee() -> anyhow::Result<()> {
        logging::init_logging::<&str>(None);
        let mock_clock = MockClock::new();
        let mut mock_usage = MockGetMemoryUsage::new();
        // Add parent
        // Add first child
        mock_usage.expect_get_memory_usage().times(2).return_const(0usize);
        // Add second child, triggering the trimming process
        mock_usage
            .expect_get_memory_usage()
            .times(1)
            .return_const(MAX_MEMPOOL_SIZE_BYTES + 1);
        // After removing one entry, cause the code to exit the loop by showing a small usage
        mock_usage.expect_get_memory_usage().return_const(0usize);

        let chain_state = ChainStateMock::new();
        let mut mempool = MempoolImpl::create(chain_state, mock_clock.clone(), mock_usage);

        let num_inputs = 1;
        let num_outputs = 3;

        // Use a higher than default fee because we don't want this transction to be evicted during
        // the trimming process
        let parent = TxGenerator::new()
            .with_num_inputs(num_inputs)
            .with_num_outputs(num_outputs)
            .generate_tx(&mempool)?;
        let parent_id = parent.get_id();
        log::debug!("parent_id: {}", parent_id.get());
        log::debug!("before adding parent");
        mempool.add_transaction(parent)?;
        log::debug!("after adding parent");

        let flags = 0;
        let locktime = 0;
        let outpoint_source_id = OutPointSourceId::Transaction(parent_id);

        // child_0 has the lower fee so it will be evicted when memory usage is too high
        let child_0 = tx_spend_input(
            &mempool,
            TxInput::new(
                outpoint_source_id.clone(),
                0,
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            ),
            None,
            flags,
            locktime,
        )?;
        let child_0_id = child_0.get_id();
        log::debug!("child_0_id {}", child_0_id.get());

        let big_fee = Amount::from_atoms(
            get_relay_fee_from_tx_size(estimate_tx_size(num_inputs, num_outputs)) + 100,
        );
        let child_1 = tx_spend_input(
            &mempool,
            TxInput::new(
                outpoint_source_id.clone(),
                1,
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            ),
            big_fee,
            flags,
            locktime,
        )?;
        let child_1_id = child_1.get_id();
        log::debug!("child_1_id {}", child_1_id.get());
        mempool.add_transaction(child_0.clone())?;
        log::debug!("added child_0");
        mempool.add_transaction(child_1)?;
        log::debug!("added child_1");

        assert_eq!(mempool.store.txs_by_id.len(), 2);
        assert!(mempool.contains_transaction(&child_1_id));
        assert!(!mempool.contains_transaction(&child_0_id));
        let rolling_fee = mempool.get_minimum_rolling_fee();
        assert_eq!(
            rolling_fee,
            (FeeRate::of_tx(mempool.try_get_fee(&child_0)?, child_0.encoded_size())?
                + *INCREMENTAL_RELAY_FEE_RATE)
                .ok_or(TxValidationError::FeeRateError)?
        );

        // Now that the minimum rolling fee has been bumped up, a low-fee tx will not pass
        // validation
        let child_2 = tx_spend_input(
            &mempool,
            TxInput::new(
                outpoint_source_id.clone(),
                2,
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            ),
            None,
            flags,
            locktime,
        )?;
        log::debug!("before child2");
        assert!(matches!(
            mempool.add_transaction(child_2),
            Err(Error::TxValidationError(
                TxValidationError::RollingFeeThresholdNotMet { .. }
            ))
        ));

        // We provide a sufficient fee for the tx to pass the minimum rolling fee requirement
        let child_2_high_fee = tx_spend_input(
            &mempool,
            TxInput::new(
                outpoint_source_id,
                2,
                InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
            ),
            mempool.get_minimum_rolling_fee().compute_fee(estimate_tx_size(1, 1))?,
            flags,
            locktime,
        )?;
        log::debug!("before child2_high_fee");
        mempool.add_transaction(child_2_high_fee)?;

        // We simulate a block being accepted so the rolling fee will begin to decay
        mempool.process_block(&parent_id)?;

        // Because the rolling fee is only updated when we attempt to add a tx to the mempool
        // we need to submit a "dummy" tx to trigger these updates.

        // Since memory usage is now zero, it is less than 1/4 of the max size
        // and ROLLING_FEE_BASE_HALFLIFE / 4 is the time it will take for the fee to halve
        let halflife = ROLLING_FEE_BASE_HALFLIFE / 4;
        mock_clock.increment(halflife);
        let dummy_tx = TxGenerator::new().generate_tx(&mempool)?;
        log::debug!("first attempt to add dummy");
        assert!(matches!(
            mempool.add_transaction(dummy_tx.clone()),
            Err(Error::TxValidationError(
                TxValidationError::RollingFeeThresholdNotMet { .. }
            ))
        ));
        assert_eq!(
            mempool.get_minimum_rolling_fee(),
            (rolling_fee / FeeRate::new(Amount::from_atoms(2))).unwrap()
        );

        mock_clock.increment(halflife);
        // Fee will have dropped under INCREMENTAL_RELAY_FEE_RATE / 2 by now, so it will be set to
        // zero and our tx will be submitted successfully
        log::debug!("second attempt to add dummy");
        mempool.add_transaction(dummy_tx)?;
        assert_eq!(
            mempool.get_minimum_rolling_fee(),
            FeeRate::new(Amount::from_atoms(0))
        );
        Ok(())
    }

    #[test]
    fn different_size_txs() -> anyhow::Result<()> {
        use std::time::Duration;
        use std::time::Instant;
        let mut mempool = setup();
        let initial_tx = TxGenerator::new()
            .with_num_inputs(1)
            .with_num_outputs(10_000)
            .generate_tx(&mempool)?;
        mempool.add_transaction(initial_tx)?;

        let target_txs = 100;
        let mut time_processing_txs = Duration::from_millis(0);
        let mut time_creating_txs = Duration::from_millis(0);
        for i in 0..target_txs {
            let num_inputs = i + 1;
            let num_outputs = i + 1;
            let before_creating = Instant::now();
            let tx = TxGenerator::new()
                .with_num_inputs(num_inputs)
                .with_num_outputs(num_outputs)
                .generate_tx(&mempool)?;
            time_creating_txs += before_creating.elapsed();
            let before_processing = Instant::now();
            mempool.add_transaction(tx)?;
            time_processing_txs += before_processing.elapsed()
        }

        log::info!("Total time spent processing: {:?}", time_processing_txs);
        log::info!("Total time spent creating: {:?}", time_creating_txs);
        Ok(())
    }

    #[test]
    fn descendant_score() -> anyhow::Result<()> {
        let mut mempool = setup();
        let tx = TxGenerator::new()
            .with_num_outputs(2)
            .generate_tx(&mempool)
            .expect("generate_replaceable_tx");
        let tx_id = tx.get_id();
        mempool.add_transaction(tx)?;

        let outpoint_source_id = OutPointSourceId::Transaction(tx_id);

        let flags = 0;
        let locktime = 0;

        let tx_b_fee = Amount::from(get_relay_fee_from_tx_size(estimate_tx_size(1, 2)));
        let tx_a_fee = (tx_b_fee + Amount::from(1000)).unwrap();
        let tx_c_fee = (tx_a_fee + Amount::from(1000)).unwrap();
        let tx_a = tx_spend_input(
            &mempool,
            TxInput::new(outpoint_source_id.clone(), 0, DUMMY_WITNESS_MSG.to_vec()),
            tx_a_fee,
            flags,
            locktime,
        )?;
        let tx_a_id = tx_a.get_id();
        log::debug!("tx_a_id : {}", tx_a_id.get());
        log::debug!("tx_a fee : {:?}", mempool.try_get_fee(&tx_a)?);
        mempool.add_transaction(tx_a)?;

        let tx_b = tx_spend_input(
            &mempool,
            TxInput::new(outpoint_source_id, 1, DUMMY_WITNESS_MSG.to_vec()),
            tx_b_fee,
            flags,
            locktime,
        )?;
        let tx_b_id = tx_b.get_id();
        log::debug!("tx_b_id : {}", tx_b_id.get());
        log::debug!("tx_b fee : {:?}", mempool.try_get_fee(&tx_b)?);
        mempool.add_transaction(tx_b)?;

        let tx_c = tx_spend_input(
            &mempool,
            TxInput::new(
                OutPointSourceId::Transaction(tx_b_id.clone()),
                0,
                DUMMY_WITNESS_MSG.to_vec(),
            ),
            tx_c_fee,
            flags,
            locktime,
        )?;
        let tx_c_id = tx_c.get_id();
        log::debug!("tx_c_id : {}", tx_c_id.get());
        log::debug!("tx_c fee : {:?}", mempool.try_get_fee(&tx_c)?);
        mempool.add_transaction(tx_c)?;

        let entry_a = mempool.store.txs_by_id.get(&tx_a_id.get()).expect("tx_a");
        log::debug!("entry a has score {:?}", entry_a.fees_with_descendants);
        let entry_b = mempool.store.txs_by_id.get(&tx_b_id.get()).expect("tx_b");
        log::debug!("entry b has score {:?}", entry_b.fees_with_descendants);
        let entry_c = mempool.store.txs_by_id.get(&tx_c_id.get()).expect("tx_c").clone();
        log::debug!("entry c has score {:?}", entry_c.fees_with_descendants);
        assert_eq!(entry_a.fee, entry_a.fees_with_descendants);
        assert_eq!(
            entry_b.fees_with_descendants,
            (entry_b.fee + entry_c.fee).unwrap()
        );
        assert!(!mempool.store.txs_by_descendant_score.contains_key(&tx_b_fee.into()));
        log::debug!(
            "raw_txs_by_descendant_score {:?}",
            mempool.store.txs_by_descendant_score
        );
        check_txs_sorted_by_descendant_sore(&mempool);

        mempool.drop_transaction(&entry_c.tx.get_id());
        assert!(!mempool.store.txs_by_descendant_score.contains_key(&tx_c_fee.into()));
        let entry_b = mempool.store.txs_by_id.get(&tx_b_id.get()).expect("tx_b");
        assert_eq!(entry_b.fees_with_descendants, entry_b.fee);

        check_txs_sorted_by_descendant_sore(&mempool);

        Ok(())
    }

    fn check_txs_sorted_by_descendant_sore(
        mempool: &MempoolImpl<ChainStateMock, SystemClock, SystemUsageEstimator>,
    ) {
        let txs_by_descendant_score =
            mempool.store.txs_by_descendant_score.values().flatten().collect::<Vec<_>>();
        for i in 0..(txs_by_descendant_score.len() - 1) {
            log::debug!("i =  {}", i);
            let tx_id = txs_by_descendant_score.get(i).unwrap();
            let next_tx_id = txs_by_descendant_score.get(i + 1).unwrap();
            let entry_score = mempool.store.txs_by_id.get(tx_id).unwrap().fees_with_descendants;
            let next_entry_score =
                mempool.store.txs_by_id.get(next_tx_id).unwrap().fees_with_descendants;
            log::debug!("entry_score: {:?}", entry_score);
            log::debug!("next_entry_score: {:?}", next_entry_score);
            assert!(entry_score <= next_entry_score)
        }
    }
}
