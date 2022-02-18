use std::cmp::Ord;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Debug;

use serialization::Encode;
use thiserror::Error;

use common::chain::transaction::Transaction;
use common::chain::transaction::TxInput;
use common::chain::OutPoint;
use common::primitives::amount::Amount;
use common::primitives::Id;
use common::primitives::Idable;
use common::primitives::H256;

// TODO this willbe defined elsewhere (some of limits.rs file)
const MAX_BLOCK_SIZE_BYTES: usize = 1_000_000;

const MEMPOOL_MAX_TXS: usize = 1_000_000;

impl<C: ChainState> TryGetFee for MempoolImpl<C> {
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
            .ok_or(TxValidationError::TransactionFeeOverflow)?;
        let sum_outputs = tx
            .outputs()
            .iter()
            .map(|output| output.value())
            .sum::<Option<_>>()
            .ok_or(TxValidationError::TransactionFeeOverflow)?;
        (sum_inputs - sum_outputs).ok_or(TxValidationError::TransactionFeeOverflow)
    }
}

pub trait Mempool<C> {
    fn create(chain_state: C) -> Self;
    fn add_transaction(&mut self, tx: Transaction) -> Result<(), MempoolError>;
    fn get_all(&self) -> Vec<&Transaction>;
    fn contains_transaction(&self, tx: &Id<Transaction>) -> bool;
    fn drop_transaction(&mut self, tx: &Id<Transaction>);
    fn new_tip_set(&mut self) -> Result<(), MempoolError>;
}

pub trait ChainState {
    fn contains_outpoint(&self, outpoint: &OutPoint) -> bool;
    fn get_outpoint_value(&self, outpoint: &OutPoint) -> Result<Amount, anyhow::Error>;
}

trait TryGetFee {
    fn try_get_fee(&self, tx: &Transaction) -> Result<Amount, TxValidationError>;
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct TxMempoolEntry {
    tx: Transaction,
    fee: Amount,
    parents: BTreeSet<H256>,
    children: BTreeSet<H256>,
    count_with_descendants: usize,
}

impl TxMempoolEntry {
    fn new(tx: Transaction, fee: Amount, parents: BTreeSet<H256>) -> TxMempoolEntry {
        Self {
            tx,
            fee,
            parents,
            children: BTreeSet::default(),
            count_with_descendants: 1,
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

    fn get_children_mut(&mut self) -> &mut BTreeSet<H256> {
        &mut self.children
    }

    fn is_replaceable(&self, store: &MempoolStore) -> bool {
        self.tx.is_replaceable()
            || self
                .unconfirmed_ancestors(store)
                .iter()
                .any(|ancestor| store.get_entry(ancestor).expect("entry").tx.is_replaceable())
    }

    fn unconfirmed_ancestors(&self, store: &MempoolStore) -> BTreeSet<H256> {
        let mut visited = BTreeSet::new();
        self.unconfirmed_ancestors_inner(&mut visited, store);
        visited
    }

    fn unconfirmed_ancestors_inner(&self, visited: &mut BTreeSet<H256>, store: &MempoolStore) {
        for parent in self.parents.iter() {
            if visited.contains(parent) {
                continue;
            } else {
                visited.insert(*parent);
                store
                    .get_entry(parent)
                    .expect("entry")
                    .unconfirmed_ancestors_inner(visited, store);
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

#[derive(Debug)]
pub struct MempoolImpl<C: ChainState> {
    store: MempoolStore,
    chain_state: C,
}

#[derive(Debug)]
struct MempoolStore {
    txs_by_id: HashMap<H256, TxMempoolEntry>,
    txs_by_fee: BTreeMap<Amount, BTreeSet<H256>>,
    spender_txs: BTreeMap<OutPoint, H256>,
}

impl MempoolStore {
    fn new() -> Self {
        Self {
            txs_by_fee: BTreeMap::new(),
            txs_by_id: HashMap::new(),
            spender_txs: BTreeMap::new(),
        }
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
        let tx_id = outpoint.tx_id().get_tx_id().expect("Not coinbase").clone();
        let err = || TxValidationError::OutPointNotFound {
            outpoint: outpoint.clone(),
            tx_id: tx_id.clone(),
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
                .expect("be there")
                .get_children_mut()
                .insert(entry.tx_id());
        }
    }

    fn update_ancestor_count(&mut self, entry: &TxMempoolEntry) {
        for ancestor in entry.unconfirmed_ancestors(self) {
            let ancestor = self.txs_by_id.get_mut(&ancestor).expect("ancestor");
            ancestor.count_with_descendants += 1;
        }
    }

    fn mark_outpoints_as_spent(&mut self, entry: &TxMempoolEntry) {
        let id = entry.tx_id();
        for outpoint in entry.tx.inputs().iter().map(|input| input.outpoint()) {
            self.spender_txs.insert(outpoint.clone(), id);
        }
    }

    fn add_tx(&mut self, entry: TxMempoolEntry) -> Result<(), MempoolError> {
        let id = entry.tx_id();
        self.append_to_parents(&entry);
        self.update_ancestor_count(&entry);
        self.mark_outpoints_as_spent(&entry);

        self.txs_by_fee.entry(entry.fee).or_default().insert(id);
        self.txs_by_id.insert(id, entry);

        Ok(())
    }

    fn drop_tx(&mut self, tx_id: &Id<Transaction>) {
        if let Some(entry) = self.txs_by_id.remove(&tx_id.get()) {
            self.txs_by_fee.entry(entry.fee).and_modify(|entries| {
                entries.remove(&tx_id.get()).then(|| ()).expect("Inconsistent mempool store")
            });
            self.spender_txs.retain(|_, id| *id != tx_id.get())
        } else {
            assert!(!self.txs_by_fee.values().flatten().any(|id| *id == tx_id.get()));
            assert!(!self.spender_txs.iter().any(|(_, id)| *id == tx_id.get()));
        }
    }

    fn find_conflicting_tx(&self, outpoint: &OutPoint) -> Option<H256> {
        self.spender_txs.get(outpoint).cloned()
    }
}

#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("Mempool is full")]
    MempoolFull,
    #[error(transparent)]
    TxValidationError(TxValidationError),
}

#[derive(Debug, Error)]
pub enum TxValidationError {
    #[error("No Inputs")]
    NoInputs,
    #[error("No Ouputs")]
    NoOutputs,
    #[error("DuplicateInputs")]
    DuplicateInputs,
    #[error("OutPointNotFound {outpoint:?}")]
    OutPointNotFound {
        outpoint: OutPoint,
        tx_id: Id<Transaction>,
    },
    #[error("ExceedsMaxBlockSize")]
    ExceedsMaxBlockSize,
    #[error("TransactionAlreadyInMempool")]
    TransactionAlreadyInMempool,
    #[error("ConflictWithIrreplaceableTransaction")]
    ConflictWithIrreplaceableTransaction,
    #[error("TransactionFeeOverflow")]
    TransactionFeeOverflow,
    #[error("ReplacementFeeLowerThanOriginal")]
    ReplacementFeeLowerThanOriginal,
    #[error("TooManyPotentialReplacements")]
    TooManyPotentialReplacements,
}

impl From<TxValidationError> for MempoolError {
    fn from(e: TxValidationError) -> Self {
        MempoolError::TxValidationError(e)
    }
}

impl<C: ChainState + Debug> MempoolImpl<C> {
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
        Ok(TxMempoolEntry::new(tx, fee, parents))
    }

    fn validate_transaction(&self, tx: &Transaction) -> Result<(), TxValidationError> {
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

        let conflicts = tx
            .inputs()
            .iter()
            .filter_map(|input| self.store.find_conflicting_tx(input.outpoint()))
            .map(|id_conflict| self.store.get_entry(&id_conflict).expect("entry for id"))
            .collect::<Vec<_>>();

        for entry in &conflicts {
            entry
                .is_replaceable(&self.store)
                .then(|| ())
                .ok_or(TxValidationError::ConflictWithIrreplaceableTransaction)?;

            self.pays_more_than_conflicts(tx, &conflicts)?;
            self.potential_replacements_within_limit(&conflicts)?;
        }

        self.verify_inputs_available(tx)?;

        Ok(())
    }

    fn pays_more_than_conflicts(
        &self,
        tx: &Transaction,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), TxValidationError> {
        let replacement_fee = self.try_get_fee(tx)?;
        conflicts
            .iter()
            .all(|conflict| conflict.fee < replacement_fee)
            .then(|| ())
            .ok_or(TxValidationError::ReplacementFeeLowerThanOriginal)
    }

    fn potential_replacements_within_limit(
        &self,
        conflicts: &[&TxMempoolEntry],
    ) -> Result<(), TxValidationError> {
        const MAX_BIP125_REPLACEMENT_CANDIATES: usize = 100;
        let mut num_potential_replacements = 0;
        for conflict in conflicts {
            num_potential_replacements += conflict.count_with_descendants();
            if num_potential_replacements > MAX_BIP125_REPLACEMENT_CANDIATES {
                return Err(TxValidationError::TooManyPotentialReplacements);
            }
        }
        Ok(())
    }
}

impl<C: ChainState + Debug> Mempool<C> for MempoolImpl<C> {
    fn create(chain_state: C) -> Self {
        Self {
            store: MempoolStore::new(),
            chain_state,
        }
    }

    fn new_tip_set(&mut self) -> Result<(), MempoolError> {
        unimplemented!()
    }
    //

    fn add_transaction(&mut self, tx: Transaction) -> Result<(), MempoolError> {
        // TODO (1). First, we need to decide on criteria for the Mempool to be considered full. Maybe number
        // of transactions is not a good enough indicator. Consider checking mempool size as well
        // TODO (2) What to do when the mempool is full. Instead of rejecting Do incoming transaction we probably want to evict a low-score transaction
        if self.store.txs_by_fee.len() >= MEMPOOL_MAX_TXS {
            return Err(MempoolError::MempoolFull);
        }
        self.validate_transaction(&tx)?;
        let entry = self.create_entry(tx)?;
        self.store.add_tx(entry)?;
        Ok(())
    }

    fn get_all(&self) -> Vec<&Transaction> {
        self.store
            .txs_by_fee
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
        self.store.drop_tx(tx_id);
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
    use rand::Rng;

    const DUMMY_WITNESS_MSG: &[u8] = b"dummy_witness_msg";

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
    struct ValuedOutPoint {
        outpoint: OutPoint,
        value: Amount,
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

    impl MempoolImpl<ChainStateMock> {
        fn available_outpoints(&self) -> BTreeSet<ValuedOutPoint> {
            self.store
                .unconfirmed_outpoints()
                .into_iter()
                .chain(self.chain_state.confirmed_outpoints())
                .collect()
        }

        fn get_input_value(&self, input: &TxInput) -> anyhow::Result<Amount> {
            self.available_outpoints()
                .iter()
                .find_map(|valued_outpoint| {
                    (valued_outpoint.outpoint == *input.outpoint()).then(|| valued_outpoint.value)
                })
                .ok_or_else(|| anyhow::anyhow!("No such unconfirmed output"))
        }
    }

    #[derive(Debug, Clone)]
    pub(crate) struct ChainStateMock {
        txs: HashMap<H256, Transaction>,
        outpoints: BTreeSet<OutPoint>,
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
                txs: std::iter::once((genesis_tx.get_id().get(), genesis_tx)).collect(),
                outpoints,
            }
        }

        fn unspent_outpoints(&self) -> BTreeSet<ValuedOutPoint> {
            self.outpoints
                .iter()
                .map(|outpoint| {
                    let value =
                        self.get_outpoint_value(outpoint).expect("Inconsistent Chain State");
                    ValuedOutPoint {
                        outpoint: outpoint.clone(),
                        value,
                    }
                })
                .collect()
        }

        fn confirmed_txs(&self) -> &HashMap<H256, Transaction> {
            &self.txs
        }

        fn get_outpoint_value(&self, outpoint: &OutPoint) -> Result<Amount, anyhow::Error> {
            self.txs
                .get(&outpoint.tx_id().get_tx_id().expect("Not Coinbase").get())
                .ok_or_else(|| anyhow::anyhow!("tx for outpoint sought in chain state, not found"))
                .and_then(|tx| {
                    tx.outputs()
                        .get(outpoint.output_index() as usize)
                        .ok_or_else(|| anyhow::anyhow!("outpoint index out of bounds"))
                        .map(|output| output.value())
                })
        }

        fn confirmed_outpoints(&self) -> BTreeSet<ValuedOutPoint> {
            self.txs
                .values()
                .flat_map(|tx| {
                    std::iter::repeat(tx.get_id())
                        .zip(tx.outputs().iter().enumerate())
                        .map(move |(tx_id, (i, output))| valued_outpoint(&tx_id, i as u32, output))
                })
                .collect()
        }
    }

    impl ChainState for ChainStateMock {
        fn contains_outpoint(&self, outpoint: &OutPoint) -> bool {
            self.outpoints.iter().any(|value| *value == *outpoint)
        }

        fn get_outpoint_value(&self, outpoint: &OutPoint) -> Result<Amount, anyhow::Error> {
            self.txs
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

    struct TxGenerator {
        coin_pool: BTreeSet<ValuedOutPoint>,
        num_inputs: usize,
        num_outputs: usize,
        tx_fee: Option<Amount>,
    }

    impl TxGenerator {
        fn new(
            mempool: &MempoolImpl<ChainStateMock>,
            num_inputs: usize,
            num_outputs: usize,
        ) -> Self {
            let unconfirmed_outputs = BTreeSet::new();
            Self::create_tx_generator(
                &mempool.chain_state,
                &unconfirmed_outputs,
                num_inputs,
                num_outputs,
            )
        }

        fn with_fee(mut self, fee: Amount) -> Self {
            self.tx_fee = Some(fee);
            self
        }

        fn new_with_unconfirmed(
            mempool: &MempoolImpl<ChainStateMock>,
            num_inputs: usize,
            num_outputs: usize,
        ) -> Self {
            let unconfirmed_outputs = mempool.available_outpoints();
            Self::create_tx_generator(
                &mempool.chain_state,
                &unconfirmed_outputs,
                num_inputs,
                num_outputs,
            )
        }

        fn create_tx_generator(
            chain_state: &ChainStateMock,
            unconfirmed_outputs: &BTreeSet<ValuedOutPoint>,
            num_inputs: usize,
            num_outputs: usize,
        ) -> Self {
            let coin_pool = chain_state
                .unspent_outpoints()
                .iter()
                .chain(unconfirmed_outputs)
                .cloned()
                .collect();

            Self {
                coin_pool,
                num_inputs,
                num_outputs,
                tx_fee: None,
            }
        }

        fn generate_tx(&mut self) -> anyhow::Result<Transaction> {
            let valued_inputs = self.generate_tx_inputs();
            let outputs = self.generate_tx_outputs(&valued_inputs, self.tx_fee)?;
            let locktime = 0;
            let flags = 0;
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

        fn generate_replaceable_tx(mut self) -> anyhow::Result<Transaction> {
            let valued_inputs = self.generate_tx_inputs();
            let outputs = self.generate_tx_outputs(&valued_inputs, self.tx_fee)?;
            let locktime = 0;
            let flags = 1;
            let (inputs, _values): (Vec<TxInput>, Vec<Amount>) = valued_inputs.into_iter().unzip();
            let tx = Transaction::new(flags, inputs, outputs, locktime)?;
            assert!(tx.is_replaceable());
            Ok(tx)
        }

        fn generate_tx_inputs(&mut self) -> Vec<(TxInput, Amount)> {
            std::iter::repeat(())
                .take(self.num_inputs)
                .filter_map(|_| self.generate_input().ok())
                .collect()
        }

        fn generate_tx_outputs(
            &self,
            inputs: &[(TxInput, Amount)],
            tx_fee: Option<Amount>,
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

            let total_to_spend = if let Some(fee) = tx_fee {
                (sum_of_inputs - fee).expect("underflow")
            } else {
                sum_of_inputs
            };

            let mut left_to_spend = total_to_spend;
            let mut outputs = Vec::new();

            let max_output_value = Amount::from_atoms(1_000);
            for _ in 0..self.num_outputs - 1 {
                let max_output_value = std::cmp::min(
                    (left_to_spend / 2).expect("division failed"),
                    max_output_value,
                );
                if max_output_value == Amount::from_atoms(0) {
                    return Err(anyhow::Error::msg("No more funds to spend"));
                }
                let value = Amount::random(Amount::from_atoms(1)..=max_output_value);
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

        fn generate_input(&self) -> anyhow::Result<(TxInput, Amount)> {
            let ValuedOutPoint { outpoint, value } = self.random_unspent_outpoint()?;
            Ok((
                TxInput::new(
                    outpoint.tx_id(),
                    outpoint.output_index(),
                    InputWitness::NoSignature(None),
                ),
                value,
            ))
        }

        fn random_unspent_outpoint(&self) -> anyhow::Result<ValuedOutPoint> {
            let num_outpoints = self.coin_pool.len();
            (num_outpoints > 0)
                .then(|| {
                    let index = rand::thread_rng().gen_range(0..num_outpoints);
                    self.coin_pool
                        .iter()
                        .nth(index)
                        .cloned()
                        .expect("Outpoint set should not be empty")
                })
                .ok_or_else(|| anyhow::anyhow!("no outpoints left"))
        }
    }

    #[test]
    fn add_single_tx() -> anyhow::Result<()> {
        let mut mempool = MempoolImpl::create(ChainStateMock::new());

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
        let tx = tx_spend_input(&mempool, input, None, flags, locktime)?;

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

    // The "fees" now a are calculated as sum of the outputs
    // This test creates transactions with a single input and a single output to check that the
    // mempool sorts txs by fee
    #[test]
    fn txs_sorted() -> anyhow::Result<()> {
        let chain_state = ChainStateMock::new();
        let num_inputs = 1;
        let num_outputs = 1;
        let mut mempool = MempoolImpl::create(chain_state);
        let mut tx_generator = TxGenerator::new(&mempool, num_inputs, num_outputs);
        let target_txs = 100;

        for _ in 0..target_txs {
            match tx_generator.generate_tx() {
                Ok(tx) => {
                    mempool.add_transaction(tx.clone())?;
                }
                _ => break,
            }
        }

        let fees = mempool
            .get_all()
            .iter()
            .map(|tx| tx.outputs().first().expect("TX should have exactly one output").value())
            .collect::<Vec<_>>();
        let mut fees_sorted = fees.clone();
        fees_sorted.sort_by(|a, b| b.cmp(a));
        assert_eq!(fees, fees_sorted);
        Ok(())
    }

    #[test]
    fn tx_no_inputs() -> anyhow::Result<()> {
        let mut mempool = setup();
        let num_inputs = 0;
        let num_outputs = 1;
        let tx = TxGenerator::new(&mempool, num_inputs, num_outputs)
            .generate_tx()
            .expect("generate_tx failed");
        assert!(matches!(
            mempool.add_transaction(tx),
            Err(MempoolError::TxValidationError(TxValidationError::NoInputs))
        ));
        Ok(())
    }

    fn setup() -> MempoolImpl<ChainStateMock> {
        MempoolImpl::create(ChainStateMock::new())
    }

    #[test]
    fn tx_no_outputs() -> anyhow::Result<()> {
        let mut mempool = setup();
        let num_inputs = 1;
        let num_outputs = 0;
        let tx = TxGenerator::new(&mempool, num_inputs, num_outputs)
            .generate_tx()
            .expect("generate_tx failed");
        assert!(matches!(
            mempool.add_transaction(tx),
            Err(MempoolError::TxValidationError(
                TxValidationError::NoOutputs
            ))
        ));
        Ok(())
    }

    #[test]
    fn tx_duplicate_inputs() -> anyhow::Result<()> {
        let mut mempool = MempoolImpl::create(ChainStateMock::new());

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
            Err(MempoolError::TxValidationError(
                TxValidationError::DuplicateInputs
            ))
        ));
        Ok(())
    }

    #[test]
    fn tx_already_in_mempool() -> anyhow::Result<()> {
        let mut mempool = MempoolImpl::create(ChainStateMock::new());

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
            Err(MempoolError::TxValidationError(
                TxValidationError::TransactionAlreadyInMempool
            ))
        ));
        Ok(())
    }

    #[test]
    fn outpoint_not_found() -> anyhow::Result<()> {
        let mut mempool = MempoolImpl::create(ChainStateMock::new());

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
            Err(MempoolError::TxValidationError(
                TxValidationError::OutPointNotFound { .. }
            ))
        ));

        Ok(())
    }

    #[test]
    fn tx_too_big() -> anyhow::Result<()> {
        let mut mempool = setup();
        let num_inputs = 1;
        let num_outputs = 400_000;
        let tx = TxGenerator::new(&mempool, num_inputs, num_outputs)
            .generate_tx()
            .expect("generate_tx failed");
        assert!(matches!(
            mempool.add_transaction(tx),
            Err(MempoolError::TxValidationError(
                TxValidationError::ExceedsMaxBlockSize
            ))
        ));
        Ok(())
    }

    fn test_replace_tx(original_fee: Amount, replacement_fee: Amount) -> Result<(), MempoolError> {
        let mut mempool = setup();
        let num_inputs = 1;
        let num_outputs = 1;
        let tx = TxGenerator::new(&mempool, num_inputs, num_outputs)
            .with_fee(original_fee)
            .generate_replaceable_tx()
            .expect("generate_replaceable_tx");
        mempool.add_transaction(tx)?;

        let tx = TxGenerator::new(&mempool, num_inputs, num_outputs)
            .with_fee(replacement_fee)
            .generate_tx()
            .expect("generate_tx_failed");

        mempool.add_transaction(tx)?;
        Ok(())
    }

    #[test]
    fn tx_replace() -> anyhow::Result<()> {
        assert!(test_replace_tx(Amount::from_atoms(10), Amount::from_atoms(15)).is_ok());
        assert!(matches!(
            test_replace_tx(Amount::from_atoms(10), Amount::from_atoms(10)),
            Err(MempoolError::TxValidationError(
                TxValidationError::ReplacementFeeLowerThanOriginal
            ))
        ));
        assert!(matches!(
            test_replace_tx(Amount::from_atoms(10), Amount::from_atoms(5)),
            Err(MempoolError::TxValidationError(
                TxValidationError::ReplacementFeeLowerThanOriginal
            ))
        ));
        Ok(())
    }

    #[test]
    fn tx_replace_child() -> anyhow::Result<()> {
        // TODO this test doesn't test what it's supposed to test!
        let mut mempool = setup();
        let num_inputs = 1;
        let num_outputs = 1;
        let tx = TxGenerator::new_with_unconfirmed(&mempool, num_inputs, num_outputs)
            .generate_replaceable_tx()
            .expect("generate_replaceable_tx");
        mempool.add_transaction(tx.clone())?;

        let outpoint_source_id = OutPointSourceId::Transaction(tx.get_id());
        let child_tx_input = TxInput::new(
            outpoint_source_id,
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );
        // We want to test that even though it doesn't signal replaceability directly, the child tx is replaceable because it's parent signalled replaceability
        // replaced
        let flags = 0;
        let locktime = 0;
        let child_tx = tx_spend_input(&mempool, child_tx_input, None, flags, locktime)?;
        mempool.add_transaction(child_tx)?;
        Ok(())
    }

    fn tx_spend_input(
        mempool: &MempoolImpl<ChainStateMock>,
        input: TxInput,
        fee: Option<Amount>,
        flags: u32,
        locktime: u32,
    ) -> anyhow::Result<Transaction> {
        tx_spend_several_inputs(mempool, &[input], fee, flags, locktime)
    }

    fn tx_spend_several_inputs(
        mempool: &MempoolImpl<ChainStateMock>,
        inputs: &[TxInput],
        fee: impl Into<Option<Amount>>,
        flags: u32,
        locktime: u32,
    ) -> anyhow::Result<Transaction> {
        let input_value = inputs
            .iter()
            .map(|input| mempool.get_input_value(input))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .sum::<Option<_>>()
            .expect("tx_spend_input: overflow");

        let output_value = if let Some(fee) = fee.into() {
            (fee <= input_value)
                .then(|| (input_value - fee).expect("tx_spend_input: subtraction error"))
                .ok_or_else(|| anyhow::anyhow!("Not enough funds"))?
        } else {
            (input_value / 2).expect("tx_spend_input: division error")
        };

        Transaction::new(
            flags,
            inputs.to_owned(),
            vec![
                TxOutput::new(
                    output_value,
                    OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                ),
                TxOutput::new(
                    (input_value - output_value).expect("underflow"),
                    OutputPurpose::Transfer(Destination::AnyoneCanSpend),
                ),
            ],
            locktime,
        )
        .map_err(Into::into)
    }

    #[test]
    fn one_ancestor_signal_is_enough() -> anyhow::Result<()> {
        let mut mempool = setup();
        let num_inputs = 1;
        let num_outputs = 2;
        let tx = TxGenerator::new_with_unconfirmed(&mempool, num_inputs, num_outputs)
            .generate_tx()
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

        let original_fee = Amount::from_atoms(10);
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

        mempool.add_transaction(replaced_tx)?;

        let replacing_tx = Transaction::new(
            flags_irreplaceable,
            vec![input_with_irreplaceable_parent],
            vec![dummy_output],
            locktime,
        )?;

        mempool.add_transaction(replacing_tx)?;

        Ok(())
    }

    #[test]
    fn tx_mempool_entry_num_ancestors() -> anyhow::Result<()> {
        let mut mempool = setup();
        // Input different flag values just to make the hashes of these dummy transactions
        // different
        let tx1 = Transaction::new(1, vec![], vec![], 0).map_err(anyhow::Error::from)?;
        let tx2 = Transaction::new(2, vec![], vec![], 0).map_err(anyhow::Error::from)?;
        let tx3 = Transaction::new(3, vec![], vec![], 0).map_err(anyhow::Error::from)?;
        let tx4 = Transaction::new(4, vec![], vec![], 0).map_err(anyhow::Error::from)?;
        let tx5 = Transaction::new(5, vec![], vec![], 0).map_err(anyhow::Error::from)?;

        let tx6 = Transaction::new(6, vec![], vec![], 0).map_err(anyhow::Error::from)?;
        let fee = Amount::from_atoms(0);

        // Generation 1
        let tx1_parents = BTreeSet::default();
        let entry1 = TxMempoolEntry::new(tx1, fee, tx1_parents);
        let tx2_parents = BTreeSet::default();
        let entry2 = TxMempoolEntry::new(tx2, fee, tx2_parents);

        // Generation 2
        let tx3_parents = vec![entry1.tx_id(), entry2.tx_id()].into_iter().collect();
        let entry3 = TxMempoolEntry::new(tx3, fee, tx3_parents);

        // Generation 3
        let tx4_parents = vec![entry3.tx_id()].into_iter().collect();
        let tx5_parents = vec![entry3.tx_id()].into_iter().collect();
        let entry4 = TxMempoolEntry::new(tx4, fee, tx4_parents);
        let entry5 = TxMempoolEntry::new(tx5, fee, tx5_parents);

        // Generation 4
        let tx6_parents =
            vec![entry3.tx_id(), entry4.tx_id(), entry5.tx_id()].into_iter().collect();
        let entry6 = TxMempoolEntry::new(tx6, fee, tx6_parents);

        let entries = vec![entry1, entry2, entry3, entry4, entry5, entry6];
        let ids = entries.clone().into_iter().map(|entry| entry.tx_id()).collect::<Vec<_>>();

        for (index, entry) in entries.into_iter().enumerate() {
            println!("adding {}, (entry {})", entry.tx_id(), index + 1);
            mempool.store.add_tx(entry)?;
            println!(
                "after adding entry {}, store looks like this {:#?}",
                index + 1,
                mempool.store.txs_by_id
            );
        }

        let entry1 = mempool.store.get_entry(ids.get(0).expect("index")).expect("entry");
        let entry2 = mempool.store.get_entry(ids.get(1).expect("index")).expect("entry");
        let entry3 = mempool.store.get_entry(ids.get(2).expect("index")).expect("entry");
        let entry4 = mempool.store.get_entry(ids.get(3).expect("index")).expect("entry");
        let entry5 = mempool.store.get_entry(ids.get(4).expect("index")).expect("entry");
        let entry6 = mempool.store.get_entry(ids.get(5).expect("index")).expect("entry");
        assert_eq!(entry1.unconfirmed_ancestors(&mempool.store).len(), 0);
        assert_eq!(entry2.unconfirmed_ancestors(&mempool.store).len(), 0);
        assert_eq!(entry3.unconfirmed_ancestors(&mempool.store).len(), 2);
        assert_eq!(entry4.unconfirmed_ancestors(&mempool.store).len(), 3);
        assert_eq!(entry5.unconfirmed_ancestors(&mempool.store).len(), 3);
        assert_eq!(entry6.unconfirmed_ancestors(&mempool.store).len(), 5);

        //println!("entry1 {:#?}", entry1);
        assert_eq!(entry1.count_with_descendants(), 5);
        //assert_eq!(entry2.count_with_descendants(&mempool.store), 4);

        Ok(())
    }
}
