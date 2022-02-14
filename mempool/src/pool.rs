use std::cmp::Ord;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Debug;
use std::rc::Rc;

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

#[derive(Debug, PartialEq, Eq, Clone)]
struct TxMempoolEntry {
    tx: Transaction,
    fee: Amount,
    parents: BTreeSet<Rc<TxMempoolEntry>>,
}

trait TryGetFee {
    fn try_get_fee(&self, tx: &Transaction) -> Result<Amount, TxValidationError>;
}

impl TxMempoolEntry {
    fn new<C: ChainState>(tx: Transaction, pool: &MempoolImpl<C>) -> Option<TxMempoolEntry> {
        let parents = tx
            .inputs()
            .iter()
            .filter_map(|input| {
                pool.store
                    .txs_by_id
                    .get(&input.outpoint().tx_id().get_tx_id().expect("Not coinbase").get())
            })
            .cloned()
            .collect::<BTreeSet<_>>();

        let fee = pool.try_get_fee(&tx).ok()?;

        Some(Self { tx, fee, parents })
    }
    fn is_replaceable(&self) -> bool {
        self.tx.is_replaceable()
            || self.unconfirmed_ancestors().iter().any(|ancestor| ancestor.tx.is_replaceable())
    }

    fn unconfirmed_ancestors(&self) -> BTreeSet<Rc<TxMempoolEntry>> {
        let mut visited = BTreeSet::new();
        self.unconfirmed_ancestors_inner(&mut visited);
        visited
    }

    fn unconfirmed_ancestors_inner(&self, visited: &mut BTreeSet<Rc<TxMempoolEntry>>) {
        for parent in self.parents.iter() {
            if visited.contains(parent) {
                continue;
            } else {
                visited.insert(Rc::clone(parent));
                parent.unconfirmed_ancestors_inner(visited);
            }
        }
    }
}

impl PartialOrd for TxMempoolEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(other.tx.get_id().get().cmp(&self.tx.get_id().get()))
    }
}

impl Ord for TxMempoolEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other.tx.get_id().get().cmp(&self.tx.get_id().get())
    }
}

#[derive(Debug)]
pub struct MempoolImpl<C: ChainState> {
    store: MempoolStore,
    chain_state: C,
}

#[derive(Debug)]
struct MempoolStore {
    txs_by_id: HashMap<H256, Rc<TxMempoolEntry>>,
    txs_by_fee: BTreeMap<Amount, BTreeSet<Rc<TxMempoolEntry>>>,
    spender_txs: BTreeMap<OutPoint, Rc<TxMempoolEntry>>,
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

    fn add_tx(&mut self, entry: TxMempoolEntry) -> Result<(), MempoolError> {
        let id = entry.tx.get_id().get();
        let entry = Rc::new(entry);
        self.txs_by_id.insert(id, Rc::clone(&entry));
        self.txs_by_fee.entry(entry.fee).or_default().insert(Rc::clone(&entry));

        for outpoint in entry.tx.inputs().iter().map(|input| input.outpoint()) {
            self.spender_txs.insert(outpoint.clone(), Rc::clone(&entry));
        }
        Ok(())
    }

    fn drop_tx(&mut self, tx_id: &Id<Transaction>) {
        if let Some(entry) = self.txs_by_id.remove(&tx_id.get()) {
            self.txs_by_fee.entry(entry.fee).and_modify(|entries| {
                entries.remove(&entry).then(|| ()).expect("Inconsistent mempool store")
            });
            self.spender_txs.retain(|_, entry| entry.tx.get_id() != *tx_id)
        } else {
            assert!(!self.txs_by_fee.values().flatten().any(|entry| entry.tx.get_id() == *tx_id));
            assert!(!self.spender_txs.iter().any(|(_, entry)| entry.tx.get_id() == *tx_id));
        }
    }

    fn find_conflicting_tx(&self, outpoint: &OutPoint) -> Option<Rc<TxMempoolEntry>> {
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
            .collect::<Vec<_>>();

        for entry in conflicts {
            if !entry.is_replaceable() {
                return Err(TxValidationError::ConflictWithIrreplaceableTransaction);
            }
        }

        self.verify_inputs_available(tx)?;

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
        let entry = TxMempoolEntry::new(tx, self)
            .ok_or_else(|| MempoolError::from(TxValidationError::TransactionFeeOverflow))?;
        self.store.add_tx(entry)?;
        Ok(())
    }

    fn get_all(&self) -> Vec<&Transaction> {
        self.store.txs_by_fee.values().flatten().map(|entry| &entry.tx).collect()
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
            }
        }

        fn generate_tx(&mut self) -> anyhow::Result<Transaction> {
            let valued_inputs = self.generate_tx_inputs();
            let outputs = self.generate_tx_outputs(&valued_inputs)?;
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
            let outputs = self.generate_tx_outputs(&valued_inputs)?;
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
        ) -> anyhow::Result<Vec<TxOutput>> {
            if self.num_outputs == 0 {
                return Ok(vec![]);
            }

            let inputs: Vec<_> = inputs.to_owned();
            let (inputs, values): (Vec<TxInput>, Vec<Amount>) = inputs.into_iter().unzip();
            if inputs.is_empty() {
                return Ok(vec![]);
            }
            let max_spend =
                values.into_iter().sum::<Option<_>>().expect("Overflow in sum of input values");

            let mut left_to_spend = max_spend;
            let mut outputs = Vec::new();

            let max_output_value = Amount::from_atoms(1_000);
            for _ in 0..self.num_outputs {
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
        let input = TxInput::new(
            outpoint_source_id,
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );
        let outputs = spend_input(&mempool, &input)?;

        let flags = 0;
        let inputs = vec![input];
        let locktime = 0;
        let tx = Transaction::new(flags, inputs, outputs, locktime)
            .map_err(|e| anyhow::anyhow!("failed to create transaction: {:?}", e))?;

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

    fn spend_input(
        mempool: &MempoolImpl<ChainStateMock>,
        input: &TxInput,
    ) -> anyhow::Result<Vec<TxOutput>> {
        let outpoint = input.outpoint();
        let input_value = mempool.chain_state.get_outpoint_value(outpoint).or_else(|_| {
            mempool
                .available_outpoints()
                .iter()
                .find_map(|valued_outpoint| {
                    (valued_outpoint.outpoint == *outpoint).then(|| valued_outpoint.value)
                })
                .ok_or_else(|| anyhow::anyhow!("No such unconfirmed output"))
        })?;
        let output_value = (input_value / 2).expect("failed to divide input");
        let output_pay = TxOutput::new(
            output_value,
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        );
        let output_change_amount = (input_value - output_value).expect("underflow");
        let output_change = TxOutput::new(
            output_change_amount,
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        );
        Ok(vec![output_pay, output_change])
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
        let outputs = spend_input(&mempool, &input)?;
        let inputs = vec![input, duplicate_input];
        let flags = 0;
        let locktime = 0;
        let tx = Transaction::new(flags, inputs, outputs, locktime)
            .map_err(|e| anyhow::anyhow!("failed to create transaction: {:?}", e))?;

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
        let outputs = spend_input(&mempool, &input)?;

        let flags = 0;
        let inputs = vec![input];
        let locktime = 0;
        let tx = Transaction::new(flags, inputs, outputs, locktime)?;

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
        let outputs = spend_input(&mempool, &good_input)?;
        let bad_outpoint_index = 1;
        let bad_input = TxInput::new(
            outpoint_source_id,
            bad_outpoint_index,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );

        let flags = 0;
        let inputs = vec![bad_input];
        let locktime = 0;
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

    #[test]
    fn tx_replace() -> anyhow::Result<()> {
        let mut mempool = setup();
        let num_inputs = 1;
        let num_outputs = 1;
        let tx = TxGenerator::new(&mempool, num_inputs, num_outputs)
            .generate_replaceable_tx()
            .expect("generate_replaceable_tx");
        mempool.add_transaction(tx)?;

        let tx = TxGenerator::new(&mempool, num_inputs, num_outputs)
            .generate_tx()
            .expect("generate_tx_failed");

        mempool.add_transaction(tx)?;
        Ok(())
    }

    #[test]
    fn tx_replace_child() -> anyhow::Result<()> {
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
        let outputs = spend_input(&mempool, &child_tx_input)?;
        let inputs = vec![child_tx_input];
        let child_tx = Transaction::new(flags, inputs, outputs, locktime)?;
        mempool.add_transaction(child_tx)?;
        Ok(())
    }

    fn tx_spend_input(
        mempool: &MempoolImpl<ChainStateMock>,
        input: TxInput,
        flags: u32,
        locktime: u32,
    ) -> anyhow::Result<Transaction> {
        let input_value = mempool
            .available_outpoints()
            .iter()
            .find_map(|valued_outpoint| {
                (valued_outpoint.outpoint == *input.outpoint()).then(|| valued_outpoint.value)
            })
            .ok_or_else(|| anyhow::anyhow!("No such unconfirmed output"))?;
        let output_value = (input_value / 2).expect("failed to divide input");
        let output_pay = TxOutput::new(
            output_value,
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        );
        let output_change_amount = (input_value - output_value).expect("underflow");
        let output_change = TxOutput::new(
            output_change_amount,
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        );
        let outputs = vec![output_pay, output_change];
        let inputs = vec![input];
        Transaction::new(flags, inputs, outputs, locktime).map_err(Into::into)
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

        let outpoint_source_id = OutPointSourceId::Transaction(tx.get_id());
        let replaceable_input = TxInput::new(
            outpoint_source_id.clone(),
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );
        let other_input = TxInput::new(
            outpoint_source_id,
            1,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        );

        let flags_replaceable = 1;
        let flags_irreplaceable = 0;
        let locktime = 0;

        let ancestor_with_signal =
            tx_spend_input(&mempool, replaceable_input, flags_replaceable, locktime)?;

        let ancestor_without_signal =
            tx_spend_input(&mempool, other_input, flags_irreplaceable, locktime)?;

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
        let dummy_output = TxOutput::new(
            Amount::from_atoms(0),
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        );

        let replaced_tx = Transaction::new(
            flags_irreplaceable,
            vec![input_with_irreplaceable_parent.clone(), input_with_replaceable_parent],
            vec![dummy_output.clone()],
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
}
