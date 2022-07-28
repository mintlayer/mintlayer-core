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
                let tx = self.confirmed_txs.get(&tx_id.get()).expect("Inconsistent Chain State");
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
        let spent_outpoints = inputs.iter().map(|input| input.outpoint()).collect::<BTreeSet<_>>();
        self.coin_pool
            .retain(|outpoint| !spent_outpoints.iter().any(|spent| **spent == outpoint.outpoint));
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
    let outputs = tx_spend_input(&mempool, good_input, None, flags, locktime)?.outputs().clone();

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
    log::debug!(
        "tx_replace_tx: original_fee: {:?}, replacement_fee {:?}",
        original_fee,
        replacement_fee
    );
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
    log::debug!("created a tx with fee {:?}", mempool.try_get_fee(&original));
    mempool.add_transaction(original)?;

    let flags = 0;
    let replacement = tx_spend_input(&mempool, input, replacement_fee, flags, locktime)
        .expect("should be able to spend here");
    log::debug!(
        "created a replacement with fee {:?}",
        mempool.try_get_fee(&replacement)
    );
    mempool.add_transaction(replacement)?;
    assert!(!mempool.contains_transaction(&original_id));

    Ok(())
}

#[test]
fn try_replace_irreplaceable() -> anyhow::Result<()> {
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
    let flags = 0;
    let locktime = 0;
    let original_fee = Amount::from_atoms(get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE));
    let original = tx_spend_input(&mempool, input.clone(), original_fee, flags, locktime)
        .expect("should be able to spend here");
    let original_id = original.get_id();
    mempool.add_transaction(original)?;

    let flags = 0;
    let replacement_fee = (original_fee + Amount::from_atoms(1000)).unwrap();
    let replacement = tx_spend_input(&mempool, input, replacement_fee, flags, locktime)
        .expect("should be able to spend here");
    assert!(matches!(
        mempool.add_transaction(replacement.clone()),
        Err(Error::TxValidationError(
            TxValidationError::ConflictWithIrreplaceableTransaction
        ))
    ));

    mempool.drop_transaction(&original_id);
    mempool.add_transaction(replacement)?;

    Ok(())
}

#[test]
fn tx_replace() -> anyhow::Result<()> {
    let relay_fee = get_relay_fee_from_tx_size(TX_SPEND_INPUT_SIZE);
    let replacement_fee = Amount::from_atoms(relay_fee + 100);
    test_replace_tx(Amount::from_atoms(100), replacement_fee)?;
    let res = test_replace_tx(Amount::from_atoms(300), replacement_fee);
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
const TX_SPEND_INPUT_SIZE: usize = 213;

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
fn one_ancestor_replaceability_signal_is_enough() -> anyhow::Result<()> {
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
    let entry1 = TxMempoolEntry::new(txs.get(0).unwrap().clone(), fee, tx1_parents, time::get());
    let tx2_parents = BTreeSet::default();
    let entry2 = TxMempoolEntry::new(txs.get(1).unwrap().clone(), fee, tx2_parents, time::get());

    // Generation 2
    let tx3_parents = vec![entry1.tx_id(), entry2.tx_id()].into_iter().collect();
    let entry3 = TxMempoolEntry::new(txs.get(2).unwrap().clone(), fee, tx3_parents, time::get());

    // Generation 3
    let tx4_parents = vec![entry3.tx_id()].into_iter().collect();
    let tx5_parents = vec![entry3.tx_id()].into_iter().collect();
    let entry4 = TxMempoolEntry::new(txs.get(3).unwrap().clone(), fee, tx4_parents, time::get());
    let entry5 = TxMempoolEntry::new(txs.get(4).unwrap().clone(), fee, tx5_parents, time::get());

    // Generation 4
    let tx6_parents = vec![entry3.tx_id(), entry4.tx_id(), entry5.tx_id()].into_iter().collect();
    let entry6 = TxMempoolEntry::new(txs.get(5).unwrap().clone(), fee, tx6_parents, time::get());

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
    let child_0_fee = mempool.try_get_fee(&child_0)?;
    log::debug!("FeeRate of child_0 {:?}", child_0_fee);
    assert_eq!(
        rolling_fee,
        *INCREMENTAL_RELAY_FEE_RATE
            + FeeRate::from_total_tx_fee(child_0_fee, child_0.encoded_size())
    );
    assert_eq!(rolling_fee, FeeRate::new(Amount::from_atoms(3582)));
    log::debug!(
        "minimum rolling fee after child_0's eviction {:?}",
        rolling_fee
    );
    assert_eq!(
        rolling_fee,
        FeeRate::from_total_tx_fee(mempool.try_get_fee(&child_0)?, child_0.encoded_size())
            + *INCREMENTAL_RELAY_FEE_RATE
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
    log::debug!(
        "before child2: fee = {:?}, size = {}, minimum fee rate = {:?}",
        mempool.try_get_fee(&child_2)?,
        child_2.encoded_size(),
        mempool.get_minimum_rolling_fee()
    );
    let res = mempool.add_transaction(child_2);
    log::debug!("result of adding child2 {:?}", res);
    assert!(matches!(
        res,
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
        mempool.get_minimum_rolling_fee().compute_fee(estimate_tx_size(1, 1)),
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
    // We are going to submit dummy txs to the mempool incrementing time by this halflife
    // between txs. Finally, when the fee rate falls under INCREMENTAL_RELAY_THRESHOLD, we
    // observer that it is set to zero
    let halflife = ROLLING_FEE_BASE_HALFLIFE / 4;
    mock_clock.increment(halflife);
    let dummy_tx = TxGenerator::new().with_fee(Amount::from_atoms(100)).generate_tx(&mempool)?;
    log::debug!(
        "First attempt to add dummy which pays a fee of {:?}",
        mempool.try_get_fee(&dummy_tx)?
    );
    let res = mempool.add_transaction(dummy_tx.clone());

    log::debug!("Result of first attempt to add dummy: {:?}", res);
    assert!(matches!(
        res,
        Err(Error::TxValidationError(
            TxValidationError::RollingFeeThresholdNotMet { .. }
        ))
    ));
    log::debug!(
        "minimum rolling fee after first attempt to add dummy: {:?}",
        mempool.get_minimum_rolling_fee()
    );
    assert_eq!(
        mempool.get_minimum_rolling_fee(),
        rolling_fee / std::num::NonZeroU128::new(2).expect("nonzero")
    );

    mock_clock.increment(halflife);
    log::debug!("Second attempt to add dummy");
    mempool.add_transaction(dummy_tx)?;
    log::debug!(
        "minimum rolling fee after first second to add dummy: {:?}",
        mempool.get_minimum_rolling_fee()
    );
    assert_eq!(
        mempool.get_minimum_rolling_fee(),
        rolling_fee / std::num::NonZeroU128::new(4).expect("nonzero")
    );
    log::debug!(
        "After successful addition of dummy, rolling fee rate is {:?}",
        mempool.get_minimum_rolling_fee()
    );

    // Add another dummmy until rolling feerate drops to zero
    mock_clock.increment(halflife);
    let another_dummy =
        TxGenerator::new().with_fee(Amount::from_atoms(100)).generate_tx(&mempool)?;
    mempool.add_transaction(another_dummy)?;
    assert_eq!(
        mempool.get_minimum_rolling_fee(),
        FeeRate::new(Amount::from_atoms(0))
    );

    Ok(())
}

#[test]
fn different_size_txs() -> anyhow::Result<()> {
    let mut mempool = setup();
    let initial_tx = TxGenerator::new()
        .with_num_inputs(1)
        .with_num_outputs(10_000)
        .generate_tx(&mempool)?;
    mempool.add_transaction(initial_tx)?;

    let target_txs = 100;
    for i in 0..target_txs {
        let num_inputs = i + 1;
        let num_outputs = i + 1;
        let tx = TxGenerator::new()
            .with_num_inputs(num_inputs)
            .with_num_outputs(num_outputs)
            .generate_tx(&mempool)?;
        mempool.add_transaction(tx)?;
    }

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

    let tx_b_fee = Amount::from_atoms(get_relay_fee_from_tx_size(estimate_tx_size(1, 2)));
    let tx_a_fee = (tx_b_fee + Amount::from_atoms(1000)).unwrap();
    let tx_c_fee = (tx_a_fee + Amount::from_atoms(1000)).unwrap();
    let tx_a = tx_spend_input(
        &mempool,
        TxInput::new(
            outpoint_source_id.clone(),
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        ),
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
        TxInput::new(
            outpoint_source_id,
            1,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        ),
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
            OutPointSourceId::Transaction(tx_b_id),
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
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

#[test]
fn descendant_of_expired_entry() -> anyhow::Result<()> {
    let mock_clock = MockClock::new();
    logging::init_logging::<&str>(None);

    let mut mempool = MempoolImpl::create(
        ChainStateMock::new(),
        mock_clock.clone(),
        SystemUsageEstimator {},
    );

    let num_inputs = 1;
    let num_outputs = 2;
    let fee = get_relay_fee_from_tx_size(estimate_tx_size(num_inputs, num_outputs));
    let parent = TxGenerator::new()
        .with_num_inputs(num_inputs)
        .with_num_outputs(num_outputs)
        .with_fee(Amount::from_atoms(fee))
        .generate_tx(&mempool)?;
    let parent_id = parent.get_id();
    mempool.add_transaction(parent)?;

    let flags = 0;
    let locktime = 0;
    let outpoint_source_id = OutPointSourceId::Transaction(parent_id);
    let child = tx_spend_input(
        &mempool,
        TxInput::new(
            outpoint_source_id,
            0,
            InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
        ),
        None,
        flags,
        locktime,
    )?;
    let child_id = child.get_id();
    mock_clock.set(DEFAULT_MEMPOOL_EXPIRY + Duration::new(1, 0));

    assert!(matches!(
        mempool.add_transaction(child),
        Err(Error::TxValidationError(
            TxValidationError::DescendantOfExpiredTransaction
        ))
    ));

    assert!(!mempool.contains_transaction(&parent_id));
    assert!(!mempool.contains_transaction(&child_id));
    Ok(())
}

#[test]
fn mempool_full() -> anyhow::Result<()> {
    logging::init_logging::<&str>(None);
    let mut mock_usage = MockGetMemoryUsage::new();
    mock_usage
        .expect_get_memory_usage()
        .times(1)
        .return_const(MAX_MEMPOOL_SIZE_BYTES + 1);

    let chain_state = ChainStateMock::new();
    let mut mempool = MempoolImpl::create(chain_state, SystemClock, mock_usage);

    let tx = TxGenerator::new().generate_tx(&mempool)?;
    log::debug!("mempool_full: tx has is {}", tx.get_id().get());
    assert!(matches!(
        mempool.add_transaction(tx),
        Err(Error::MempoolFull)
    ));
    Ok(())
}

#[test]
fn no_empty_bags_in_descendant_score_index() -> anyhow::Result<()> {
    let mut mempool = setup();

    let num_inputs = 1;
    let num_outputs = 100;
    let fee = get_relay_fee_from_tx_size(estimate_tx_size(num_inputs, num_outputs));
    let parent = TxGenerator::new()
        .with_num_inputs(num_inputs)
        .with_num_outputs(num_outputs)
        .with_fee(Amount::from_atoms(fee))
        .generate_tx(&mempool)?;
    let parent_id = parent.get_id();

    let outpoint_source_id = OutPointSourceId::Transaction(parent.get_id());
    mempool.add_transaction(parent)?;
    let num_child_txs = num_outputs;
    let flags = 0;
    let locktime = 0;
    let txs = (0..num_child_txs)
        .into_iter()
        .map(|i| {
            tx_spend_input(
                &mempool,
                TxInput::new(
                    outpoint_source_id.clone(),
                    u32::try_from(i).unwrap(),
                    InputWitness::NoSignature(Some(DUMMY_WITNESS_MSG.to_vec())),
                ),
                Amount::from_atoms(fee + u128::try_from(i).unwrap()),
                flags,
                locktime,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let ids = txs.iter().map(|tx| tx.get_id()).collect::<Vec<_>>();

    for tx in txs {
        mempool.add_transaction(tx)?;
    }

    mempool.drop_transaction(&parent_id);
    for id in ids {
        mempool.drop_transaction(&id)
    }
    assert!(mempool.store.txs_by_descendant_score.is_empty());
    Ok(())
}
