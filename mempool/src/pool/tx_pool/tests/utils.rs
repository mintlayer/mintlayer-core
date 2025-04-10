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

use common::chain::output_value::OutputValue;
use common::chain::UtxoOutPoint;
use common::primitives::H256;

// Re-export various testing utils from other crates
pub use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
pub use logging::log;
pub use rstest::rstest;
pub use test_utils::{
    mock_time_getter::mocked_time_getter_seconds,
    random::{make_seedable_rng, CryptoRng, Rng, Seed},
};

pub use memory_usage_estimator::StoreMemoryUsageEstimator;

use super::*;

pub const DUMMY_WITNESS_MSG: &[u8] = b"dummy_witness_msg";

/// Max tip age of about 100 years, useful to avoid the IBD state during testing
pub const HUGE_MAX_TIP_AGE: MaxTipAge =
    MaxTipAge::new(Duration::from_secs(100 * 365 * 24 * 60 * 60));

pub const TEST_MIN_TX_RELAY_FEE_RATE: FeeRate =
    FeeRate::from_amount_per_kb(Amount::from_atoms(1000));

pub fn create_mempool_config() -> ConstValue<MempoolConfig> {
    ConstValue::new(MempoolConfig {
        min_tx_relay_fee_rate: TEST_MIN_TX_RELAY_FEE_RATE.into(),
    })
}

pub fn get_relay_fee_from_tx_size(tx_size: usize) -> Amount {
    TEST_MIN_TX_RELAY_FEE_RATE.compute_fee(tx_size).unwrap().into()
}

mockall::mock! {
    pub MemoryUsageEstimator {}

    impl MemoryUsageEstimator for MemoryUsageEstimator {
        fn estimate_memory_usage(&self, store: &MempoolStore) -> usize;
    }
}

impl<M: MemoryUsageEstimator> TxPool<M> {
    /// Create transaction with some default values for testing.
    ///
    /// Origin is set to a default value and work queue is set to be temporary one and the orphans
    /// are immediately processed. If the test needs to adjust the origin or a different orphan
    /// behavior it should use [Mempool::add_transaction] directly.
    pub fn make_transaction_test(&self, tx: SignedTransaction) -> TxEntry {
        let origin = TxOrigin::Remote(RemoteTxOrigin::new(p2p_types::PeerId::from_u64(1)));
        let creation_time = self.clock.get_time();
        let options = TxOptions::default_for(origin);
        TxEntry::new(tx, creation_time, origin, options)
    }

    pub fn add_transaction_test(&mut self, tx: SignedTransaction) -> Result<TxStatus, Error> {
        self.add_transaction_bare(self.make_transaction_test(tx))
    }

    pub fn add_transaction_bare(&mut self, tx: TxEntry) -> Result<TxStatus, Error> {
        self.add_transaction(tx, |outcome, _| match outcome {
            TxAdditionOutcome::Added { .. } => Ok(TxStatus::InMempool),
            TxAdditionOutcome::Duplicate { .. } => Ok(TxStatus::InMempoolDuplicate),
            TxAdditionOutcome::Rejected { error, .. } => Err(error.into()),
        })?
    }

    pub fn get_minimum_rolling_fee(&self) -> FeeRate {
        self.rolling_fee_rate.read().rolling_minimum_fee_rate()
    }

    pub fn on_new_tip(
        &mut self,
        block_id: Id<Block>,
        block_height: BlockHeight,
    ) -> Result<(), ReorgError> {
        self.reorg(block_id, block_height, |_, _| ())
    }
}

// Expose some transaction pool internals via mempool for testing
impl<M: MemoryUsageEstimator> crate::pool::Mempool<M> {
    pub fn tx_pool(&self) -> &TxPool<M> {
        &self.tx_pool
    }

    pub fn tx_store(&self) -> &MempoolStore {
        &self.tx_pool.store
    }
}

pub trait TxStatusExt: Sized {
    /// Assert the status of the transaction that the tx is in mempool
    fn assert_in_mempool(&self);

    /// Assert the status of the transaction that the tx is in orphan pool
    fn assert_in_orphan_pool(&self);
}

impl TxStatusExt for TxStatus {
    fn assert_in_mempool(&self) {
        assert!(self.in_mempool());
    }

    fn assert_in_orphan_pool(&self) {
        assert!(self.in_orphan_pool());
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ValuedOutPoint {
    pub outpoint: UtxoOutPoint,
    pub value: Amount,
}

impl PartialOrd for ValuedOutPoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ValuedOutPoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other.value.cmp(&self.value)
    }
}

fn dummy_witness() -> InputWitness {
    let witness = DUMMY_WITNESS_MSG.to_vec();
    InputWitness::NoSignature(Some(witness))
}

fn dummy_input() -> TxInput {
    let outpoint_source_id = OutPointSourceId::Transaction(Id::new(H256::zero()));
    let output_index = 0;
    TxInput::from_utxo(outpoint_source_id, output_index)
}

fn dummy_output() -> TxOutput {
    let value = Amount::from_atoms(0);
    TxOutput::Transfer(OutputValue::Coin(value), Destination::AnyoneCanSpend)
}

pub fn estimate_tx_size(num_inputs: usize, num_outputs: usize) -> usize {
    let witnesses: Vec<InputWitness> = (0..num_inputs).map(|_| dummy_witness()).collect();
    let inputs = (0..num_inputs).map(|_| dummy_input()).collect();
    let outputs = (0..num_outputs).map(|_| dummy_output()).collect();
    let flags = 0;
    let size = SignedTransaction::new(Transaction::new(flags, inputs, outputs).unwrap(), witnesses)
        .expect("invalid witness count")
        .encoded_size();
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

pub async fn try_get_fee<M>(tx_pool: &TxPool<M>, tx: &SignedTransaction) -> Fee {
    let tx_clone = tx.clone();

    // Outputs in this vec are:
    //     Some(Amount) if the outpoint was found in the mainchain
    //     None         if the outpoint wasn't found in the mainchain (maybe it's in the mempool?)
    let chainstate_input_values = tx_pool
        .chainstate_handle
        .call(move |this| this.get_inputs_outpoints_coin_amount(tx_clone.transaction().inputs()))
        .await
        .expect("chainstate to work")
        .expect("tx to exist");

    let mut input_values = Vec::<Amount>::new();
    for (i, chainstate_input_value) in chainstate_input_values.iter().enumerate() {
        if let Some(value) = chainstate_input_value {
            input_values.push(*value)
        } else {
            let value = get_unconfirmed_outpoint_value(
                &tx_pool.store,
                tx.transaction().inputs().get(i).expect("index").utxo_outpoint().unwrap(),
            );
            input_values.push(value);
        }
    }

    let sum_inputs =
        input_values.iter().cloned().sum::<Option<_>>().expect("input values overflow");
    let sum_outputs = tx
        .transaction()
        .outputs()
        .iter()
        .map(output_coin_amount)
        .sum::<Option<_>>()
        .expect("output values overflow");
    (sum_inputs - sum_outputs).expect("negative fee").into()
}

// unconfirmed means: The outpoint comes from a transaction in the mempool
pub fn get_unconfirmed_outpoint_value(store: &MempoolStore, outpoint: &UtxoOutPoint) -> Amount {
    let tx_id = *outpoint.source_id().get_tx_id().expect("Not a transaction");
    let entry = store.txs_by_id.get(&tx_id).expect("Entry not found");
    let tx = entry.transaction().transaction();
    let output = tx.outputs().get(outpoint.output_index() as usize).expect("output not found");
    output_coin_amount(output)
}

fn output_coin_amount(output: &TxOutput) -> Amount {
    let val = match output {
        TxOutput::Transfer(val, _) => val,
        TxOutput::LockThenTransfer(val, _, _) => val,
        _ => return Amount::ZERO,
    };
    val.coin_amount().unwrap_or(Amount::ZERO)
}

pub fn make_tx(
    rng: &mut (impl Rng + CryptoRng),
    ins: &[(OutPointSourceId, u32)],
    outs: &[u128],
) -> SignedTransaction {
    let builder = ins.iter().fold(TransactionBuilder::new(), |b, (s, n)| {
        b.add_input(TxInput::from_utxo(s.clone(), *n), empty_witness(rng))
    });
    let builder = outs.iter().fold(builder, |b, a| {
        b.add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(*a)),
            Destination::AnyoneCanSpend,
        ))
    });
    builder.build()
}

/// Generate a valid transaction graph.
///
/// This produces an infinite iterator but taking too many items may not be valid:
/// * The transaction fees may drop below minimum threshold.
/// * In extreme, 0-value outputs may be generated.
pub fn generate_transaction_graph(
    rng: &mut (impl Rng + CryptoRng),
    time: Time,
) -> impl Iterator<Item = TxEntryWithFee> + '_ {
    let tf = TestFramework::builder(rng).build();
    let mut utxos = vec![(
        TxInput::from_utxo(tf.genesis().get_id().into(), 0),
        100_000_000_000_000_u128,
    )];

    std::iter::from_fn(move || {
        let n_inputs = rng.gen_range(1..=std::cmp::min(3, utxos.len()));
        let n_outputs = rng.gen_range(1..=3);

        let estimated_fee = get_relay_fee_from_tx_size(estimate_tx_size(n_inputs, n_outputs));

        let mut builder = TransactionBuilder::new();
        let mut total = 0u128;
        let mut amts = Vec::new();

        for _ in 0..n_inputs {
            let (outpt, amt) = utxos.swap_remove(rng.gen_range(0..utxos.len()));
            total += amt;
            builder = builder.add_input(outpt, empty_witness(rng));
        }

        total = total.checked_sub(estimated_fee.into_atoms())?;

        for _ in 0..n_outputs {
            let amt = rng.gen_range((total / 2)..(95 * total / 100));
            total -= amt;
            builder = builder.add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(amt)),
                Destination::AnyoneCanSpend,
            ));
            amts.push(amt);
        }

        let tx = builder.build();
        let tx_id = tx.transaction().get_id();

        utxos.extend(
            amts.into_iter()
                .enumerate()
                .map(|(i, amt)| (TxInput::from_utxo(tx_id.into(), i as u32), amt)),
        );

        let origin = RemoteTxOrigin::new(p2p_types::PeerId::from_u64(1)).into();
        let options = crate::TxOptions::default_for(origin);
        let entry = TxEntry::new(tx, time, origin, options);
        Some(TxEntryWithFee::new(
            entry,
            Fee::new(Amount::from_atoms(total)),
        ))
    })
}

pub fn make_test_block(
    txs: Vec<SignedTransaction>,
    parent: impl Into<Id<GenBlock>>,
    time: BlockTimestamp,
) -> Block {
    Block::new(
        txs,
        parent.into(),
        time,
        ConsensusData::None,
        BlockReward::new(vec![]),
    )
    .unwrap()
}

pub fn setup() -> TxPool<StoreMemoryUsageEstimator> {
    logging::init_logging();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let chainstate_interface = start_chainstate_with_config(Arc::clone(&chain_config));
    TxPool::new(
        chain_config,
        create_mempool_config(),
        chainstate_interface,
        Default::default(),
        StoreMemoryUsageEstimator,
    )
}

pub fn setup_with_min_tx_relay_fee_rate(fee_rate: FeeRate) -> TxPool<StoreMemoryUsageEstimator> {
    logging::init_logging();
    let chain_config = Arc::new(common::chain::config::create_unit_test_config());
    let mempool_config = MempoolConfig {
        min_tx_relay_fee_rate: fee_rate.into(),
    };
    let chainstate_interface = start_chainstate_with_config(Arc::clone(&chain_config));
    TxPool::new(
        chain_config,
        mempool_config.into(),
        chainstate_interface,
        Default::default(),
        StoreMemoryUsageEstimator,
    )
}

pub fn setup_with_chainstate(
    chainstate: Box<dyn ChainstateInterface>,
) -> TxPool<StoreMemoryUsageEstimator> {
    logging::init_logging();
    let chain_config = Arc::clone(chainstate.get_chain_config());
    let chainstate_handle = start_chainstate(chainstate);
    TxPool::new(
        chain_config,
        create_mempool_config(),
        chainstate_handle,
        Default::default(),
        StoreMemoryUsageEstimator,
    )
}

pub fn start_chainstate(chainstate: Box<dyn ChainstateInterface>) -> chainstate::ChainstateHandle {
    let mut man = subsystem::Manager::new("TODO");
    let handle = man.add_subsystem("chainstate", chainstate);
    tokio::spawn(async move { man.main().await });
    handle
}

// Starts chainstate with given config. Also sets the max tip age chainstate setting to a huge
// value to prevent IBD state.
pub fn start_chainstate_with_config(
    chain_config: Arc<ChainConfig>,
) -> chainstate::ChainstateHandle {
    let storage = chainstate_storage::inmemory::Store::new_empty().unwrap();
    let chainstate_config = {
        let mut config = ChainstateConfig::new();
        config.max_tip_age = HUGE_MAX_TIP_AGE;
        config
    };
    let chainstate = make_chainstate(
        chain_config,
        chainstate_config,
        storage,
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
    )
    .unwrap();
    start_chainstate(chainstate)
}

// To test our validation of BIP125 Rule#4 (replacement transaction pays for its own bandwidth), we need to know the necessary relay fee before creating the transaction. The relay fee depends on the size of the transaction. The usual way to get the size of a transaction is to call `tx.encoded_size` but we cannot do this until we have created the transaction itself. To get around this cycle, we have precomputed the size of all transaction created by `tx_spend_input`. This value will be the same for all transactions created by this function.
pub const TX_SPEND_INPUT_SIZE: usize = 213;

pub async fn tx_spend_input<M>(
    tx_pool: &TxPool<M>,
    input: TxInput,
    witness: InputWitness,
    fee: impl Into<Option<Fee>>,
    flags: u128,
) -> anyhow::Result<SignedTransaction> {
    let fee = fee.into().map_or_else(
        || get_relay_fee_from_tx_size(estimate_tx_size(1, 2)).into(),
        std::convert::identity,
    );
    tx_spend_several_inputs(tx_pool, &[input], &[witness], fee, flags).await
}

pub async fn tx_spend_several_inputs<M>(
    tx_pool: &TxPool<M>,
    inputs: &[TxInput],
    witnesses: &[InputWitness],
    fee: Fee,
    flags: u128,
) -> anyhow::Result<SignedTransaction> {
    let mut input_values = Vec::new();
    let inputs = inputs.to_owned();
    for input in inputs.clone() {
        let outpoint = input.utxo_outpoint().unwrap().clone();
        let chainstate_outpoint_value = tx_pool
            .chainstate_handle
            .call(move |this| this.get_inputs_outpoints_coin_amount(&[input]))
            .await??;
        let input_value = match chainstate_outpoint_value.first().unwrap() {
            Some(input_value) => *input_value,
            None => get_unconfirmed_outpoint_value(&tx_pool.store, &outpoint),
        };
        input_values.push(input_value)
    }
    let input_value = input_values.into_iter().sum::<Option<_>>().ok_or_else(|| {
        let msg = String::from("tx_spend_input: overflow");
        log::error!("{}", msg);
        anyhow::Error::msg(msg)
    })?;

    let available_for_spending = (input_value - *fee).ok_or_else(|| {
        let msg = format!(
            "tx_spend_several_inputs: input_value ({input_value:?}) lower than fee ({fee:?})"
        );
        log::error!("{}", msg);
        anyhow::Error::msg(msg)
    })?;
    let spent = (available_for_spending / 2).expect("division error");

    let change = (available_for_spending - spent).ok_or_else(|| {
        let msg = String::from("Error computing change");
        anyhow::Error::msg(msg)
    })?;

    let tx: anyhow::Result<Transaction> = Transaction::new(
        flags,
        inputs.clone(),
        vec![
            TxOutput::Transfer(OutputValue::Coin(spent), Destination::AnyoneCanSpend),
            TxOutput::Transfer(OutputValue::Coin(change), Destination::AnyoneCanSpend),
        ],
    )
    .map_err(Into::into);
    let tx = tx?;
    SignedTransaction::new(tx, witnesses.to_vec())
        .map_err(|_| anyhow::Error::msg("invalid witness count"))
}
