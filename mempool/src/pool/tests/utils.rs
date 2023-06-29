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

use common::chain::tokens::OutputValue;
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

use super::*;

mockall::mock! {
    pub MemoryUsageEstimator {}

    impl MemoryUsageEstimator for MemoryUsageEstimator {
        fn estimate_memory_usage(&self, store: &MempoolStore) -> usize;
    }
}

impl TxStatus {
    /// Fetch status of given instruction from mempool, doing some integrity checks
    pub fn fetch<T>(mempool: &Mempool<T>, tx_id: &Id<Transaction>) -> Option<Self> {
        let in_mempool = mempool.contains_transaction(tx_id);
        let in_orphan_pool = mempool.contains_orphan_transaction(tx_id);
        match (in_mempool, in_orphan_pool) {
            (false, false) => None,
            (false, true) => Some(TxStatus::InOrphanPool),
            (true, false) => Some(TxStatus::InMempool),
            (true, true) => panic!("Transaction {tx_id} both in mempool and orphan pool"),
        }
    }

    /// Assert the status of the transaction that the tx is in mempool
    pub fn assert_in_mempool(&self) {
        assert!(self.in_mempool());
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ValuedOutPoint {
    pub outpoint: UtxoOutPoint,
    pub value: Amount,
}

impl PartialOrd for ValuedOutPoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        other.value.partial_cmp(&self.value)
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

pub async fn try_get_fee<M>(mempool: &Mempool<M>, tx: &SignedTransaction) -> Fee {
    let tx_clone = tx.clone();

    // Outputs in this vec are:
    //     Some(Amount) if the outpoint was found in the mainchain
    //     None         if the outpoint wasn't found in the mainchain (maybe it's in the mempool?)
    let chainstate_input_values = mempool
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
                &mempool.store,
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
    let tx_id = *outpoint.tx_id().get_tx_id().expect("Not a transaction");
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
    match val {
        OutputValue::Coin(amt) => *amt,
        OutputValue::Token(_) => Amount::ZERO,
    }
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

    std::iter::repeat_with(move || {
        let n_inputs = rng.gen_range(1..=std::cmp::min(3, utxos.len()));
        let n_outputs = rng.gen_range(1..=3);

        let mut builder = TransactionBuilder::new();
        let mut total = 0u128;
        let mut amts = Vec::new();

        for _ in 0..n_inputs {
            let (outpt, amt) = utxos.swap_remove(rng.gen_range(0..utxos.len()));
            total += amt;
            builder = builder.add_input(outpt, empty_witness(rng));
        }

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

        TxEntryWithFee::new(TxEntry::new(tx, time), Fee::new(Amount::from_atoms(total)))
    })
}
