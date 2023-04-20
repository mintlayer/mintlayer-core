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
use common::chain::OutPoint;
use common::primitives::H256;

use super::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ValuedOutPoint {
    pub outpoint: OutPoint,
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
    TxInput::new(outpoint_source_id, output_index)
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
    let locktime = 0;
    let size = SignedTransaction::new(
        Transaction::new(flags, inputs, outputs, locktime).unwrap(),
        witnesses,
    )
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

// TODO this calculation is already done in ChainState, reuse it
pub async fn try_get_fee<M>(mempool: &Mempool<M>, tx: &SignedTransaction) -> Fee
where
    M: GetMemoryUsage,
{
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
                tx.transaction().inputs().get(i).expect("index").outpoint(),
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
pub fn get_unconfirmed_outpoint_value(store: &MempoolStore, outpoint: &OutPoint) -> Amount {
    let tx_id = *outpoint.tx_id().get_tx_id().expect("Not a transaction");
    let entry = store.txs_by_id.get(&tx_id).expect("Entry not found");
    let tx = entry.tx().transaction();
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
