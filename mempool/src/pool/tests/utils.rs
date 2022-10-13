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

use common::primitives::H256;

use super::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub(in crate::pool::tests) struct ValuedOutPoint {
    pub(in crate::pool::tests) outpoint: OutPoint,
    pub(in crate::pool::tests) value: Amount,
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
    let purpose = OutputPurpose::Transfer(Destination::AnyoneCanSpend);
    TxOutput::new(OutputValue::Coin(value), purpose)
}

pub(in crate::pool::tests) fn estimate_tx_size(num_inputs: usize, num_outputs: usize) -> usize {
    let witnesses: Vec<InputWitness> =
        (0..num_inputs).into_iter().map(|_| dummy_witness()).collect();
    let inputs = (0..num_inputs).into_iter().map(|_| dummy_input()).collect();
    let outputs = (0..num_outputs).into_iter().map(|_| dummy_output()).collect();
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
