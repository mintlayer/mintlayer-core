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

use common::{
    chain::{
        signature::inputsig::InputWitness, signed_transaction::SignedTransaction,
        tokens::OutputValue, Destination, OutputPurpose, Transaction, TxInput, TxOutput,
    },
    primitives::Amount,
};
use rstest::rstest;

/// The transaction builder.
pub struct TransactionBuilder {
    flags: u32,
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    witnesses: Vec<InputWitness>,
    lock_time: u32,
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            flags: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            witnesses: Vec::new(),
            lock_time: 0,
        }
    }

    pub fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_inputs(mut self, inputs: Vec<TxInput>) -> Self {
        self.inputs = inputs;
        self
    }

    pub fn with_witnesses(mut self, witnesses: Vec<InputWitness>) -> Self {
        self.witnesses = witnesses;
        self
    }

    pub fn add_input(mut self, input: TxInput, witness: InputWitness) -> Self {
        self.inputs.push(input);
        self.witnesses.push(witness);
        self
    }

    pub fn with_outputs(mut self, outputs: Vec<TxOutput>) -> Self {
        self.outputs = outputs;
        self
    }

    pub fn add_output(mut self, output: TxOutput) -> Self {
        self.outputs.push(output);
        self
    }

    /// Adds an output with the "anyone can spend" destination.
    pub fn add_anyone_can_spend_output(self, amount: u128) -> Self {
        self.add_output(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(amount)),
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        ))
    }

    pub fn with_lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = lock_time;
        self
    }

    pub fn build(self) -> SignedTransaction {
        SignedTransaction::new(
            Transaction::new(self.flags, self.inputs, self.outputs, self.lock_time).unwrap(),
            self.witnesses,
        )
        .expect("invalid witness count")
    }
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
fn build_transaction(#[case] seed: test_utils::random::Seed) {
    use common::chain::signature::inputsig::InputWitness;
    use common::chain::OutPointSourceId;
    use common::primitives::Id;
    use common::primitives::H256;

    let mut rng = test_utils::random::make_seedable_rng(seed);

    let flags = 1;
    let lock_time = 2;
    let witness = InputWitness::NoSignature(None);
    let input = TxInput::new(
        OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng))),
        0,
    );

    let tx = TransactionBuilder::new()
        .with_flags(flags)
        .with_inputs(vec![input.clone()])
        .with_witnesses(vec![InputWitness::NoSignature(None)])
        .add_input(input.clone(), witness)
        .with_outputs(vec![TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(100)),
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        )])
        .add_output(TxOutput::new(
            OutputValue::Coin(Amount::from_atoms(200)),
            OutputPurpose::Transfer(Destination::AnyoneCanSpend),
        ))
        .with_lock_time(lock_time)
        .build();

    assert_eq!(flags, tx.transaction().flags());
    assert_eq!(&vec![input.clone(), input], tx.transaction().inputs());
    assert_eq!(lock_time, tx.transaction().lock_time());
}
