// Copyright (c) 2024 RBB S.r.l
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

use common::chain::{
    signature::{inputsig::InputWitness, verify_signature, Signable, Transactable},
    ChainConfig, Destination, SignedTransaction, Transaction, TransactionCreationError, TxInput,
    TxOutput,
};
use serialization::{Decode, Encode};
use utils::ensure;

use crate::{WalletError, WalletResult};

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct PartiallySignedTransaction {
    tx: Transaction,
    witnesses: Vec<Option<InputWitness>>,

    input_utxos: Vec<Option<TxOutput>>,
    destinations: Vec<Option<Destination>>,
}

impl PartiallySignedTransaction {
    pub fn new(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
    ) -> WalletResult<Self> {
        ensure!(
            tx.inputs().len() == witnesses.len(),
            TransactionCreationError::InvalidWitnessCount
        );

        ensure!(
            input_utxos.len() == witnesses.len(),
            TransactionCreationError::InvalidWitnessCount
        );

        ensure!(
            input_utxos.len() == destinations.len(),
            TransactionCreationError::InvalidWitnessCount
        );

        Ok(Self {
            tx,
            witnesses,
            input_utxos,
            destinations,
        })
    }

    pub fn new_witnesses(mut self, witnesses: Vec<Option<InputWitness>>) -> Self {
        self.witnesses = witnesses;
        self
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    pub fn take_tx(self) -> Transaction {
        self.tx
    }

    pub fn input_utxos(&self) -> &[Option<TxOutput>] {
        self.input_utxos.as_ref()
    }

    pub fn destinations(&self) -> &[Option<Destination>] {
        self.destinations.as_ref()
    }

    pub fn witnesses(&self) -> &[Option<InputWitness>] {
        self.witnesses.as_ref()
    }

    pub fn count_inputs(&self) -> usize {
        self.tx.inputs().len()
    }

    pub fn count_completed_signatures(&self) -> usize {
        self.witnesses.iter().filter(|w| w.is_some()).count()
    }

    pub fn is_fully_signed(&self, chain_config: &ChainConfig) -> bool {
        let inputs_utxos_refs: Vec<_> = self.input_utxos.iter().map(|out| out.as_ref()).collect();
        self.witnesses
            .iter()
            .enumerate()
            .zip(&self.destinations)
            .all(|((input_num, w), d)| match (w, d) {
                (Some(InputWitness::NoSignature(_)), None) => true,
                (Some(InputWitness::NoSignature(_)), Some(_)) => false,
                (Some(InputWitness::Standard(_)), None) => false,
                (Some(InputWitness::Standard(_)), Some(dest)) => {
                    // FIXME: move to into_signed_tx?
                    verify_signature(chain_config, dest, self, &inputs_utxos_refs, input_num)
                        .is_ok()
                }
                (None, _) => false,
            })
    }

    pub fn into_signed_tx(self, chain_config: &ChainConfig) -> WalletResult<SignedTransaction> {
        if self.is_fully_signed(chain_config) {
            let witnesses = self.witnesses.into_iter().map(|w| w.expect("cannot fail")).collect();
            Ok(SignedTransaction::new(self.tx, witnesses)?)
        } else {
            Err(WalletError::FailedToConvertPartiallySignedTx(self))
        }
    }
}

impl Signable for PartiallySignedTransaction {
    fn inputs(&self) -> Option<&[TxInput]> {
        Some(self.tx.inputs())
    }

    fn outputs(&self) -> Option<&[TxOutput]> {
        Some(self.tx.outputs())
    }

    fn version_byte(&self) -> Option<u8> {
        Some(self.tx.version_byte())
    }

    fn flags(&self) -> Option<u128> {
        Some(self.tx.flags())
    }
}

impl Transactable for PartiallySignedTransaction {
    fn signatures(&self) -> Vec<Option<InputWitness>> {
        self.witnesses.clone()
    }
}
