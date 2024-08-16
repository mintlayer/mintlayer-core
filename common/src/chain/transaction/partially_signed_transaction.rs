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

use super::{
    htlc::HtlcSecret,
    signature::{inputsig::InputWitness, Signable, Transactable},
    Destination, Transaction, TxOutput,
};
use crate::{
    chain::{SignedTransaction, TransactionCreationError, TxInput},
    primitives::Amount,
};
use serialization::{Decode, Encode};
use utils::ensure;

/// Additional info for UTXOs
#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub enum UtxoAdditionalInfo {
    TokenInfo { num_decimals: u8, ticker: Vec<u8> },
    PoolInfo { staker_balance: Amount },
    NoAdditionalInfo,
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct UtxoWithAdditionalInfo {
    pub utxo: TxOutput,
    pub additional_info: UtxoAdditionalInfo,
}

impl UtxoWithAdditionalInfo {
    pub fn new(utxo: TxOutput, additional_info: UtxoAdditionalInfo) -> Self {
        Self {
            utxo,
            additional_info,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct PartiallySignedTransaction {
    tx: Transaction,
    witnesses: Vec<Option<InputWitness>>,

    input_utxos: Vec<Option<UtxoWithAdditionalInfo>>,
    destinations: Vec<Option<Destination>>,

    htlc_secrets: Vec<Option<HtlcSecret>>,
}

impl PartiallySignedTransaction {
    pub fn new(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<UtxoWithAdditionalInfo>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
    ) -> Result<Self, TransactionCreationError> {
        let htlc_secrets = htlc_secrets.unwrap_or_else(|| vec![None; tx.inputs().len()]);

        let this = Self {
            tx,
            witnesses,
            input_utxos,
            destinations,
            htlc_secrets,
        };

        this.ensure_consistency()?;

        Ok(this)
    }

    pub fn ensure_consistency(&self) -> Result<(), TransactionCreationError> {
        ensure!(
            self.tx.inputs().len() == self.witnesses.len(),
            TransactionCreationError::InvalidWitnessCount
        );

        ensure!(
            self.tx.inputs().len() == self.input_utxos.len(),
            TransactionCreationError::InvalidInputUtxosCount,
        );

        ensure!(
            self.tx.inputs().len() == self.destinations.len(),
            TransactionCreationError::InvalidDestinationsCount
        );

        ensure!(
            self.tx.inputs().len() == self.htlc_secrets.len(),
            TransactionCreationError::InvalidHtlcSecretsCount
        );

        Ok(())
    }

    pub fn with_witnesses(mut self, witnesses: Vec<Option<InputWitness>>) -> Self {
        self.witnesses = witnesses;
        self
    }

    pub fn tx(&self) -> &Transaction {
        &self.tx
    }

    pub fn take_tx(self) -> Transaction {
        self.tx
    }

    pub fn input_utxos(&self) -> &[Option<UtxoWithAdditionalInfo>] {
        self.input_utxos.as_ref()
    }

    pub fn destinations(&self) -> &[Option<Destination>] {
        self.destinations.as_ref()
    }

    pub fn witnesses(&self) -> &[Option<InputWitness>] {
        self.witnesses.as_ref()
    }

    pub fn htlc_secrets(&self) -> &[Option<HtlcSecret>] {
        self.htlc_secrets.as_ref()
    }

    pub fn count_inputs(&self) -> usize {
        self.tx.inputs().len()
    }

    pub fn all_signatures_available(&self) -> bool {
        self.witnesses
            .iter()
            .enumerate()
            .zip(&self.destinations)
            .all(|((_, w), d)| match (w, d) {
                (Some(InputWitness::NoSignature(_)), None) => true,
                (Some(InputWitness::NoSignature(_)), Some(_)) => false,
                (Some(InputWitness::Standard(_)), None) => false,
                (Some(InputWitness::Standard(_)), Some(_)) => true,
                (None, _) => false,
            })
    }

    pub fn into_signed_tx(self) -> Result<SignedTransaction, TransactionCreationError> {
        if self.all_signatures_available() {
            let witnesses = self.witnesses.into_iter().map(|w| w.expect("cannot fail")).collect();
            Ok(SignedTransaction::new(self.tx, witnesses)?)
        } else {
            Err(TransactionCreationError::FailedToConvertPartiallySignedTx(
                self,
            ))
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
