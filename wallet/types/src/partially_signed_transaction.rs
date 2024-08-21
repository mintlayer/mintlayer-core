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
        htlc::HtlcSecret,
        signature::{inputsig::InputWitness, Signable, Transactable},
        Destination, SignedTransaction, Transaction, TransactionCreationError, TxInput, TxOutput,
    },
    primitives::Amount,
};
use serialization::{Decode, Encode};
use thiserror::Error;
use tx_verifier::input_check::signature_only_check::SignatureOnlyVerifiable;
use utils::ensure;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PartiallySignedTransactionCreationError {
    #[error("Failed to convert partially signed tx to signed")]
    FailedToConvertPartiallySignedTx(PartiallySignedTransaction),
    #[error("The number of output additional infos does not match the number of outputs")]
    InvalidOutputAdditionalInfoCount,
    #[error("Failed to create transaction: {0}")]
    TxCreationError(#[from] TransactionCreationError),
    #[error("The number of input utxos does not match the number of inputs")]
    InvalidInputUtxosCount,
    #[error("The number of destinations does not match the number of inputs")]
    InvalidDestinationsCount,
    #[error("The number of htlc secrets does not match the number of inputs")]
    InvalidHtlcSecretsCount,
}

/// Additional info for UTXOs
#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub enum UtxoAdditionalInfo {
    TokenInfo { num_decimals: u8, ticker: Vec<u8> },
    PoolInfo { staker_balance: Amount },
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct UtxoWithAdditionalInfo {
    pub utxo: TxOutput,
    pub additional_info: Option<UtxoAdditionalInfo>,
}

impl UtxoWithAdditionalInfo {
    pub fn new(utxo: TxOutput, additional_info: Option<UtxoAdditionalInfo>) -> Self {
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
    output_additional_infos: Vec<Option<UtxoAdditionalInfo>>,
}

impl PartiallySignedTransaction {
    pub fn new(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<UtxoWithAdditionalInfo>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        output_additional_infos: Vec<Option<UtxoAdditionalInfo>>,
    ) -> Result<Self, PartiallySignedTransactionCreationError> {
        ensure!(
            tx.inputs().len() == witnesses.len(),
            PartiallySignedTransactionCreationError::TxCreationError(
                TransactionCreationError::InvalidWitnessCount
            )
        );

        ensure!(
            tx.inputs().len() == input_utxos.len(),
            PartiallySignedTransactionCreationError::InvalidInputUtxosCount,
        );

        ensure!(
            tx.inputs().len() == destinations.len(),
            PartiallySignedTransactionCreationError::InvalidDestinationsCount
        );

        let htlc_secrets = htlc_secrets.unwrap_or_else(|| vec![None; tx.inputs().len()]);
        ensure!(
            htlc_secrets.len() == tx.inputs().len(),
            PartiallySignedTransactionCreationError::InvalidHtlcSecretsCount
        );

        ensure!(
            input_utxos.len() == witnesses.len(),
            PartiallySignedTransactionCreationError::TxCreationError(
                TransactionCreationError::InvalidWitnessCount
            )
        );

        ensure!(
            input_utxos.len() == destinations.len(),
            PartiallySignedTransactionCreationError::InvalidDestinationsCount
        );

        ensure!(
            tx.outputs().len() == output_additional_infos.len(),
            PartiallySignedTransactionCreationError::InvalidOutputAdditionalInfoCount
        );

        Ok(Self {
            tx,
            witnesses,
            input_utxos,
            destinations,
            htlc_secrets,
            output_additional_infos,
        })
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

    pub fn output_additional_infos(&self) -> &[Option<UtxoAdditionalInfo>] {
        &self.output_additional_infos
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

    pub fn into_signed_tx(
        self,
    ) -> Result<SignedTransaction, PartiallySignedTransactionCreationError> {
        if self.all_signatures_available() {
            let witnesses = self.witnesses.into_iter().map(|w| w.expect("cannot fail")).collect();
            Ok(SignedTransaction::new(self.tx, witnesses)?)
        } else {
            Err(PartiallySignedTransactionCreationError::FailedToConvertPartiallySignedTx(self))
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

impl SignatureOnlyVerifiable for PartiallySignedTransaction {}
