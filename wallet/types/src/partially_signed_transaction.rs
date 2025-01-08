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

use std::collections::BTreeMap;

use common::{
    chain::{
        htlc::HtlcSecret,
        output_value::OutputValue,
        signature::{inputsig::InputWitness, Signable, Transactable},
        tokens::TokenId,
        Destination, OrderId, PoolId, SignedTransaction, Transaction, TransactionCreationError,
        TxInput, TxOutput,
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
    #[error("Failed to create transaction: {0}")]
    TxCreationError(#[from] TransactionCreationError),
    #[error("The number of input utxos does not match the number of inputs")]
    InvalidInputUtxosCount,
    #[error("The number of destinations does not match the number of inputs")]
    InvalidDestinationsCount,
    #[error("The number of htlc secrets does not match the number of inputs")]
    InvalidHtlcSecretsCount,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Encode, Decode)]
pub enum InfoId {
    PoolId(PoolId),
    TokenId(TokenId),
    OrderId(OrderId),
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct TokenAdditionalInfo {
    pub num_decimals: u8,
    pub ticker: Vec<u8>,
}

/// Additional info for a partially signed Tx mainly used by hardware wallets to show info to the
/// user
#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub enum TxAdditionalInfo {
    TokenInfo(TokenAdditionalInfo),
    PoolInfo {
        staker_balance: Amount,
    },
    OrderInfo {
        initially_asked: OutputValue,
        initially_given: OutputValue,
        ask_balance: Amount,
        give_balance: Amount,
    },
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct PartiallySignedTransaction {
    tx: Transaction,
    witnesses: Vec<Option<InputWitness>>,

    input_utxos: Vec<Option<TxOutput>>,
    destinations: Vec<Option<Destination>>,

    htlc_secrets: Vec<Option<HtlcSecret>>,
    additional_infos: BTreeMap<InfoId, TxAdditionalInfo>,
}

impl PartiallySignedTransaction {
    pub fn new(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_infos: BTreeMap<InfoId, TxAdditionalInfo>,
    ) -> Result<Self, PartiallySignedTransactionCreationError> {
        let htlc_secrets = htlc_secrets.unwrap_or_else(|| vec![None; tx.inputs().len()]);

        let this = Self {
            tx,
            witnesses,
            input_utxos,
            destinations,
            htlc_secrets,
            additional_infos,
        };

        this.ensure_consistency()?;

        Ok(this)
    }

    pub fn ensure_consistency(&self) -> Result<(), PartiallySignedTransactionCreationError> {
        ensure!(
            self.tx.inputs().len() == self.witnesses.len(),
            TransactionCreationError::InvalidWitnessCount
        );

        ensure!(
            self.tx.inputs().len() == self.input_utxos.len(),
            PartiallySignedTransactionCreationError::InvalidInputUtxosCount,
        );

        ensure!(
            self.tx.inputs().len() == self.destinations.len(),
            PartiallySignedTransactionCreationError::InvalidDestinationsCount
        );

        ensure!(
            self.tx.inputs().len() == self.htlc_secrets.len(),
            PartiallySignedTransactionCreationError::InvalidHtlcSecretsCount
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

    pub fn input_utxos(&self) -> &[Option<TxOutput>] {
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

    pub fn additional_infos(&self) -> &BTreeMap<InfoId, TxAdditionalInfo> {
        &self.additional_infos
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
