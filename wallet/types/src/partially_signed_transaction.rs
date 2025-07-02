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
        signature::{
            inputsig::InputWitness,
            sighash::{
                self,
                input_commitments::{
                    make_sighash_input_commitments_for_transaction_inputs, SighashInputCommitment,
                },
            },
            Signable, Transactable,
        },
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
pub enum PartiallySignedTransactionError {
    #[error("Failed to convert partially signed tx to signed")]
    FailedToConvertPartiallySignedTx(PartiallySignedTransaction),

    #[error("Failed to create transaction: {0}")]
    TxCreationError(TransactionCreationError),

    #[error("The number of witnesses does not match the number of inputs")]
    InvalidWitnessCount,

    #[error("The number of input utxos does not match the number of inputs")]
    InvalidInputUtxosCount,

    #[error("The number of destinations does not match the number of inputs")]
    InvalidDestinationsCount,

    #[error("The number of htlc secrets does not match the number of inputs")]
    InvalidHtlcSecretsCount,

    #[error("Error creating sighash input commitment: {0}")]
    SighashInputCommitmentCreationError(#[from] SighashInputCommitmentCreationError),
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct TokenAdditionalInfo {
    pub num_decimals: u8,
    pub ticker: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct PoolAdditionalInfo {
    pub staker_balance: Amount,
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct OrderAdditionalInfo {
    pub initially_asked: OutputValue,
    pub initially_given: OutputValue,
    pub ask_balance: Amount,
    pub give_balance: Amount,
}

/// Additional info for a partially signed Tx mainly used by hardware wallets to show info to the
/// user
#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct TxAdditionalInfo {
    token_info: BTreeMap<TokenId, TokenAdditionalInfo>,
    pool_info: BTreeMap<PoolId, PoolAdditionalInfo>,
    order_info: BTreeMap<OrderId, OrderAdditionalInfo>,
}

impl TxAdditionalInfo {
    pub fn new() -> Self {
        Self {
            token_info: BTreeMap::new(),
            pool_info: BTreeMap::new(),
            order_info: BTreeMap::new(),
        }
    }

    pub fn with_token_info(mut self, token_id: TokenId, info: TokenAdditionalInfo) -> Self {
        self.token_info.insert(token_id, info);
        self
    }

    pub fn with_pool_info(mut self, pool_id: PoolId, info: PoolAdditionalInfo) -> Self {
        self.pool_info.insert(pool_id, info);
        self
    }

    pub fn with_order_info(mut self, order_id: OrderId, info: OrderAdditionalInfo) -> Self {
        self.order_info.insert(order_id, info);
        self
    }

    pub fn add_token_info(&mut self, token_id: TokenId, info: TokenAdditionalInfo) {
        self.token_info.insert(token_id, info);
    }

    pub fn join(mut self, other: Self) -> Self {
        self.token_info.extend(other.token_info);
        self.pool_info.extend(other.pool_info);
        self.order_info.extend(other.order_info);
        Self {
            token_info: self.token_info,
            pool_info: self.pool_info,
            order_info: self.order_info,
        }
    }

    pub fn get_token_info(&self, token_id: &TokenId) -> Option<&TokenAdditionalInfo> {
        self.token_info.get(token_id)
    }

    pub fn get_pool_info(&self, pool_id: &PoolId) -> Option<&PoolAdditionalInfo> {
        self.pool_info.get(pool_id)
    }

    pub fn get_order_info(&self, order_id: &OrderId) -> Option<&OrderAdditionalInfo> {
        self.order_info.get(order_id)
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct PartiallySignedTransaction {
    tx: Transaction,
    witnesses: Vec<Option<InputWitness>>,

    input_utxos: Vec<Option<TxOutput>>,
    destinations: Vec<Option<Destination>>,

    htlc_secrets: Vec<Option<HtlcSecret>>,
    additional_info: TxAdditionalInfo,
}

impl PartiallySignedTransaction {
    pub fn new(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_info: TxAdditionalInfo,
    ) -> Result<Self, PartiallySignedTransactionError> {
        let htlc_secrets = htlc_secrets.unwrap_or_else(|| vec![None; tx.inputs().len()]);

        let this = Self {
            tx,
            witnesses,
            input_utxos,
            destinations,
            htlc_secrets,
            additional_info,
        };

        this.ensure_consistency()?;

        Ok(this)
    }

    pub fn ensure_consistency(&self) -> Result<(), PartiallySignedTransactionError> {
        ensure!(
            self.tx.inputs().len() == self.witnesses.len(),
            PartiallySignedTransactionError::InvalidWitnessCount
        );

        ensure!(
            self.tx.inputs().len() == self.input_utxos.len(),
            PartiallySignedTransactionError::InvalidInputUtxosCount,
        );

        ensure!(
            self.tx.inputs().len() == self.destinations.len(),
            PartiallySignedTransactionError::InvalidDestinationsCount
        );

        ensure!(
            self.tx.inputs().len() == self.htlc_secrets.len(),
            PartiallySignedTransactionError::InvalidHtlcSecretsCount
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

    pub fn into_signed_tx(self) -> Result<SignedTransaction, PartiallySignedTransactionError> {
        if self.all_signatures_available() {
            let witnesses = self.witnesses.into_iter().map(|w| w.expect("cannot fail")).collect();
            Ok(SignedTransaction::new(self.tx, witnesses)
                .map_err(PartiallySignedTransactionError::TxCreationError)?)
        } else {
            Err(PartiallySignedTransactionError::FailedToConvertPartiallySignedTx(self))
        }
    }

    pub fn additional_info(&self) -> &TxAdditionalInfo {
        &self.additional_info
    }

    pub fn make_sighash_input_commitments(
        &self,
    ) -> Result<Vec<SighashInputCommitment<'_>>, PartiallySignedTransactionError> {
        Ok(make_sighash_input_commitments(
            self.tx.inputs(),
            &self.input_utxos,
        )?)
    }
}

pub type SighashInputCommitmentCreationError =
    sighash::input_commitments::SighashInputCommitmentCreationError<std::convert::Infallible>;

pub fn make_sighash_input_commitments<'a>(
    tx_inputs: &[TxInput],
    input_utxos: &'a [Option<TxOutput>],
) -> Result<Vec<SighashInputCommitment<'a>>, SighashInputCommitmentCreationError> {
    make_sighash_input_commitments_for_transaction_inputs(
        tx_inputs,
        &sighash::input_commitments::TrivialUtxoProvider(input_utxos),
    )
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
