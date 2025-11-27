// Copyright (c) 2021-2025 RBB S.r.l
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

use thiserror::Error;

use serialization::{Decode, Encode};

use crate::{
    chain::{
        htlc::HtlcSecret,
        partially_signed_transaction::v1::PartiallySignedTransactionV1,
        signature::{
            inputsig::InputWitness,
            sighash::{
                self,
                input_commitments::{
                    make_sighash_input_commitments_for_transaction_inputs,
                    make_sighash_input_commitments_for_transaction_inputs_at_height,
                    SighashInputCommitment,
                },
            },
            Signable, Transactable,
        },
        tokens::TokenId,
        ChainConfig, Destination, OrderId, PoolId, SighashInputCommitmentVersion,
        SignedTransaction, Transaction, TransactionCreationError, TxInput, TxOutput,
    },
    primitives::BlockHeight,
};

mod additional_info;
#[cfg(test)]
mod tests;
mod v1;

pub use additional_info::{OrderAdditionalInfo, PoolAdditionalInfo, TxAdditionalInfo};

/// This determines what should be checked when a PartiallySignedTransaction is constructed.
pub enum PartiallySignedTransactionConsistencyCheck {
    /// Only do the cheap basic checks.
    Basic,

    /// Also check consistency of additional info.
    WithAdditionalInfo,
}

/// A partially signed transaction, which contains the transaction itself, some of the signatures
/// and certain additional info that is required to produce signatures.
///
/// Note: currently PartiallySignedTransaction's consistency checks require that the additional info
/// is present even if the inputs that need it are already signed.
///
/// Thought PartiallySignedTransaction is not part of the blockchain, it is still part of
/// the core's public interface:
/// 1) It is returned and consumed by the wallet CLI and RPC (in its encoded form).
/// 2) Through the wallet RPC, it is used by the bridge, whose e2m master agent puts
///    a PartiallySignedTransaction in the db to be read by the cosigner (and once the cosigner
///    handles the transaction, it is replaced by the normal SignedTransaction in the db).
/// 3) It is exposed in wasm-bindings via the `encode_partially_signed_transaction` and
///    `decode_partially_signed_transaction_to_js` functions.
///    The former returns it in its hex-encoded form and is expected to be used by Mojito
///    at some point.
///    The latter is currently only used by js tests in wasm-bindings and it's the only place
///    where its serialized form is exposed.
///
/// So:
/// 1) Expanding PartiallySignedTransaction can only be done by introducing an additional
///    enum variant (i.e. V2).
/// 2) Deprecating older versions may be tricky.
#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode, serde::Serialize)]
#[serde(tag = "type")]
pub enum PartiallySignedTransaction {
    // Note: in some places (in particular, in the wallet), we want to be able, given a byte
    // array, to interpret it as either Transaction, SignedTransaction or PartiallySignedTransaction.
    // Since SignedTransaction starts with Transaction, we can distinguish one from another
    // simply by the fact that the former will have more bytes. PartiallySignedTransaction,
    // on the other hand, starts with its enum discriminant byte. If it happens to be the same
    // as Transaction's version tag (the first byte of every Transaction), a PartiallySignedTransaction
    // can be erroneously interpreted as a Transaction or SignedTransaction, or vice versa.
    // To avoid this both now and in the future, PartiallySignedTransaction's starting discriminant
    // byte value was chosen to be noticeably bigger than the Transaction's version tag.
    #[codec(index = 64)]
    V1(PartiallySignedTransactionV1),
}

impl PartiallySignedTransaction {
    // Note: passing `None` for `htlc_secrets` is equivalent to passing a `Vec` of `None`s.
    pub fn new(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_info: TxAdditionalInfo,
        consistency_check: PartiallySignedTransactionConsistencyCheck,
    ) -> Result<Self, PartiallySignedTransactionError> {
        Ok(Self::V1(PartiallySignedTransactionV1::new(
            tx,
            witnesses,
            input_utxos,
            destinations,
            htlc_secrets,
            additional_info,
            consistency_check,
        )?))
    }

    pub fn ensure_consistency(
        &self,
        consistency_check: PartiallySignedTransactionConsistencyCheck,
    ) -> Result<(), PartiallySignedTransactionError> {
        match self {
            Self::V1(ptx) => ptx.ensure_consistency(consistency_check),
        }
    }

    pub fn with_witnesses(
        self,
        witnesses: Vec<Option<InputWitness>>,
    ) -> Result<Self, PartiallySignedTransactionError> {
        match self {
            Self::V1(ptx) => Ok(Self::V1(ptx.with_witnesses(witnesses)?)),
        }
    }

    pub fn tx(&self) -> &Transaction {
        match self {
            Self::V1(ptx) => ptx.tx(),
        }
    }

    pub fn take_tx(self) -> Transaction {
        match self {
            Self::V1(ptx) => ptx.take_tx(),
        }
    }

    pub fn input_utxos(&self) -> &[Option<TxOutput>] {
        match self {
            Self::V1(ptx) => ptx.input_utxos(),
        }
    }

    /// Input destinations
    pub fn destinations(&self) -> &[Option<Destination>] {
        match self {
            Self::V1(ptx) => ptx.input_destinations(),
        }
    }

    pub fn witnesses(&self) -> &[Option<InputWitness>] {
        match self {
            Self::V1(ptx) => ptx.witnesses(),
        }
    }

    pub fn htlc_secrets(&self) -> &[Option<HtlcSecret>] {
        match self {
            Self::V1(ptx) => ptx.htlc_secrets(),
        }
    }

    pub fn inputs_count(&self) -> usize {
        self.tx().inputs().len()
    }

    // Note: this function only checks that all inputs that require a signature have one.
    // I.e. it doesn't check whether a multisig input has all required signatures.
    // TODO: rename it at least or make private.
    pub fn all_signatures_available(&self) -> bool {
        match self {
            Self::V1(ptx) => ptx.all_signatures_available(),
        }
    }

    pub fn into_signed_tx(self) -> Result<SignedTransaction, PartiallySignedTransactionError> {
        match self {
            Self::V1(ptx) => ptx.into_signed_tx(),
        }
    }

    pub fn additional_info(&self) -> &TxAdditionalInfo {
        match self {
            Self::V1(ptx) => ptx.additional_info(),
        }
    }

    pub fn make_sighash_input_commitments(
        &self,
        version: SighashInputCommitmentVersion,
    ) -> Result<Vec<SighashInputCommitment<'_>>, PartiallySignedTransactionError> {
        Ok(make_sighash_input_commitments(
            self.tx().inputs(),
            self.input_utxos(),
            self.additional_info(),
            version,
        )?)
    }

    pub fn make_sighash_input_commitments_at_height(
        &self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
    ) -> Result<Vec<SighashInputCommitment<'_>>, PartiallySignedTransactionError> {
        Ok(make_sighash_input_commitments_at_height(
            self.tx().inputs(),
            self.input_utxos(),
            self.additional_info(),
            chain_config,
            block_height,
        )?)
    }
}

pub fn make_sighash_input_commitments_at_height<'a>(
    tx_inputs: &[TxInput],
    input_utxos: &'a [Option<TxOutput>],
    additional_info: &TxAdditionalInfo,
    chain_config: &ChainConfig,
    block_height: BlockHeight,
) -> Result<Vec<SighashInputCommitment<'a>>, SighashInputCommitmentCreationError> {
    make_sighash_input_commitments_for_transaction_inputs_at_height(
        tx_inputs,
        &sighash::input_commitments::TrivialUtxoProvider(input_utxos),
        additional_info,
        additional_info,
        chain_config,
        block_height,
    )
}

pub fn make_sighash_input_commitments<'a>(
    tx_inputs: &[TxInput],
    input_utxos: &'a [Option<TxOutput>],
    additional_info: &TxAdditionalInfo,
    version: SighashInputCommitmentVersion,
) -> Result<Vec<SighashInputCommitment<'a>>, SighashInputCommitmentCreationError> {
    make_sighash_input_commitments_for_transaction_inputs(
        tx_inputs,
        &sighash::input_commitments::TrivialUtxoProvider(input_utxos),
        additional_info,
        additional_info,
        version,
    )
}

impl From<PartiallySignedTransactionV1> for PartiallySignedTransaction {
    fn from(value: PartiallySignedTransactionV1) -> Self {
        Self::V1(value)
    }
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PartiallySignedTransactionError {
    #[error("Failed to convert partially signed tx to signed")]
    FailedToConvertPartiallySignedTx(Box<PartiallySignedTransaction>),

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

    #[error("Missing UTXO for input #{input_index}")]
    MissingUtxoForUtxoInput { input_index: usize },

    #[error("A UTXO for non-UTXO input #{input_index} is specified")]
    UtxoPresentForNonUtxoInput { input_index: usize },

    #[error("Additional info is missing for order {0}")]
    OrderAdditionalInfoMissing(OrderId),

    #[error("Additional info is missing for token {0}")]
    TokenAdditionalInfoMissing(TokenId),

    #[error("Additional info is missing for pool {0}")]
    PoolAdditionalInfoMissing(PoolId),

    #[error("Error creating sighash input commitment: {0}")]
    SighashInputCommitmentCreationError(#[from] SighashInputCommitmentCreationError),
}

pub type SighashInputCommitmentCreationError =
    sighash::input_commitments::SighashInputCommitmentCreationError<
        std::convert::Infallible,
        std::convert::Infallible,
        std::convert::Infallible,
    >;

impl Signable for PartiallySignedTransaction {
    fn inputs(&self) -> Option<&[TxInput]> {
        Some(self.tx().inputs())
    }

    fn outputs(&self) -> Option<&[TxOutput]> {
        Some(self.tx().outputs())
    }

    fn version_byte(&self) -> Option<u8> {
        Some(self.tx().version_byte())
    }

    fn flags(&self) -> Option<u128> {
        Some(self.tx().flags())
    }
}

impl Transactable for PartiallySignedTransaction {
    fn signatures(&self) -> Vec<Option<InputWitness>> {
        self.witnesses().to_vec()
    }
}
