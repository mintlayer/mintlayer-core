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
use utils::ensure;

use crate::{
    chain::{
        htlc::HtlcSecret,
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
        AccountCommand, ChainConfig, Destination, OrderAccountCommand, OrderId, PoolId,
        SighashInputCommitmentVersion, SignedTransaction, Transaction, TransactionCreationError,
        TxInput, TxOutput,
    },
    primitives::BlockHeight,
};

mod additional_info;

pub use additional_info::{OrderAdditionalInfo, PoolAdditionalInfo, TxAdditionalInfo};

/// This determines what should be checked when a PartiallySignedTransaction is constructed.
pub enum PartiallySignedTransactionConsistencyCheck {
    /// Only do the cheap basic checks.
    Basic,

    /// Also check consistency of additional info.
    WithAdditionalInfo,
}

/// A partially signed transaction, which contains the transaction itself, some of the signatures
/// and certain additional info, which is required to produce signatures.
///
/// Note: currently PartiallySignedTransaction's consistency checks require that the additional info
/// is present even if the inputs that need it are already signed.
///
/// Regarding the ability to refactor it, making non-backward-compatible changes.
/// Currently PartiallySignedTransaction is used:
/// 1) By the wallet. In this case the encoded transaction is supposed to be short-lived,
///    so breaking compatibility should be tolerable.
/// 2) By the bridge, whose e2m master agent puts a PartiallySignedTransaction in the db
///    to be read by the cosigner; once the cosigner handles the transaction, it is replaced
///    by the normal SignedTransaction in the db. I.e. breaking the compatibility is possible
///    provided that there are no partially signed e2m withdrawal transactions in the bridge db
///    during the update of wallet-rpc-daemon that is used by the bridge.
/// 3) By the Mojito and RioSwap teams, where the former construct a PartiallySignedTransaction
///    via the wasm call `encode_partially_signed_transaction` and the latter pass it to
///    wallet-rpc-daemon. The transaction is treated as a black box, so a breaking change is
///    technically possible, though it'll require synchronization between multiple teams.
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
    // Note: passing `None` for `htlc_secrets` is equivalent to passing a `Vec` of `None`s.
    pub fn new(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_info: TxAdditionalInfo,
        cosnsitency_check: PartiallySignedTransactionConsistencyCheck,
    ) -> Result<Self, PartiallySignedTransactionError> {
        let this = Self::new_unchecked(
            tx,
            witnesses,
            input_utxos,
            destinations,
            htlc_secrets,
            additional_info,
        );

        this.ensure_consistency(cosnsitency_check)?;
        Ok(this)
    }

    fn new_unchecked(
        tx: Transaction,
        witnesses: Vec<Option<InputWitness>>,
        input_utxos: Vec<Option<TxOutput>>,
        destinations: Vec<Option<Destination>>,
        htlc_secrets: Option<Vec<Option<HtlcSecret>>>,
        additional_info: TxAdditionalInfo,
    ) -> Self {
        let htlc_secrets = htlc_secrets.unwrap_or_else(|| vec![None; tx.inputs().len()]);

        Self {
            tx,
            witnesses,
            input_utxos,
            destinations,
            htlc_secrets,
            additional_info,
        }
    }

    pub fn ensure_consistency(
        &self,
        cosnsitency_check: PartiallySignedTransactionConsistencyCheck,
    ) -> Result<(), PartiallySignedTransactionError> {
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

        match cosnsitency_check {
            PartiallySignedTransactionConsistencyCheck::Basic => {}
            PartiallySignedTransactionConsistencyCheck::WithAdditionalInfo => {
                self.ensure_additional_info_completeness()?;
            }
        }

        Ok(())
    }

    // FIXME tests
    fn ensure_additional_info_completeness(&self) -> Result<(), PartiallySignedTransactionError> {
        let ensure_order_info_present =
            |order_id: &OrderId| -> Result<_, PartiallySignedTransactionError> {
                ensure!(
                    self.additional_info.get_order_info(order_id).is_some(),
                    PartiallySignedTransactionError::OrderAdditionalInfoMissing(*order_id)
                );
                Ok(())
            };

        let ensure_no_utxo = |input_index,
                              input_utxo_opt: &Option<TxOutput>|
         -> Result<_, PartiallySignedTransactionError> {
            ensure!(
                input_utxo_opt.is_none(),
                PartiallySignedTransactionError::UtxoPresentForNonUtxoInput { input_index }
            );
            Ok(())
        };

        let check_utxo = |output: &TxOutput| -> Result<(), PartiallySignedTransactionError> {
            match output {
                TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    ensure!(
                        self.additional_info.get_pool_info(pool_id).is_some(),
                        PartiallySignedTransactionError::PoolAdditionalInfoMissing(*pool_id)
                    );
                }
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::Burn(_)
                | TxOutput::Htlc(_, _)
                | TxOutput::CreateOrder(_)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_) => {}
            }
            Ok(())
        };

        for (input_index, (input, input_utxo)) in
            self.tx.inputs().iter().zip(self.input_utxos.iter()).enumerate()
        {
            match input {
                TxInput::Utxo(_) => {
                    let input_utxo = input_utxo.as_ref().ok_or(
                        PartiallySignedTransactionError::MissingUtxoForUtxoInput { input_index },
                    )?;
                    check_utxo(input_utxo)?;
                }
                TxInput::Account(_) => ensure_no_utxo(input_index, input_utxo)?,
                TxInput::AccountCommand(_, command) => {
                    ensure_no_utxo(input_index, input_utxo)?;

                    match command {
                        AccountCommand::ConcludeOrder(id) => ensure_order_info_present(id)?,
                        AccountCommand::FillOrder(id, _, _) => ensure_order_info_present(id)?,

                        AccountCommand::MintTokens(_, _)
                        | AccountCommand::UnmintTokens(_)
                        | AccountCommand::LockTokenSupply(_)
                        | AccountCommand::FreezeToken(_, _)
                        | AccountCommand::UnfreezeToken(_)
                        | AccountCommand::ChangeTokenAuthority(_, _)
                        | AccountCommand::ChangeTokenMetadataUri(_, _) => {}
                    }
                }
                TxInput::OrderAccountCommand(command) => {
                    // FIXME somehow re-use input commitment machinery?
                    match command {
                        OrderAccountCommand::FillOrder(id, _)
                        | OrderAccountCommand::ConcludeOrder(id) => ensure_order_info_present(id)?,

                        OrderAccountCommand::FreezeOrder(_) => {}
                    };
                }
            }
        }

        Ok(())
    }

    pub fn with_witnesses(
        mut self,
        witnesses: Vec<Option<InputWitness>>,
    ) -> Result<Self, PartiallySignedTransactionError> {
        ensure!(
            witnesses.len() == self.tx.inputs().len(),
            PartiallySignedTransactionError::InvalidWitnessCount
        );
        self.witnesses = witnesses;
        Ok(self)
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

    /// Input destinations
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

    // Note: this function only checks that all inputs that require a signature have one.
    // I.e. it doesn't check whether a multisig input has all required signatures.
    // TODO: rename it at least or make private.
    pub fn all_signatures_available(&self) -> bool {
        self.witnesses
            .iter()
            .enumerate()
            .zip(&self.destinations)
            .all(|((_, witness), dest)| {
                let dest_needs_signature = match dest {
                    Some(dest) => match dest {
                        Destination::AnyoneCanSpend => false,
                        Destination::PublicKeyHash(_)
                        | Destination::PublicKey(_)
                        | Destination::ScriptHash(_)
                        | Destination::ClassicMultisig(_) => true,
                    },
                    None => false,
                };

                match (witness, dest_needs_signature) {
                    (Some(InputWitness::NoSignature(_)), false) => true,
                    (Some(InputWitness::NoSignature(_)), true) => false,
                    // TODO: consider returning a Result and produce an error in this case.
                    (Some(InputWitness::Standard(_)), false) => false,
                    (Some(InputWitness::Standard(_)), true) => true,
                    (None, _) => false,
                }
            })
    }

    pub fn into_signed_tx(self) -> Result<SignedTransaction, PartiallySignedTransactionError> {
        if self.all_signatures_available() {
            let witnesses = self.witnesses.into_iter().map(|w| w.expect("cannot fail")).collect();
            Ok(SignedTransaction::new(self.tx, witnesses)
                .map_err(PartiallySignedTransactionError::TxCreationError)?)
        } else {
            Err(PartiallySignedTransactionError::FailedToConvertPartiallySignedTx(Box::new(self)))
        }
    }

    pub fn additional_info(&self) -> &TxAdditionalInfo {
        &self.additional_info
    }

    pub fn make_sighash_input_commitments(
        &self,
        version: SighashInputCommitmentVersion,
    ) -> Result<Vec<SighashInputCommitment<'_>>, PartiallySignedTransactionError> {
        Ok(make_sighash_input_commitments(
            self.tx.inputs(),
            &self.input_utxos,
            &self.additional_info,
            version,
        )?)
    }

    pub fn make_sighash_input_commitments_at_height(
        &self,
        chain_config: &ChainConfig,
        block_height: BlockHeight,
    ) -> Result<Vec<SighashInputCommitment<'_>>, PartiallySignedTransactionError> {
        Ok(make_sighash_input_commitments_at_height(
            self.tx.inputs(),
            &self.input_utxos,
            &self.additional_info,
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
