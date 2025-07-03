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
    primitives::{Amount, BlockHeight},
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

    pub fn order_info_iter(&self) -> impl Iterator<Item = (&'_ OrderId, &'_ OrderAdditionalInfo)> {
        self.order_info.iter()
    }
}

impl sighash::input_commitments::PoolInfoProvider for TxAdditionalInfo {
    type Error = std::convert::Infallible;

    fn get_pool_info(
        &self,
        pool_id: &PoolId,
    ) -> Result<Option<sighash::input_commitments::PoolInfo>, Self::Error> {
        Ok(
            self.pool_info.get(pool_id).map(|info| sighash::input_commitments::PoolInfo {
                staker_balance: info.staker_balance,
            }),
        )
    }
}

impl sighash::input_commitments::OrderInfoProvider for TxAdditionalInfo {
    type Error = std::convert::Infallible;

    fn get_order_info(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<sighash::input_commitments::OrderInfo>, Self::Error> {
        Ok(
            self.order_info.get(order_id).map(|info| sighash::input_commitments::OrderInfo {
                initially_asked: info.initially_asked.clone(),
                initially_given: info.initially_given.clone(),
                ask_balance: info.ask_balance,
                give_balance: info.give_balance,
            }),
        )
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

        #[cfg(debug_assertions)]
        {
            self.ensure_additional_info_completeness()?;
        }

        Ok(())
    }

    #[cfg(debug_assertions)]
    fn ensure_additional_info_completeness(&self) -> Result<(), PartiallySignedTransactionError> {
        use common::chain::{AccountCommand, OrderAccountCommand};

        let ensure_order_info_present =
            |order_id: &OrderId| -> Result<_, PartiallySignedTransactionError> {
                ensure!(
                    self.additional_info.get_order_info(order_id).is_some(),
                    PartiallySignedTransactionError::OrderAdditionalInfoMissing(*order_id)
                );
                Ok(())
            };
        let ensure_token_info_present =
            |token_id: &TokenId| -> Result<_, PartiallySignedTransactionError> {
                ensure!(
                    self.additional_info.get_token_info(token_id).is_some(),
                    PartiallySignedTransactionError::TokenAdditionalInfoMissing(*token_id)
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

        let check_tx_output = |output: &TxOutput| -> Result<(), PartiallySignedTransactionError> {
            match output {
                TxOutput::Transfer(output_value, _)
                | TxOutput::LockThenTransfer(output_value, _, _)
                | TxOutput::Burn(output_value)
                | TxOutput::Htlc(output_value, _) => {
                    output_value.token_v1_id().map(ensure_token_info_present).transpose()?;
                }
                TxOutput::CreateOrder(order_data) => {
                    order_data.ask().token_v1_id().map(ensure_token_info_present).transpose()?;
                    order_data.give().token_v1_id().map(ensure_token_info_present).transpose()?;
                }
                TxOutput::ProduceBlockFromStake(_, pool_id) => {
                    ensure!(
                        self.additional_info.get_pool_info(pool_id).is_some(),
                        PartiallySignedTransactionError::PoolAdditionalInfoMissing(*pool_id)
                    );
                }

                TxOutput::CreateDelegationId(_, _)
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
                    check_tx_output(input_utxo)?;
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
                    let id = match command {
                        OrderAccountCommand::FillOrder(id, _, _) => id,
                        OrderAccountCommand::FreezeOrder(id) => id,
                        OrderAccountCommand::ConcludeOrder(id) => id,
                    };
                    ensure_order_info_present(id)?
                }
            }
        }

        for output in self.tx.outputs() {
            check_tx_output(output)?;
        }

        for (_, order_info) in self.additional_info.order_info_iter() {
            order_info
                .initially_asked
                .token_v1_id()
                .map(ensure_token_info_present)
                .transpose()?;
            order_info
                .initially_given
                .token_v1_id()
                .map(ensure_token_info_present)
                .transpose()?;
        }

        Ok(())
    }

    pub fn with_witnesses(
        mut self,
        witnesses: Vec<Option<InputWitness>>,
    ) -> Result<Self, PartiallySignedTransactionError> {
        self.witnesses = witnesses;
        self.ensure_consistency()?;
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

impl SignatureOnlyVerifiable for PartiallySignedTransaction {}
