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

use std::collections::BTreeSet;

use chainstate_types::PropertyQueryError;
use common::{
    chain::{
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{get_tokens_issuance_count, NftIssuance},
        AccountCommand, ChainConfig, ChangeTokenMetadataUriActivated, HtlcActivated, OrderId,
        OrdersVersion, SignedTransaction, TokenIssuanceVersion, Transaction, TransactionSize,
        TxInput, TxOutput,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Id, Idable},
};
use thiserror::Error;
use utils::ensure;

use crate::{
    error::TokensError,
    transaction_verifier::tokens_check::{check_nft_issuance_data, check_tokens_issuance},
};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckTransactionError {
    #[error("Blockchain storage error: {0}")]
    PropertyQueryError(#[from] PropertyQueryError),
    #[error("Duplicate input in transaction {0}")]
    DuplicateInputInTransaction(Id<Transaction>),
    #[error("Number of signatures differs from number of inputs in tx {0}")]
    InvalidWitnessCount(Id<Transaction>),
    #[error("Empty inputs in transaction {0} found")]
    EmptyInputsInTransaction(Id<Transaction>),
    #[error("Tokens error: {0}")]
    TokensError(TokensError),
    #[error("No signature data size is too large: {0} > {1} in tx {2}")]
    NoSignatureDataSizeTooLarge(usize, usize, Id<Transaction>),
    #[error("No signature data is not allowed. Found in transaction {0}")]
    NoSignatureDataNotAllowed(Id<Transaction>),
    #[error("Data deposit size {0} exceeded max allowed {1}. Found in transaction {2}")]
    DataDepositMaxSizeExceeded(usize, usize, Id<Transaction>),
    #[error("The size if tx {0} is too large: {1} > {2}")]
    TxSizeTooLarge(Id<Transaction>, usize, usize),
    #[error("Token version {0:?} from tx {1} is deprecated")]
    DeprecatedTokenOperationVersion(TokenIssuanceVersion, Id<Transaction>),
    #[error("Htlcs are not activated yet")]
    HtlcsAreNotActivated,
    #[error("Orders from tx {0} are not yet activated")]
    OrdersAreNotActivated(Id<Transaction>),
    #[error("Orders V1 from tx {0} are not yet activated")]
    OrdersV1AreNotActivated(Id<Transaction>),
    #[error("Order inputs from tx {0} are deprecated")]
    DeprecatedOrdersCommands(Id<Transaction>),
    #[error("Orders currencies from tx {0} are the same")]
    OrdersCurrenciesMustBeDifferent(Id<Transaction>),
    #[error("Change token metadata uri not activated yet")]
    ChangeTokenMetadataUriNotActivated,
    #[error("Cannot fill order {0} with zero amount in tx {1}")]
    AttemptToFillOrderWithZero(OrderId, Id<Transaction>),
}

pub fn check_transaction(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    tx: &SignedTransaction,
) -> Result<(), CheckTransactionError> {
    check_size(chain_config, tx)?;
    check_duplicate_inputs(tx)?;
    check_witness_count(tx)?;
    check_tokens_tx(chain_config, block_height, tx)?;
    check_no_signature_size(chain_config, tx)?;
    check_data_deposit_outputs(chain_config, block_height, tx)?;
    check_htlc_outputs(chain_config, block_height, tx)?;
    check_order_inputs_outputs(chain_config, block_height, tx)?;
    Ok(())
}

fn check_size(
    chain_config: &ChainConfig,
    tx: &SignedTransaction,
) -> Result<(), CheckTransactionError> {
    match tx.transaction_data_size() {
        TransactionSize::ScriptedTransaction(size) => {
            let max_allowed_size = chain_config.max_block_size_from_std_scripts();
            ensure!(
                size <= max_allowed_size,
                CheckTransactionError::TxSizeTooLarge(
                    tx.transaction().get_id(),
                    size,
                    max_allowed_size
                )
            );
        }
        TransactionSize::SmartContractTransaction(size) => {
            let max_allowed_size = chain_config.max_block_size_from_smart_contracts();
            ensure!(
                size <= max_allowed_size,
                CheckTransactionError::TxSizeTooLarge(
                    tx.transaction().get_id(),
                    size,
                    max_allowed_size
                )
            );
        }
    };
    Ok(())
}

fn check_duplicate_inputs(tx: &SignedTransaction) -> Result<(), CheckTransactionError> {
    // check for duplicate inputs (see CVE-2018-17144)
    ensure!(
        !tx.inputs().is_empty(),
        CheckTransactionError::EmptyInputsInTransaction(tx.transaction().get_id(),),
    );

    let mut tx_inputs = BTreeSet::new();
    for input in tx.inputs() {
        ensure!(
            tx_inputs.insert(input),
            CheckTransactionError::DuplicateInputInTransaction(tx.transaction().get_id(),)
        );
    }

    Ok(())
}

fn check_witness_count(tx: &SignedTransaction) -> Result<(), CheckTransactionError> {
    ensure!(
        tx.inputs().len() == tx.signatures().len(),
        CheckTransactionError::InvalidWitnessCount(tx.transaction().get_id())
    );

    Ok(())
}

fn check_tokens_tx(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    tx: &SignedTransaction,
) -> Result<(), CheckTransactionError> {
    // Check if v0 tokens are allowed to be used at this height
    let latest_token_version = chain_config
        .chainstate_upgrades()
        .version_at_height(block_height)
        .1
        .token_issuance_version();

    match latest_token_version {
        TokenIssuanceVersion::V0 => { /* do nothing */ }
        TokenIssuanceVersion::V1 => {
            let has_tokens_v0_op = tx.outputs().iter().any(|output| match output {
                TxOutput::Transfer(output_value, _)
                | TxOutput::Burn(output_value)
                | TxOutput::LockThenTransfer(output_value, _, _)
                | TxOutput::Htlc(output_value, _) => match output_value {
                    OutputValue::Coin(_) | OutputValue::TokenV1(_, _) => false,
                    OutputValue::TokenV0(_) => true,
                },
                TxOutput::CreateOrder(data) => {
                    let ask_token_v0 = match data.ask() {
                        OutputValue::Coin(_) | OutputValue::TokenV1(_, _) => false,
                        OutputValue::TokenV0(_) => true,
                    };
                    let give_token_v0 = match data.ask() {
                        OutputValue::Coin(_) | OutputValue::TokenV1(_, _) => false,
                        OutputValue::TokenV0(_) => true,
                    };
                    ask_token_v0 || give_token_v0
                }
                TxOutput::CreateStakePool(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_) => false,
            });
            ensure!(
                !has_tokens_v0_op,
                CheckTransactionError::DeprecatedTokenOperationVersion(
                    TokenIssuanceVersion::V0,
                    tx.transaction().get_id(),
                )
            );
        }
    };

    // We can't issue multiple tokens in a single tx
    let issuance_count = get_tokens_issuance_count(tx.outputs());
    ensure!(
        issuance_count <= 1,
        CheckTransactionError::TokensError(TokensError::MultipleTokenIssuanceInTransaction(
            tx.transaction().get_id(),
        ),)
    );

    let change_token_metadata_uri_activated = chain_config
        .chainstate_upgrades()
        .version_at_height(block_height)
        .1
        .change_token_metadata_uri_activated();

    // Check token metadata uri change
    tx.inputs().iter().try_for_each(|input| match input {
        TxInput::Utxo(_) | TxInput::Account(_) | TxInput::OrderAccountCommand(_) => Ok(()),
        TxInput::AccountCommand(_, command) => match command {
            AccountCommand::MintTokens(_, _)
            | AccountCommand::UnmintTokens(_)
            | AccountCommand::LockTokenSupply(_)
            | AccountCommand::FreezeToken(_, _)
            | AccountCommand::UnfreezeToken(_)
            | AccountCommand::ChangeTokenAuthority(_, _)
            | AccountCommand::ConcludeOrder(_)
            | AccountCommand::FillOrder(_, _, _) => Ok(()),
            AccountCommand::ChangeTokenMetadataUri(token_id, metadata_uri) => {
                match change_token_metadata_uri_activated {
                    ChangeTokenMetadataUriActivated::Yes => { /* do nothing */ }
                    ChangeTokenMetadataUriActivated::No => {
                        return Err(CheckTransactionError::ChangeTokenMetadataUriNotActivated)
                    }
                }

                ensure!(
                    metadata_uri.len() <= chain_config.token_max_uri_len(),
                    CheckTransactionError::TokensError(TokensError::TokenMetadataUriTooLarge(
                        *token_id
                    ))
                );
                Ok(())
            }
        },
    })?;

    // Check token issuance
    tx.outputs()
        .iter()
        .try_for_each(|output| match output {
            TxOutput::IssueFungibleToken(issuance) => check_tokens_issuance(chain_config, issuance)
                .map_err(|e| TokensError::IssueError(e, tx.transaction().get_id())),
            TxOutput::IssueNft(_, issuance, _) => match issuance.as_ref() {
                NftIssuance::V0(data) => check_nft_issuance_data(chain_config, data)
                    .map_err(|e| TokensError::IssueError(e, tx.transaction().get_id())),
            },
            TxOutput::Transfer(_, _)
            | TxOutput::LockThenTransfer(_, _, _)
            | TxOutput::Burn(_)
            | TxOutput::CreateStakePool(_, _)
            | TxOutput::ProduceBlockFromStake(_, _)
            | TxOutput::CreateDelegationId(_, _)
            | TxOutput::DelegateStaking(_, _)
            | TxOutput::DataDeposit(_)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(_) => Ok(()),
        })
        .map_err(CheckTransactionError::TokensError)?;

    Ok(())
}

fn check_no_signature_size(
    chain_config: &ChainConfig,
    tx: &SignedTransaction,
) -> Result<(), CheckTransactionError> {
    for signature in tx.signatures() {
        match signature {
            InputWitness::NoSignature(data) => {
                if !chain_config.data_in_no_signature_witness_allowed() && data.is_some() {
                    return Err(CheckTransactionError::NoSignatureDataNotAllowed(
                        tx.transaction().get_id(),
                    ));
                }

                if let Some(inner_data) = data {
                    ensure!(
                        inner_data.len() <= chain_config.data_in_no_signature_witness_max_size(),
                        CheckTransactionError::NoSignatureDataSizeTooLarge(
                            inner_data.len(),
                            chain_config.data_in_no_signature_witness_max_size(),
                            tx.transaction().get_id()
                        )
                    )
                }
            }
            InputWitness::Standard(_) => (),
        }
    }

    Ok(())
}

fn check_data_deposit_outputs(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    tx: &SignedTransaction,
) -> Result<(), CheckTransactionError> {
    for output in tx.outputs() {
        match output {
            TxOutput::Transfer(..)
            | TxOutput::LockThenTransfer(..)
            | TxOutput::Burn(..)
            | TxOutput::CreateStakePool(..)
            | TxOutput::ProduceBlockFromStake(..)
            | TxOutput::CreateDelegationId(..)
            | TxOutput::DelegateStaking(..)
            | TxOutput::IssueFungibleToken(..)
            | TxOutput::IssueNft(..)
            | TxOutput::Htlc(_, _)
            | TxOutput::CreateOrder(..) => { /* Do nothing */ }
            TxOutput::DataDeposit(v) => {
                // Ensure the size of the data doesn't exceed the max allowed
                if v.len() > chain_config.data_deposit_max_size(block_height) {
                    return Err(CheckTransactionError::DataDepositMaxSizeExceeded(
                        v.len(),
                        chain_config.data_deposit_max_size(block_height),
                        tx.transaction().get_id(),
                    ));
                }
            }
        }
    }

    Ok(())
}

fn check_htlc_outputs(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    tx: &SignedTransaction,
) -> Result<(), CheckTransactionError> {
    match chain_config
        .as_ref()
        .chainstate_upgrades()
        .version_at_height(block_height)
        .1
        .htlc_activated()
    {
        HtlcActivated::Yes => { /* do nothing */ }
        HtlcActivated::No => {
            let htlc_output = tx.outputs().iter().any(|output| match output {
                TxOutput::Transfer(_, _)
                | TxOutput::LockThenTransfer(_, _, _)
                | TxOutput::Burn(_)
                | TxOutput::CreateStakePool(_, _)
                | TxOutput::ProduceBlockFromStake(_, _)
                | TxOutput::CreateDelegationId(_, _)
                | TxOutput::DelegateStaking(_, _)
                | TxOutput::IssueFungibleToken(_)
                | TxOutput::IssueNft(_, _, _)
                | TxOutput::DataDeposit(_)
                | TxOutput::CreateOrder(_) => false,
                TxOutput::Htlc(_, _) => true,
            });

            ensure!(!htlc_output, CheckTransactionError::HtlcsAreNotActivated);
        }
    };
    Ok(())
}

fn check_order_inputs_outputs(
    chain_config: &ChainConfig,
    block_height: BlockHeight,
    tx: &SignedTransaction,
) -> Result<(), CheckTransactionError> {
    let orders_version = chain_config
        .chainstate_upgrades()
        .version_at_height(block_height)
        .1
        .orders_version();

    for input in tx.inputs() {
        match input {
            TxInput::Utxo(_) | TxInput::Account(_) => {}
            TxInput::AccountCommand(_, account_command) => match account_command {
                AccountCommand::MintTokens(..)
                | AccountCommand::UnmintTokens(..)
                | AccountCommand::LockTokenSupply(..)
                | AccountCommand::FreezeToken(..)
                | AccountCommand::UnfreezeToken(..)
                | AccountCommand::ChangeTokenAuthority(..)
                | AccountCommand::ChangeTokenMetadataUri(..) => { /* do nothing */ }
                AccountCommand::FillOrder(..) | AccountCommand::ConcludeOrder(..) => {
                    match orders_version {
                        OrdersVersion::V0 => {}
                        OrdersVersion::V1 => {
                            return Err(CheckTransactionError::DeprecatedOrdersCommands(
                                tx.transaction().get_id(),
                            ));
                        }
                    };
                }
            },
            TxInput::OrderAccountCommand(cmd) => {
                match orders_version {
                    OrdersVersion::V0 => {
                        return Err(CheckTransactionError::OrdersV1AreNotActivated(
                            tx.transaction().get_id(),
                        ));
                    }
                    OrdersVersion::V1 => {}
                };
                match cmd {
                    common::chain::OrderAccountCommand::FillOrder(id, fill, _) => {
                        // Forbidding fills with zero amount ensures that tx has utxo and therefore is unique.
                        // Unique txs cannot be replayed.
                        ensure!(
                            *fill > Amount::ZERO,
                            CheckTransactionError::AttemptToFillOrderWithZero(
                                *id,
                                tx.transaction().get_id()
                            )
                        );
                    }
                    common::chain::OrderAccountCommand::ConcludeOrder { .. } => {}
                }
            }
        }
    }

    for output in tx.outputs() {
        match output {
            TxOutput::Transfer(..)
            | TxOutput::LockThenTransfer(..)
            | TxOutput::Burn(..)
            | TxOutput::CreateStakePool(..)
            | TxOutput::ProduceBlockFromStake(..)
            | TxOutput::CreateDelegationId(..)
            | TxOutput::DelegateStaking(..)
            | TxOutput::IssueFungibleToken(..)
            | TxOutput::IssueNft(..)
            | TxOutput::DataDeposit(..)
            | TxOutput::Htlc(..) => { /* Do nothing */ }
            TxOutput::CreateOrder(data) => {
                let orders_activated = chain_config
                    .chainstate_upgrades()
                    .version_at_height(block_height)
                    .1
                    .orders_activated();
                match orders_activated {
                    common::chain::OrdersActivated::Yes => {
                        ensure!(
                            CoinOrTokenId::from_output_value(data.ask())
                                != CoinOrTokenId::from_output_value(data.give()),
                            CheckTransactionError::OrdersCurrenciesMustBeDifferent(
                                tx.transaction().get_id()
                            )
                        )
                    }
                    common::chain::OrdersActivated::No => {
                        return Err(CheckTransactionError::OrdersAreNotActivated(
                            tx.transaction().get_id(),
                        ))
                    }
                }
            }
        }
    }

    Ok(())
}
