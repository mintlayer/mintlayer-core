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
        signature::inputsig::InputWitness,
        tokens::{get_tokens_issuance_count, NftIssuance},
        ChainConfig, SignedTransaction, Transaction, TxOutput,
    },
    primitives::{Id, Idable},
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
}

pub fn check_transaction(
    chain_config: &ChainConfig,
    tx: &SignedTransaction,
) -> Result<(), CheckTransactionError> {
    check_duplicate_inputs(tx)?;
    check_witness_count(tx)?;
    check_tokens_tx(chain_config, tx)?;
    check_no_signature_size(chain_config, tx)?;
    check_data_deposit_outputs(chain_config, tx)?;
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
    tx: &SignedTransaction,
) -> Result<(), CheckTransactionError> {
    // We can't issue multiple tokens in a single tx
    let issuance_count = get_tokens_issuance_count(tx.outputs());
    ensure!(
        issuance_count <= 1,
        CheckTransactionError::TokensError(TokensError::MultipleTokenIssuanceInTransaction(
            tx.transaction().get_id(),
        ),)
    );

    // Check tokens
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
            | TxOutput::DataDeposit(_) => Ok(()),
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
            | TxOutput::IssueNft(..) => { /* Do nothing */ }
            TxOutput::DataDeposit(v) => {
                // Ensure the size of the data doesn't exceed the max allowed
                if v.len() > chain_config.data_deposit_max_size() {
                    return Err(CheckTransactionError::DataDepositMaxSizeExceeded(
                        v.len(),
                        chain_config.data_deposit_max_size(),
                        tx.transaction().get_id(),
                    ));
                }
            }
        }
    }

    Ok(())
}