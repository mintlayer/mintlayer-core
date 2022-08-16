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
        config::{TOKEN_MAX_DEC_COUNT, TOKEN_MAX_TICKER_LEN, TOKEN_MAX_URI_LEN},
        tokens::{token_id, OutputValue, TokenData, TokenId, TokensError},
        Block, Transaction,
    },
    primitives::{Amount, Id, Idable},
};
use utils::ensure;

pub fn check_tokens_transfer_data(
    source_block_id: Id<Block>,
    tx: &Transaction,
    amount: &Amount,
) -> Result<(), TokensError> {
    // Check amount
    ensure!(
        amount > &Amount::from_atoms(0),
        TokensError::TransferZeroTokens(tx.get_id(), source_block_id)
    );

    Ok(())
}

pub fn check_tokens_burn_data(
    tx: &Transaction,
    source_block_id: &Id<Block>,
    amount_to_burn: &Amount,
) -> Result<(), TokensError> {
    // Check amount
    ensure!(
        amount_to_burn != &Amount::from_atoms(0),
        TokensError::BurnZeroTokens(tx.get_id(), *source_block_id)
    );
    Ok(())
}

pub fn check_tokens_issuance_data(
    token_ticker: &Vec<u8>,
    amount_to_issue: &Amount,
    number_of_decimals: &u8,
    metadata_uri: &Vec<u8>,
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    //TODO: Shall we have a check for unique token name?

    // Check token name
    if token_ticker.len() > TOKEN_MAX_TICKER_LEN
        || token_ticker.is_empty()
        || !String::from_utf8_lossy(token_ticker).is_ascii()
    {
        return Err(TokensError::IssueErrorIncorrectTicker(tx_id, source_block_id));
    }

    // Check amount
    if amount_to_issue == &Amount::from_atoms(0) {
        return Err(TokensError::IssueErrorIncorrectAmount(tx_id, source_block_id));
    }

    // Check decimals
    if number_of_decimals > &TOKEN_MAX_DEC_COUNT {
        return Err(TokensError::IssueErrorTooManyDecimals(tx_id, source_block_id));
    }

    // Check URI
    if metadata_uri.len() > TOKEN_MAX_URI_LEN || !String::from_utf8_lossy(metadata_uri).is_ascii() {
        return Err(TokensError::IssueErrorIncorrectMetadataURI(tx_id, source_block_id));
    }
    Ok(())
}

pub fn check_tokens_data(
    token_data: &TokenData,
    tx: &Transaction,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    match token_data {
        TokenData::TokenTransferV1 {
            token_id: _,
            amount,
        } => {
            check_tokens_transfer_data(source_block_id, tx, amount)?;
        }
        TokenData::TokenIssuanceV1 {
            token_ticker,
            amount_to_issue,
            number_of_decimals,
            metadata_uri,
        } => {
            check_tokens_issuance_data(
                token_ticker,
                amount_to_issue,
                number_of_decimals,
                metadata_uri,
                tx.get_id(),
                source_block_id,
            )?;
        }
        TokenData::TokenBurnV1 {
            token_id: _,
            amount_to_burn,
        } => {
            check_tokens_burn_data(tx, &source_block_id, amount_to_burn)?;
        }
    }
    Ok(())
}

// Get TokenId and Amount in input
pub fn filter_transferred_and_issued_amounts(
    prev_tx: &Transaction,
    output: &common::chain::TxOutput,
) -> Option<(TokenId, Amount)> {
    match output.value() {
        OutputValue::Coin(_) => None,
        OutputValue::Token(token) => Some(match token {
            TokenData::TokenTransferV1 { token_id, amount } => (*token_id, *amount),
            TokenData::TokenIssuanceV1 {
                token_ticker: _,
                amount_to_issue,
                number_of_decimals: _,
                metadata_uri: _,
            } => {
                let token_id = token_id(prev_tx)?;
                (token_id, *amount_to_issue)
            }
            TokenData::TokenBurnV1 {
                token_id: _,
                amount_to_burn: _,
            } => {
                /* Token have burned and can't be transferred */
                return None;
            }
        }),
    }
}

pub fn filter_transferred_and_burn_amounts(token_data: &TokenData) -> Option<(TokenId, Amount)> {
    match token_data {
        TokenData::TokenTransferV1 { token_id, amount } => Some((*token_id, *amount)),
        TokenData::TokenIssuanceV1 {
            token_ticker: _,
            amount_to_issue: _,
            number_of_decimals: _,
            metadata_uri: _,
        } => None,
        TokenData::TokenBurnV1 {
            token_id,
            amount_to_burn,
        } => Some((*token_id, *amount_to_burn)),
    }
}
