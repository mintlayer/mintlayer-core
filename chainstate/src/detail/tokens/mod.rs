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
        tokens::{TokenData, TokensError},
        Block, ChainConfig, Transaction,
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
    chain_config: &ChainConfig,
    token_ticker: &[u8],
    amount_to_issue: &Amount,
    number_of_decimals: &u8,
    metadata_uri: &[u8],
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    // Check token name
    if token_ticker.len() > chain_config.token_max_ticker_len() || token_ticker.is_empty() {
        return Err(TokensError::IssueErrorInvalidTickerLength(
            tx_id,
            source_block_id,
        ));
    }

    // Is the name is ut8 and is it alphanumeric?
    let is_alphanumeric = String::from_utf8(token_ticker.to_vec())
        .map_err(|_| TokensError::IssueErrorTickerHasNoneAlphaNumericChar(tx_id, source_block_id))?
        .chars()
        .all(char::is_alphanumeric);

    ensure!(
        is_alphanumeric,
        TokensError::IssueErrorTickerHasNoneAlphaNumericChar(tx_id, source_block_id)
    );

    // Check amount
    if amount_to_issue == &Amount::from_atoms(0) {
        return Err(TokensError::IssueErrorIncorrectAmount(
            tx_id,
            source_block_id,
        ));
    }

    // Check decimals
    if number_of_decimals > &chain_config.token_max_dec_count() {
        return Err(TokensError::IssueErrorTooManyDecimals(
            tx_id,
            source_block_id,
        ));
    }

    // Check URI
    let is_ascii = String::from_utf8(metadata_uri.to_vec())
        .map_err(|_| TokensError::IssueErrorIncorrectMetadataURI(tx_id, source_block_id))?
        .chars()
        // TODO: this is probably an invalid way to validate URLs. Find the proper way to do this in rust.
        .all(|ch| ch.is_alphanumeric() || ch.is_ascii_punctuation() || ch.is_ascii_control());

    ensure!(
        is_ascii && metadata_uri.len() <= chain_config.token_max_uri_len(),
        TokensError::IssueErrorIncorrectMetadataURI(tx_id, source_block_id)
    );
    Ok(())
}

pub fn check_tokens_data(
    chain_config: &ChainConfig,
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
                chain_config,
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
