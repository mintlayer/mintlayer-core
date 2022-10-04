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
        tokens::{NftIssuanceV1, TokenData},
        Block, ChainConfig, Transaction,
    },
    primitives::{Amount, Id, Idable},
};
use utils::ensure;

use super::transaction_verifier::error::TokensError;

mod check_utils;
use check_utils::*;

mod error;

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

pub fn check_nft_issuance_data(
    chain_config: &ChainConfig,
    issuance: &NftIssuanceV1,
    tx_id: Id<Transaction>,
    source_block_id: Id<Block>,
) -> Result<(), TokensError> {
    // Ticker
    check_token_text_length(
        &issuance.metadata.ticker,
        chain_config.token_max_ticker_len(),
    )
    .map_err(|_| TokensError::IssueErrorInvalidTickerLength(tx_id, source_block_id))?;

    check_is_text_alphanumeric(&issuance.metadata.ticker).map_err(|_| {
        TokensError::IssueErrorTickerHasNoneAlphaNumericChar(tx_id, source_block_id)
    })?;

    // Name
    check_token_text_length(&issuance.metadata.name, chain_config.token_max_name_len())
        .map_err(|_| TokensError::IssueErrorInvalidNameLength(tx_id, source_block_id))?;

    check_is_text_alphanumeric(&issuance.metadata.name)
        .map_err(|_| TokensError::IssueErrorNameHasNoneAlphaNumericChar(tx_id, source_block_id))?;

    // Description
    check_token_text_length(
        &issuance.metadata.description,
        chain_config.token_max_description_len(),
    )
    .map_err(|_| TokensError::IssueErrorInvalidDescriptionLength(tx_id, source_block_id))?;

    check_is_text_alphanumeric(&issuance.metadata.description).map_err(|_| {
        TokensError::IssueErrorDescriptionHasNoneAlphaNumericChar(tx_id, source_block_id)
    })?;

    // Icon URL
    match &issuance.metadata.icon_uri {
        Some(uri) => check_uri(chain_config, uri)
            .map_err(|_| TokensError::IssueErrorIncorrectIconURI(tx_id, source_block_id))?,
        None => (),
    }

    // Metadata URL
    match &issuance.metadata.additional_metadata_uri {
        Some(uri) => check_uri(chain_config, uri)
            .map_err(|_| TokensError::IssueErrorIncorrectMetadataURI(tx_id, source_block_id))?,
        None => (),
    }

    // Media URL
    match &issuance.metadata.media_uri {
        Some(uri) => check_uri(chain_config, uri)
            .map_err(|_| TokensError::IssueErrorIncorrectMediaURI(tx_id, source_block_id))?,
        None => (),
    }

    // Check media hash
    check_media_hash(&issuance.metadata.media_hash)?;

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
    check_token_text_length(token_ticker, chain_config.token_max_ticker_len())
        .map_err(|_| TokensError::IssueErrorInvalidTickerLength(tx_id, source_block_id))?;

    // Check the name consists of alphanumeric characters only
    check_is_text_alphanumeric(token_ticker).map_err(|_| {
        TokensError::IssueErrorTickerHasNoneAlphaNumericChar(tx_id, source_block_id)
    })?;

    // Check amount
    if amount_to_issue == &Amount::from_atoms(0) {
        return Err(TokensError::IssueAmountIsZero(tx_id, source_block_id));
    }

    // Check decimals
    if number_of_decimals > &chain_config.token_max_dec_count() {
        return Err(TokensError::IssueErrorTooManyDecimals(
            tx_id,
            source_block_id,
        ));
    }

    // Check URI
    check_uri(chain_config, metadata_uri)
        .map_err(|_| TokensError::IssueErrorIncorrectMetadataURI(tx_id, source_block_id))?;

    ensure!(
        metadata_uri.len() <= chain_config.token_max_uri_len(),
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
        TokenData::TokenTransferV1(transfer) => {
            check_tokens_transfer_data(source_block_id, tx, &transfer.amount)?;
        }
        TokenData::TokenIssuanceV1(issuance) => {
            check_tokens_issuance_data(
                chain_config,
                &issuance.token_ticker,
                &issuance.amount_to_issue,
                &issuance.number_of_decimals,
                &issuance.metadata_uri,
                tx.get_id(),
                source_block_id,
            )?;
        }
        TokenData::TokenBurnV1(burn) => {
            check_tokens_burn_data(tx, &source_block_id, &burn.amount_to_burn)?;
        }
        TokenData::NftIssuanceV1(issuance) => {
            check_nft_issuance_data(chain_config, issuance, tx.get_id(), source_block_id)?
        }
    }
    Ok(())
}
