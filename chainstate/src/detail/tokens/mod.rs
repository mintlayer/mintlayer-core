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

mod validate_utils;
use validate_utils::*;

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
    //FIXME(nft_issuance)

    // Ticker
    check_token_ticker(
        chain_config,
        &issuance.metadata.ticker,
        tx_id,
        source_block_id,
    )?;
    check_alphanumeric(&issuance.metadata.ticker, tx_id, source_block_id)?;

    // Name
    check_token_name(
        chain_config,
        &issuance.metadata.name,
        tx_id,
        source_block_id,
    )?;
    check_alphanumeric(&issuance.metadata.name, tx_id, source_block_id)?;

    // Description
    check_token_description(
        chain_config,
        &issuance.metadata.name,
        tx_id,
        source_block_id,
    )?;
    check_alphanumeric(&issuance.metadata.description, tx_id, source_block_id)?;

    // Icon URL
    match &issuance.metadata.icon_url {
        Some(url) => check_url(chain_config, url, tx_id, source_block_id)?,
        None => (),
    }

    // Metadata URL
    match &issuance.metadata.additional_metadata_url {
        Some(url) => check_url(chain_config, url, tx_id, source_block_id)?,
        None => (),
    }

    // Media URL
    match &issuance.metadata.media_url {
        Some(url) => check_url(chain_config, url, tx_id, source_block_id)?,
        None => (),
    }

    // Check media hash
    check_media_hash(&issuance.metadata.media_hash)?;

    // Check issued time
    // Check expired time
    // Check start time

    // issuance.metadata.creator: TokenCreator,
    // issuance.metadata.media_hash: Vec<u8>,
    // issuance.metadata.issuead_at: Option<u64>,
    // issuance.metadata.expired_at: Option<u64>,
    // issuance.metadata.valid_since: Option<u64>,
    // issuance.metadata.refund_period: Option<u64>,

    unimplemented!()
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
    check_token_ticker(chain_config, token_ticker, tx_id, source_block_id)?;

    // Check the name consists of alphanumeric characters only
    check_alphanumeric(token_ticker, tx_id, source_block_id)?;

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
