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

use self::check_utils::check_media_hash;

use super::transaction_verifier::error::TokensError;
use common::{
    chain::{
        tokens::{NftIssuance, TokenData},
        Block, ChainConfig, Transaction,
    },
    primitives::{Amount, Id, Idable},
};
use serialization::{DecodeAll, Encode};
use tx_verifier::error::TokenIssuanceError;
use utils::ensure;

mod check_utils;
pub use check_utils::is_rfc3986_valid_symbol;
use check_utils::{check_nft_description, check_nft_name, check_token_ticker, is_uri_valid};

pub fn check_positive_amount(
    source_block_id: Id<Block>,
    tx: &Transaction,
    amount: &Amount,
) -> Result<(), TokensError> {
    // Check amount
    ensure!(
        amount > &Amount::ZERO,
        TokensError::TransferZeroTokens(tx.get_id(), source_block_id)
    );

    Ok(())
}

pub fn check_nft_issuance_data(
    chain_config: &ChainConfig,
    issuance: &NftIssuance,
) -> Result<(), TokenIssuanceError> {
    check_token_ticker(chain_config, &issuance.metadata.ticker)?;
    check_nft_name(chain_config, &issuance.metadata.name)?;
    check_nft_description(chain_config, &issuance.metadata.description)?;

    let icon_uri = Vec::<u8>::decode_all(&mut issuance.metadata.icon_uri.encode().as_slice())
        .map_err(|_| TokenIssuanceError::IssueErrorIncorrectIconURI)?;
    if !icon_uri.is_empty() {
        ensure!(
            icon_uri.len() <= chain_config.token_max_uri_len(),
            TokenIssuanceError::IssueErrorIncorrectIconURI
        );
        ensure!(
            is_uri_valid(&icon_uri),
            TokenIssuanceError::IssueErrorIncorrectIconURI
        );
    }

    let additional_metadata_uri =
        Vec::<u8>::decode_all(&mut issuance.metadata.additional_metadata_uri.encode().as_slice())
            .map_err(|_| TokenIssuanceError::IssueErrorIncorrectMetadataURI)?;
    if !additional_metadata_uri.is_empty() {
        ensure!(
            additional_metadata_uri.len() <= chain_config.token_max_uri_len(),
            TokenIssuanceError::IssueErrorIncorrectMetadataURI
        );
        ensure!(
            is_uri_valid(&additional_metadata_uri),
            TokenIssuanceError::IssueErrorIncorrectMetadataURI
        );
    }

    let media_uri = Vec::<u8>::decode_all(&mut issuance.metadata.media_uri.encode().as_slice())
        .map_err(|_| TokenIssuanceError::IssueErrorIncorrectMediaURI)?;
    if !media_uri.is_empty() {
        ensure!(
            media_uri.len() <= chain_config.token_max_uri_len(),
            TokenIssuanceError::IssueErrorIncorrectMediaURI
        );
        ensure!(
            is_uri_valid(&media_uri),
            TokenIssuanceError::IssueErrorIncorrectMediaURI
        );
    }
    check_media_hash(chain_config, &issuance.metadata.media_hash)?;
    Ok(())
}

pub fn check_tokens_issuance_data(
    chain_config: &ChainConfig,
    token_ticker: &[u8],
    amount_to_issue: &Amount,
    number_of_decimals: &u8,
    metadata_uri: &[u8],
) -> Result<(), TokenIssuanceError> {
    // Check token ticker
    check_token_ticker(chain_config, token_ticker)?;

    // Check amount
    ensure!(
        amount_to_issue > &Amount::ZERO,
        TokenIssuanceError::IssueAmountIsZero
    );

    // Check decimals
    ensure!(
        number_of_decimals <= &chain_config.token_max_dec_count(),
        TokenIssuanceError::IssueErrorTooManyDecimals
    );

    // Check URI
    ensure!(
        is_uri_valid(metadata_uri),
        TokenIssuanceError::IssueErrorIncorrectMetadataURI
    );

    ensure!(
        metadata_uri.len() <= chain_config.token_max_uri_len(),
        TokenIssuanceError::IssueErrorIncorrectMetadataURI
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
        TokenData::TokenTransfer(transfer) => {
            check_positive_amount(source_block_id, tx, &transfer.amount)
        }
        TokenData::TokenIssuance(issuance) => check_tokens_issuance_data(
            chain_config,
            &issuance.token_ticker,
            &issuance.amount_to_issue,
            &issuance.number_of_decimals,
            &issuance.metadata_uri,
        )
        .map_err(|err| TokensError::IssueError(err, tx.get_id(), source_block_id)),
        TokenData::NftIssuance(issuance) => check_nft_issuance_data(chain_config, issuance)
            .map_err(|err| TokensError::IssueError(err, tx.get_id(), source_block_id)),
        TokenData::TokenIssuanceV2(issuance) => check_tokens_issuance_data(
            chain_config,
            &issuance.token_ticker,
            &issuance.amount_to_issue,
            &issuance.number_of_decimals,
            &issuance.metadata_uri,
        )
        .map_err(|err| TokensError::IssueError(err, tx.get_id(), source_block_id)),
        TokenData::TokenReissuanceV1(reissuance) => {
            check_positive_amount(source_block_id, tx, &reissuance.amount_to_issue)
        }
    }
}
