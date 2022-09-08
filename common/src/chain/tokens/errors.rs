// Copyright (c) 2021 RBB S.r.l
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

use super::TokenId;
use crate::{
    chain::{Block, Transaction},
    primitives::Id,
};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum TokensError {
    #[error("Invalid ticker in issue transaction {0} in block {1}")]
    IssueErrorInvalidTickerLength(Id<Transaction>, Id<Block>),
    #[error("Invalid ticker in issue transaction {0} in block {1}")]
    IssueErrorTickerHasNoneAlphaNumericChar(Id<Transaction>, Id<Block>),
    #[error("Incorrect amount in issue transaction {0} in block {1}")]
    IssueErrorIncorrectAmount(Id<Transaction>, Id<Block>),
    #[error("Too many decimals in issue transaction {0} in block {1}")]
    IssueErrorTooManyDecimals(Id<Transaction>, Id<Block>),
    #[error("Incorrect metadata URI in issue transaction {0} in block {1}")]
    IssueErrorIncorrectMetadataURI(Id<Transaction>, Id<Block>),
    #[error("Too many tokens issued in transaction {0} in block {1}")]
    MultipleTokenIssuanceInTransaction(Id<Transaction>, Id<Block>),
    #[error("Coin or token overflow")]
    CoinOrTokenOverflow,
    #[error("Insufficient token fees insuffience in transaction {0} in block {1}")]
    InsufficientTokenFees(Id<Transaction>, Id<Block>),
    #[error("Can't burn zero value in transaction {0} in block {1}")]
    BurnZeroTokens(Id<Transaction>, Id<Block>),
    #[error("Can't transfer zero tokens in transaction {0} in block {1}")]
    TransferZeroTokens(Id<Transaction>, Id<Block>),
    #[error("Can't fetch transaction inputs in main chain by outpoint")]
    NoTxInMainChainByOutpoint,
    #[error("Block reward output can't be used in tokens transaction")]
    BlockRewardOutputCantBeUsedInTokenTx,
    #[error("Tokens with ID: `{0}` are not registered")]
    TokensNotRegistered(TokenId),
    #[error("Tokens ID can't be calculated")]
    TokenIdCantBeCalculated,
    #[error("Burned tokens cannot be transferred")]
    AttemptToTransferBurnedTokens,
    #[error("Block reward can't be paid by tokens")]
    BlockRewardInTokens,
    #[error("Invariant broken - duplicate token id in transaction {0} in block {1}")]
    InvariantBrokenDuplicateTokenId(Id<Transaction>, Id<Block>),
    #[error("Invariant broken - attempt undo issuance on non-existent token {0}")]
    InvariantBrokenUndoIssuanceOnNonexistentToken(TokenId),
    #[error("Invariant broken - attempt register issuance on non-existent token {0}")]
    InvariantBrokenRegisterIssuanceOnNonexistentToken(TokenId),
    #[error("Invariant broken - flush non-existent token {0}")]
    InvariantBrokenFlushNonexistentToken(TokenId),
}
