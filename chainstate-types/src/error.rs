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

use thiserror::Error;

use common::{
    chain::{tokens::TokenId, Block, GenBlock, Transaction},
    primitives::{BlockHeight, Id},
};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum TokensError {
    #[error("Incorrect ticker in issue transaction {0} in block {1}")]
    IssueErrorIncorrectTicker(Id<Transaction>, Id<Block>),
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
    #[error("Token fees insuffience in transaction {0} in block {1}")]
    InsuffienceTokenFees(Id<Transaction>, Id<Block>),
    #[error("Token value in inputs insuffience in transaction {0} in block {1}")]
    InsuffienceTokenValueInInputs(Id<Transaction>, Id<Block>),
    #[error("Can't burn zero value in transaction {0} in block {1}")]
    BurnZeroTokens(Id<Transaction>, Id<Block>),
    #[error("Can't transfer zero tokens in transaction {0} in block {1}")]
    TransferZeroTokens(Id<Transaction>, Id<Block>),
    #[error("Some of the tokens are lost in transaction {0} in block {1}")]
    SomeTokensLost(Id<Transaction>, Id<Block>),
    #[error("Can't find token in inputs in transaction {0} in block {1}")]
    NoTokenInInputs(Id<Transaction>, Id<Block>),
    #[error("Can't fetch transaction inputs in main chain by outpoint")]
    NoTxInMainChainByOutpoint,
    #[error("Block reward output can't be used in tokens transaction")]
    BlockRewardOutputCantBeUsedInTokenTx,
    #[error("Tokens with ID: `{0}` are not registered")]
    TokensNotRegistered(TokenId),
    #[error("Token ID can't be calculated")]
    TokenIdCantBeCalculated,
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum PropertyQueryError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] crate::storage_result::Error),
    #[error("Best block not found")]
    BestBlockNotFound,
    #[error("Best block index not found")]
    BestBlockIndexNotFound,
    #[error("Block not found {0}")]
    BlockNotFound(Id<Block>),
    #[error("Previous block index not found {0}")]
    PrevBlockIndexNotFound(Id<GenBlock>),
    #[error("Block for height {0} not found")]
    BlockForHeightNotFound(BlockHeight),
    #[error("Provided an empty list")]
    InvalidInputEmpty,
    #[error("Invalid ancestor height: sought ancestor with height {ancestor_height} for block with height {block_height}")]
    InvalidAncestorHeight {
        block_height: BlockHeight,
        ancestor_height: BlockHeight,
    },
    #[error("Genesis block has no header")]
    GenesisHeaderRequested,
    #[error("Tokens error: {0}")]
    TokensError(TokensError),
}
