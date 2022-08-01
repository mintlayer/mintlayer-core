// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach, A. Sinitsyn

use common::{
    chain::{Block, GenBlock, Transaction},
    primitives::{BlockHeight, Id},
};
use thiserror::Error;

use super::{
    orphan_blocks::OrphanAddError, pow::error::ConsensusPoWError,
    spend_cache::error::StateUpdateError,
};

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockError {
    #[error("Block storage error: `{0}`")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Error while checking the previous block: {0}")]
    OrphanCheckFailed(#[from] OrphanCheckError),
    #[error("Check block failed: {0}")]
    CheckBlockFailed(#[from] CheckBlockError),
    #[error("Failed to update the internal blockchain state: {0}")]
    StateUpdateFailed(#[from] StateUpdateError),
    #[error("Failed to load best block")]
    BestBlockLoadError(PropertyQueryError),
    #[error("Starting from block {0} with current best {1}, failed to find a path of blocks to connect to reorg with error: {2}")]
    InvariantErrorFailedToFindNewChainPath(Id<Block>, Id<GenBlock>, PropertyQueryError),
    #[error("Invariant error: Attempted to connected block that isn't on the tip")]
    InvariantErrorInvalidTip,
    #[error("The previous block not found")]
    PrevBlockNotFound,
    #[error("Block {0} already exists")]
    BlockAlreadyExists(Id<Block>),
    #[error("Failed to commit block state update to database for block: {0} after {1} attempts with error {2}")]
    DatabaseCommitError(Id<Block>, usize, chainstate_storage::Error),
    #[error("Block proof calculation error for block: {0}")]
    BlockProofCalculationError(Id<Block>),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum ConsensusVerificationError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Error while loading previous block {0} of block {1} with error {2}")]
    PrevBlockLoadError(Id<GenBlock>, Id<Block>, PropertyQueryError),
    #[error("Previous block {0} of block {1} not found in database")]
    PrevBlockNotFound(Id<GenBlock>, Id<Block>),
    #[error("Block consensus type does not match our chain configuration: {0}")]
    ConsensusTypeMismatch(String),
    #[error("PoW error: {0}")]
    PoWError(ConsensusPoWError),
    #[error("Unsupported consensus type")]
    UnsupportedConsensusType,
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckBlockError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Block has an invalid merkle root")]
    MerkleRootMismatch,
    #[error("Block has an invalid witness merkle root")]
    WitnessMerkleRootMismatch,
    #[error("Previous block {0} of block {1} not found in database")]
    PrevBlockNotFound(Id<Block>, Id<Block>),
    #[error("Block time must be equal or higher than the median of its ancestors")]
    BlockTimeOrderInvalid,
    #[error("Block time too far into the future")]
    BlockFromTheFuture,
    #[error("Block size is too large: {0}")]
    BlockSizeError(#[from] BlockSizeError),
    #[error("Check transaction failed: {0}")]
    CheckTransactionFailed(CheckBlockTransactionsError),
    #[error("Check transaction failed: {0}")]
    ConsensusVerificationFailed(ConsensusVerificationError),
}

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
    #[error("Coin or token overflow in transaction {0} in block {1}")]
    CoinOrTokenOverflow(Id<Transaction>, Id<Block>),
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
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum CheckBlockTransactionsError {
    #[error("Blockchain storage error: {0}")]
    StorageError(chainstate_storage::Error),
    #[error("Duplicate input in transaction {0} in block {1}")]
    DuplicateInputInTransaction(Id<Transaction>, Id<Block>),
    #[error("Duplicate input in block")]
    DuplicateInputInBlock(Id<Block>),
    #[error("Duplicate transaction {0} found in block {1}")]
    DuplicatedTransactionInBlock(Id<Transaction>, Id<Block>),
    #[error("Tokens error: {0}")]
    CheckTokensError(TokensError),
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum PropertyQueryError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
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
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum OrphanCheckError {
    #[error("Blockchain storage error: {0}")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("Block index not found")]
    PrevBlockIndexNotFound(PropertyQueryError),
    #[error("Orphan that was submitted legitimately through a local source")]
    LocalOrphan,
}

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum BlockSizeError {
    #[error("Block header too large (current: {0}, limit: {1})")]
    Header(usize, usize),
    #[error("Block transactions component size too large (current: {0}, limit: {1})")]
    SizeOfTxs(usize, usize),
    #[error("Block smart contracts component size too large (current: {0}, limit: {1})")]
    SizeOfSmartContracts(usize, usize),
}

impl From<OrphanAddError> for Result<(), OrphanCheckError> {
    fn from(err: OrphanAddError) -> Self {
        match err {
            OrphanAddError::BlockAlreadyInOrphanList(_) => Ok(()),
        }
    }
}
