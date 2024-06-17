// Copyright (c) 2023 RBB S.r.l
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

use common::{chain::tokens::TokenId, primitives::Amount};

#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone)]
pub enum Error {
    #[error("Accounting storage error")]
    StorageError(#[from] chainstate_types::storage_result::Error),
    #[error("Base accounting error: {0}")]
    AccountingError(#[from] accounting::Error),
    #[error("Token already exist: `{0}`")]
    TokenAlreadyExists(TokenId),
    #[error("Data for token {0}` not found")]
    TokenDataNotFound(TokenId),
    #[error("Data for token {0}` not found on reversal")]
    TokenDataNotFoundOnReversal(TokenId),
    #[error("Circulating supply for token {0}` not found")]
    CirculatingSupplyNotFound(TokenId),
    #[error("Minting `{0:?}` tokens would exceed supply limit `{1:?}` for token `{2}`")]
    MintExceedsSupplyLimit(Amount, Amount, TokenId),
    #[error("Amount overflow")]
    AmountOverflow,
    #[error("Cannot mint from locked supply for token: '{0}`")]
    CannotMintFromLockedSupply(TokenId),
    #[error("Cannot mint frozen token: '{0}`")]
    CannotMintFrozenToken(TokenId),
    #[error("Cannot unmint from locked supply for token: '{0}`")]
    CannotUnmintFromLockedSupply(TokenId),
    #[error("Cannot unmint frozen token: '{0}`")]
    CannotUnmintFrozenToken(TokenId),
    #[error("Circulating supply `{0:?}` is not enough to unmint `{1:?}` for token `{2}`")]
    NotEnoughCirculatingSupplyToUnmint(Amount, Amount, TokenId),
    #[error("Supply for a token '{0}` is already locked")]
    SupplyIsAlreadyLocked(TokenId),
    #[error("Cannot lock supply for a token '{0}` with not lockable supply type")]
    CannotLockNotLockableSupply(TokenId),
    #[error("Cannot lock frozen token '{0}`")]
    CannotLockFrozenToken(TokenId),
    #[error("Cannot unlock supply on reversal for a token '{0}` with is not locked")]
    CannotUnlockNotLockedSupplyOnReversal(TokenId),
    #[error("Cannot undo mint on reversal for a token '{0}` with locked supply")]
    CannotUndoMintForLockedSupplyOnReversal(TokenId),
    #[error("Cannot undo unmint on reversal for a token '{0}` with locked supply")]
    CannotUndoUnmintForLockedSupplyOnReversal(TokenId),
    #[error("A token '{0}` is already frozen")]
    TokenIsAlreadyFrozen(TokenId),
    #[error("Cannot freeze token '{0}` that is not freezable")]
    CannotFreezeNotFreezableToken(TokenId),
    #[error("Cannot unfreeze token '{0}` that is not unfreezable")]
    CannotUnfreezeNotUnfreezableToken(TokenId),
    #[error("Cannot unfreeze token '{0}` that is not frozen")]
    CannotUnfreezeTokenThatIsNotFrozen(TokenId),
    #[error("Cannot unfreeze on reversal token '{0}` that is not frozen")]
    CannotUndoFreezeTokenThatIsNotFrozen(TokenId),
    #[error("Cannot unfreeze on reversal token '{0}` that is not frozen")]
    CannotUndoUnfreezeTokenThatIsFrozen(TokenId),
    #[error("Cannot change authority for frozen token '{0}`")]
    CannotChangeAuthorityForFrozenToken(TokenId),
    #[error("Cannot undo change authority for frozen token '{0}`")]
    CannotUndoChangeAuthorityForFrozenToken(TokenId),
    #[error("Non-zero circulating supply of non-existing token")]
    InvariantErrorNonZeroSupplyForNonExistingToken,

    // TODO Need a more granular error reporting in the following
    //      https://github.com/mintlayer/mintlayer-core/issues/811
    #[error("Tokens accounting view query failed")]
    ViewFail,
    #[error("Tokens accounting storage write failed")]
    StorageWrite,
}

pub type Result<T> = core::result::Result<T, Error>;
