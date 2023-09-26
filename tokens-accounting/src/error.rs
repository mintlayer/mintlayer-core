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
    TokenAlreadyExist(TokenId),
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
    #[error("Cannot redeem from locked supply for token: '{0}`")]
    CannotRedeemFromLockedSupply(TokenId),
    #[error("Circulating supply `{0:?}` is not enough to redeem `{1:?}` for token `{2}`")]
    NotEnoughCirculatingSupplyToRedeem(Amount, Amount, TokenId),
    #[error("Supply for a token '{0}` is already locked")]
    SupplyIsAlreadyLocked(TokenId),
    #[error("Cannot lock supply for a token '{0}` with not lockable supply type")]
    CannotLockNotLockableSupply(TokenId),

    // TODO Need a more granular error reporting in the following
    //      https://github.com/mintlayer/mintlayer-core/issues/811
    #[error("Tokens accounting view query failed")]
    ViewFail,
    #[error("Tokens accounting storage write failed")]
    StorageWrite,
}

pub type Result<T> = core::result::Result<T, Error>;
