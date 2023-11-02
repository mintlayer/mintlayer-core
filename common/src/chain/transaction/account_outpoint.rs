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

use crate::{
    chain::{
        tokens::{IsTokenUnfreezable, TokenId},
        DelegationId,
    },
    primitives::Amount,
};
use serialization::{Decode, Encode};

use super::Destination;

/// Type of an account that can be used to identify series of spending from an account
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Encode, Decode)]
pub enum AccountType {
    #[codec(index = 0)]
    Delegation(DelegationId),
    /// Token account type is used to authorize changes in token data.
    #[codec(index = 1)]
    Token(TokenId),
}

impl From<AccountSpending> for AccountType {
    fn from(spending: AccountSpending) -> Self {
        match spending {
            AccountSpending::DelegationBalance(id, _) => AccountType::Delegation(id),
        }
    }
}

impl From<AuthorityCommand> for AccountType {
    fn from(op: AuthorityCommand) -> Self {
        match op {
            AuthorityCommand::MintTokens(id, _)
            | AuthorityCommand::UnmintTokens(id)
            | AuthorityCommand::LockTokenSupply(id)
            | AuthorityCommand::FreezeToken(id, _)
            | AuthorityCommand::UnfreezeToken(id)
            | AuthorityCommand::ChangeTokenAuthority(id, _) => AccountType::Token(id),
        }
    }
}

// FIXME: better name?
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode, serde::Serialize)]
pub enum AccountOperation {
    #[codec(index = 0)]
    Spending(AccountSpending),
    #[codec(index = 1)]
    Command(AuthorityCommand),
}

/// The type represents the amount to withdraw from a particular account.
/// Otherwise it's unclear how much should be deducted from an account balance.
/// It also helps solving 2 additional problems: calculating fees and providing ability to sign input balance with the witness.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode, serde::Serialize)]
pub enum AccountSpending {
    #[codec(index = 0)]
    DelegationBalance(DelegationId, Amount),
}

// Represents an operation that can be performed on an account.
// Operation must be unique and authorized.
#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd, Encode, Decode, serde::Serialize)]
pub enum AuthorityCommand {
    // Create certain amount of tokens and add them to circulating supply
    #[codec(index = 0)]
    MintTokens(TokenId, Amount),
    // Take tokens out of circulation. Not the same as Burn because unminting means that certain amount
    // of tokens is no longer supported by underlying fiat currency, which can only be done by the authority.
    #[codec(index = 1)]
    UnmintTokens(TokenId),
    // After supply is locked tokens cannot be minted or unminted ever again.
    // Works only for Lockable tokens supply.
    #[codec(index = 2)]
    LockTokenSupply(TokenId),
    // Freezing token forbids any operation with all the tokens (except for optional unfreeze)
    #[codec(index = 3)]
    FreezeToken(TokenId, IsTokenUnfreezable),
    // By unfreezing token all operations are available for the tokens again
    #[codec(index = 4)]
    UnfreezeToken(TokenId),
    // Change the authority who can authorize operations for a token
    #[codec(index = 5)]
    ChangeTokenAuthority(TokenId, Destination),
}
