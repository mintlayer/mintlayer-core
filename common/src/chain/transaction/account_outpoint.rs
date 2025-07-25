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
        AccountNonce, DelegationId, OrderId,
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
    #[codec(index = 2)]
    Order(OrderId),
}

impl From<&AccountSpending> for AccountType {
    fn from(spending: &AccountSpending) -> Self {
        match spending {
            AccountSpending::DelegationBalance(id, _) => AccountType::Delegation(*id),
        }
    }
}

impl From<&AccountCommand> for AccountType {
    fn from(op: &AccountCommand) -> Self {
        match op {
            AccountCommand::MintTokens(id, _)
            | AccountCommand::UnmintTokens(id)
            | AccountCommand::LockTokenSupply(id)
            | AccountCommand::FreezeToken(id, _)
            | AccountCommand::UnfreezeToken(id)
            | AccountCommand::ChangeTokenAuthority(id, _)
            | AccountCommand::ChangeTokenMetadataUri(id, _) => AccountType::Token(*id),
            AccountCommand::ConcludeOrder(id) | AccountCommand::FillOrder(id, _, _) => {
                AccountType::Order(*id)
            }
        }
    }
}

impl From<OrderAccountCommand> for AccountType {
    fn from(cmd: OrderAccountCommand) -> Self {
        match cmd {
            OrderAccountCommand::FillOrder(order_id, _)
            | OrderAccountCommand::FreezeOrder(order_id)
            | OrderAccountCommand::ConcludeOrder(order_id) => AccountType::Order(order_id),
        }
    }
}

/// The type represents the amount to withdraw from a particular account.
/// Otherwise it's unclear how much should be deducted from an account balance.
/// It also helps solving 2 additional problems: calculating fees and providing ability to sign input balance with the witness.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum AccountSpending {
    #[codec(index = 0)]
    DelegationBalance(DelegationId, Amount),
}

// Represents a command that can be performed on an account.
// Operation must be unique and authorized.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum AccountCommand {
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

    // Close an order and withdraw all remaining funds from both give and ask balances.
    // Only the address specified as `conclude_key` can authorize this command.
    // After ChainstateUpgrade::OrdersVersion::V1 is activated this command becomes deprecated.
    // TODO: rename this command to ConcludeOrderDeprecated.
    //       https://github.com/mintlayer/mintlayer-core/issues/1901
    #[codec(index = 6)]
    ConcludeOrder(OrderId),

    // Satisfy an order completely or partially.
    // The second element is the fill amount in the order's "ask" currency.
    // The third element is an arbitrary destination, which is present here due to historical reasons.
    // (Though it can technically be the same as the actual output destination, this is not enforced).
    //
    // Also note that though a FillOrder input can technically have a signature, it is not checked.
    // So it's better not to provide one, to reduce the transaction size and avoid needlessly exposing
    // the corresponding public key.
    //
    // After ChainstateUpgrade::OrdersVersion::V1 is activated this command becomes deprecated.
    // TODO: rename this command to FillOrderDeprecated
    //       https://github.com/mintlayer/mintlayer-core/issues/1901
    #[codec(index = 7)]
    FillOrder(OrderId, Amount, Destination),

    // Change token metadata uri
    #[codec(index = 8)]
    ChangeTokenMetadataUri(TokenId, Vec<u8>),
}

/// Type of OutPoint that represents spending from an account
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AccountOutPoint {
    nonce: AccountNonce,
    account: AccountSpending,
}

impl AccountOutPoint {
    pub fn new(nonce: AccountNonce, account: AccountSpending) -> Self {
        Self { nonce, account }
    }

    pub fn nonce(&self) -> AccountNonce {
        self.nonce
    }

    pub fn account(&self) -> &AccountSpending {
        &self.account
    }
}

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Encode,
    Decode,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum OrderAccountCommand {
    // Satisfy an order completely or partially.
    // The second element is the fill amount in the order's "ask" currency.
    // Note that in orders v1 there is no `Destination` element inside `FillOrder`.
    #[codec(index = 0)]
    FillOrder(OrderId, Amount),

    // Freeze an order which effectively forbids any fill operations.
    // Frozen order can only be concluded.
    // Only the address specified as `conclude_key` can authorize this command.
    #[codec(index = 1)]
    FreezeOrder(OrderId),

    // Close an order and withdraw all remaining funds from both give and ask balances.
    // Only the address specified as `conclude_key` can authorize this command.
    #[codec(index = 2)]
    ConcludeOrder(OrderId),
}
