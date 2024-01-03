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

//! Types supporting the RPC interface

use std::collections::BTreeMap;

use common::{
    address::Address,
    chain::{tokens::TokenId, Destination, GenBlock, TxOutput, UtxoOutPoint},
    primitives::{Amount, BlockHeight, Id},
};
use crypto::key::hdkd::{child_number::ChildNumber, u31::U31};

pub use mempool_types::tx_options::TxOptionsOverrides;
pub use serialization::hex_encoded::HexEncoded;

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct AmountString(pub String);

impl AmountString {
    pub fn new(amt: Amount, decimals: u8) -> Self {
        Self(amt.into_fixedpoint_str(decimals))
    }

    pub fn amount(&self, decimals: u8) -> Result<Amount, RpcError> {
        Amount::from_fixedpoint_str(&self.0, decimals).ok_or(RpcError::InvalidCoinAmount)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("Account index out of supported range")]
    AcctIndexOutOfRange,

    #[error("Invalid coin amount")]
    InvalidCoinAmount,

    #[error("Invalid address")]
    InvalidAddress,

    #[error("Malformed amount")]
    MalformedAmount,
}

impl From<RpcError> for rpc::Error {
    fn from(e: RpcError) -> Self {
        Self::owned::<()>(-1, e.to_string(), None)
    }
}

/// Struct representing empty arguments to RPC call, for forwards compatibility
#[derive(Debug, Eq, PartialEq, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct EmptyArgs {}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccountIndexArg {
    pub account: u32,
}

impl AccountIndexArg {
    pub fn index(&self) -> rpc::RpcResult<U31> {
        rpc::handle_result(U31::from_u32(self.account).ok_or(RpcError::AcctIndexOutOfRange))
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockInfo {
    pub id: Id<GenBlock>,
    pub height: BlockHeight,
}

impl BlockInfo {
    pub fn from_tuple((id, height): (Id<GenBlock>, BlockHeight)) -> Self {
        Self { id, height }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct AddressInfo {
    pub address: String,
    pub index: String,
}

impl AddressInfo {
    pub fn new(child_number: ChildNumber, address: Address<Destination>) -> Self {
        Self {
            address: address.to_string(),
            index: child_number.to_string(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct AddressWithUsageInfo {
    pub address: String,
    pub index: String,
    pub used: bool,
}

impl AddressWithUsageInfo {
    pub fn new(child_number: ChildNumber, address: Address<Destination>, used: bool) -> Self {
        Self {
            address: address.to_string(),
            index: child_number.to_string(),
            used,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct BalanceInfo {
    pub coins: AmountString,
    pub tokens: BTreeMap<TokenId, AmountString>,
}

impl BalanceInfo {
    pub fn new(coins: AmountString, tokens: BTreeMap<TokenId, AmountString>) -> Self {
        Self { coins, tokens }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UtxoInfo {
    pub outpoint: UtxoOutPoint,
    pub output: TxOutput,
}

impl UtxoInfo {
    pub fn from_tuple((outpoint, output): (UtxoOutPoint, TxOutput)) -> Self {
        Self { outpoint, output }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NewAccountInfo {
    pub account: u32,
    pub name: Option<String>,
}

impl NewAccountInfo {
    pub fn new(account: U31, name: Option<String>) -> Self {
        let account = account.into_u32();
        Self { account, name }
    }
}
