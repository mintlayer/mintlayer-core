// Copyright (c) 2021-2025 RBB S.r.l
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
    address::{AddressError, RpcAddress},
    chain::{
        output_value::{OutputValue, RpcOutputValue},
        tokens::TokenId,
        ChainConfig,
    },
    primitives::Amount,
};

// TODO: currently out RPC types are a bit of a mess and we need to revamp them.
// The reason for having RPC types in the first place is that in RPC we'd like for certain things to have a more
// human-readable representation, namely:
// 1) Destinations, VRF public keys and ids of pools/delegations/tokens/orders should be bech32-encoded instead
// of being hex-encoded or "hexified" via `HexifiedAddress`. For this purpose we have the `RpcAddress` wrapper
// (which holds a bech-32 encoded string), so e.g. `RpcAddress<PoolId>` should be used instead of the plain
// PoolId in RPC types.
// 2) Amounts are more readable when they are in the decimal form instead of the plain number of atoms. But we also
// have to differentiate between input and output amounts, because for inputs we want the amount to be *either* atoms
// or a decimal value, but for outputs we want *both* the atoms and the decimal value. For this reason we have
// `RpcAmountIn`/`RpcOutputValueIn` and `RpcAmountOut`/`RpcOutputValueOut`.
//
// About the mess:
// 1) We also have the `RpcOutputValue` type which is just the normal `OutputValue` but without the deprecated
// `TokenV0` variant, i.e. it has a plain `TokenId` and plain `Amount`'s. Normally, this type should have been named
// `OutputValueV1` (and it could become just `OutputValue` if we decide to get rid of TokenV0 completely, though this
// would require to restart the testnet). However, it actually implements `rpc_description::HasValueHint` and is used
// in RPC types.
// 2) Many RPC types contain plain `Destination`'s and/or ids, e.g. `RPCFungibleTokenInfo` and `RpcOrderInfo`.
// Many RPC types also contain plain `Amount`'s and `RpcOutputValue`'s, e.g. `RpcOrderInfo` and RPCTokenTotalSupply`.
// 3) In the wallet some RPC types have the "Rpc" prefix and some don't. E.g. `RpcStandaloneAddressDetail`s and
// `StandaloneAddressWithDetails` are both RPC types. Also, sometimes they use plain String's instead of `RpcAddress`.
// Also, some of the types are quite generic, e.g. `TokenTotalSupply` (which should have been named
// `RpcTokenTotalSupplyIn` and moved out of the wallet).
//
// What should we do:
// 1) The "RPC" prefix should be replaced with "Rpc" to honor Rust's naming conventions.
// 2) `RpcOutputValue` should be renamed to `OutputValueV1` and it should *not* implement `HasValueHint`.
// Also, all functions that take `RpcOutputValue` and are named as such (e.g. `from_rpc_output_value` below)
// should be renamed as well.
// 3) `Destination` and ids of pools/delegations/tokens/orders should *not* implement `HasValueHint` either
// (see also the TODO inside `impl ValueHint` in `rpc/description/src/value_hint.rs`); `RpcAddress` should be used
// in all RPC types instead.
// 4) RPC types should not contain plain `Amount`'s and `OutputValue`'s; instead, they should contain the corresponding
// "Rpc...In" or "...Out" type. Which in turn means that RPC types that contain an amount or an output value must
// themselves be designated as "In" or "Out" and have the corresponding suffix.
// 5) We also need to reconsider where the RPC types live. Currently many of them live in `common`, even though they're
// only used in the chainstate RPC, but lots of others live in `chainstate`, see the contents of the `chainstate/src/rpc/types/`
// folder. One approach would be to put an RPC type into the same crate as its non-RPC counterpart. Another approach
// is to put them all to chainstate (note that blockprod and mempool depend on chainstate, so we'll be able to use
// chainstate types in their RPC interfaces if needed).
// 6) All types that implement `HasValueHint` should have a specific prefix designating them as RPC types. Normally,
// it would be "Rpc", but for wallet types we could consider a different prefix, e.g. "WalletRpc", "Wrpc"  or something
// like that. The reason is that wallet RPC may potentially need a special wallet-only version of a generic RPC type.
// Also, in general, wallet RPC types are rather specific, so it might be better to differentiate them from the generic ones.
// 7) Some of the wallet's RPC types (like the above-mentioned `TokenTotalSupply`) should be moved outside the wallet.
// 8) We should also ensure that RPC types don't contain plain String's where an RpcAddress can be used (this affects
// how the corresponding value is referred to in the generated RPC documentation; also, it has less potential for mis-use).

#[derive(PartialEq, Eq, PartialOrd, Ord, Copy, Clone, Debug)]
pub enum Currency {
    Coin,
    Token(TokenId),
}

impl Currency {
    pub fn from_output_value(output_value: &OutputValue) -> Option<Self> {
        match output_value {
            OutputValue::Coin(_) => Some(Self::Coin),
            OutputValue::TokenV0(_) => None,
            OutputValue::TokenV1(id, _) => Some(Self::Token(*id)),
        }
    }

    pub fn from_rpc_output_value(output_value: &RpcOutputValue) -> Self {
        match output_value {
            RpcOutputValue::Coin { .. } => Self::Coin,
            RpcOutputValue::Token { id, .. } => Self::Token(*id),
        }
    }

    pub fn into_output_value(&self, amount: Amount) -> OutputValue {
        match self {
            Self::Coin => OutputValue::Coin(amount),
            Self::Token(id) => OutputValue::TokenV1(*id, amount),
        }
    }

    pub fn to_rpc_currency(&self, chain_config: &ChainConfig) -> Result<RpcCurrency, AddressError> {
        RpcCurrency::from_currency(self, chain_config)
    }
}

#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    rpc_description::HasValueHint,
)]
#[serde(tag = "type", content = "content")]
pub enum RpcCurrency {
    Coin,
    Token(RpcAddress<TokenId>),
}

impl RpcCurrency {
    pub fn to_currency(&self, chain_config: &ChainConfig) -> Result<Currency, AddressError> {
        let result = match self {
            RpcCurrency::Coin => Currency::Coin,
            RpcCurrency::Token(rpc_address) => {
                Currency::Token(rpc_address.decode_object(chain_config)?)
            }
        };

        Ok(result)
    }

    pub fn from_currency(
        currency: &Currency,
        chain_config: &ChainConfig,
    ) -> Result<Self, AddressError> {
        let result = match currency {
            Currency::Coin => Self::Coin,
            Currency::Token(id) => Self::Token(RpcAddress::new(chain_config, *id)?),
        };

        Ok(result)
    }
}
