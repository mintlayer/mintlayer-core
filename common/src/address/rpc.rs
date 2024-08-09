// Copyright (c) 2024 RBB S.r.l
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

use super::{Address, AddressError, Addressable, ChainConfig};

/// Address string for use in RPC. Not guaranteed to hold a valid address.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RpcAddress<T> {
    address: String,
    #[serde(skip)]
    _phantom: std::marker::PhantomData<T>,
}

impl<T> RpcAddress<T> {
    /// Construct from a raw string.
    pub fn from_string(address: String) -> Self {
        let _phantom = Default::default();
        Self { address, _phantom }
    }

    /// Construct from an [Address].
    pub fn from_address(address: Address<T>) -> Self {
        Self::from_string(address.into_string())
    }

    /// Get the address string, no validation is performed
    pub fn as_str(&self) -> &str {
        &self.address
    }

    /// Get the address string
    pub fn into_string(self) -> String {
        self.address
    }
}

impl<T: Addressable> RpcAddress<T> {
    /// Construct from an addressable object
    pub fn new(cfg: &ChainConfig, object: T) -> Result<Self, AddressError> {
        Ok(Self::from_address(Address::new(cfg, object)?))
    }

    /// Convert to an address, according to given chain config.
    pub fn into_address(self, cfg: &ChainConfig) -> Result<Address<T>, AddressError> {
        Address::from_string(cfg, self.address)
    }

    /// Convert to an object, according to given chain config.
    pub fn decode_object(&self, cfg: &ChainConfig) -> Result<T, AddressError> {
        Ok(self.clone().into_address(cfg)?.into_object())
    }
}

impl<T> From<Address<T>> for RpcAddress<T> {
    fn from(value: Address<T>) -> Self {
        Self::from_address(value)
    }
}

impl<T> From<String> for RpcAddress<T> {
    fn from(value: String) -> Self {
        Self::from_string(value)
    }
}

impl<T> std::fmt::Display for RpcAddress<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.address.fmt(f)
    }
}

impl<T> Clone for RpcAddress<T> {
    fn clone(&self) -> Self {
        Self::from_string(self.address.clone())
    }
}

impl<T> rpc_description::HasValueHint for RpcAddress<T> {
    const HINT_SER: rpc_description::ValueHint = rpc_description::ValueHint::BECH32_STRING;
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json::{from_value, json, to_value};

    #[rstest::rstest]
    #[case("")]
    #[case("hello")]
    #[case("rmt1qyyra5j3qduhyd43wa50lpn2ddpg9ql0u50ceu68")]
    fn serde_bare_string(#[case] addr_str: &str) {
        let addr = RpcAddress::<()>::from_string(addr_str.into());
        let json = json!(addr_str);
        assert_eq!(to_value(&addr).unwrap(), json);
        assert_eq!(from_value::<RpcAddress<()>>(json).unwrap(), addr);
    }
}
