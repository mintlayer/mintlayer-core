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

use std::{
    fmt::Display,
    net::{AddrParseError, IpAddr},
    str::FromStr,
};

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    rpc_description::HasValueHint,
)]
// Note: the derived newtype `Serialize` delegates to the inner `IpAddr`, matching the
// manual `Deserialize` below; keep the two impls wire-compatible if this changes.
pub struct BannableAddress(IpAddr);

// Deserialize routes through `new` so that persisted bans stored in the mapped form are
// treated as their plain IPv4 form when loaded.
impl<'de> serde::Deserialize<'de> for BannableAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        IpAddr::deserialize(deserializer).map(BannableAddress::new)
    }
}

impl BannableAddress {
    pub fn new(ip: IpAddr) -> Self {
        // IPv4-mapped IPv6 addresses are reduced to the embedded IPv4 form so that a mapped
        // address and the plain IPv4 address it represents share one ban key.
        Self(crate::socket_address::canonical_ip_addr(ip))
    }

    pub fn ip_addr(&self) -> IpAddr {
        self.0
    }
}

impl Display for BannableAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for BannableAddress {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        IpAddr::from_str(s).map(BannableAddress::new)
    }
}

#[cfg(test)]
mod bannable_address_tests {
    use super::*;

    #[test]
    fn mapped_addresses_share_the_ban_key_with_the_embedded_ipv4() {
        let plain = IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4));
        let mapped: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        assert_eq!(BannableAddress::new(mapped), BannableAddress::new(plain));

        // The serde round trip folds the mapped form into the plain form.
        let serialized = serde_json::to_string(&BannableAddress::new(mapped)).unwrap();
        let deserialized: BannableAddress = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, BannableAddress::new(plain));
    }
}
