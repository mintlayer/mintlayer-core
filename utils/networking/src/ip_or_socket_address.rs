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
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

/// IP or socket address
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpOrSocketAddress {
    Ip(IpAddr),
    Socket(SocketAddr),
}

impl FromStr for IpOrSocketAddress {
    type Err = <SocketAddr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<IpAddr>()
            .map(IpOrSocketAddress::Ip)
            .or_else(|_err| s.parse::<SocketAddr>().map(IpOrSocketAddress::Socket))
    }
}

impl Display for IpOrSocketAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpOrSocketAddress::Ip(ip) => ip.fmt(f),
            IpOrSocketAddress::Socket(addr) => addr.fmt(f),
        }
    }
}

impl IpOrSocketAddress {
    pub fn new_socket_address(addr: SocketAddr) -> Self {
        Self::Socket(addr)
    }

    pub fn new_ip(ip: IpAddr) -> Self {
        Self::Ip(ip)
    }

    pub fn to_socket_address(&self, default_port: u16) -> SocketAddr {
        match self {
            IpOrSocketAddress::Ip(ip) => SocketAddr::new(*ip, default_port),
            IpOrSocketAddress::Socket(addr) => *addr,
        }
    }

    pub fn to_ip_address(&self) -> IpAddr {
        match self {
            IpOrSocketAddress::Ip(ip) => *ip,
            IpOrSocketAddress::Socket(addr) => addr.ip(),
        }
    }
}

impl serde::Serialize for IpOrSocketAddress {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_string().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for IpOrSocketAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = IpOrSocketAddress;
            fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                fmt.write_str("IP or socket address")
            }
            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
                s.parse().map_err(serde::de::Error::custom)
            }
        }
        d.deserialize_str(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use serde_test::{assert_tokens, Token};

    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        for original_address in ["1.1.1.1", "2a00::1", "1.1.1.1:1234", "[2a00::1]:1234"] {
            let parsed: IpOrSocketAddress = original_address.parse().unwrap();
            assert_tokens(&parsed, &[Token::Str(original_address)]);
        }
    }
}
