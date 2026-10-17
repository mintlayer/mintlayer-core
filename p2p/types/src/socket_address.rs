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
    net::{AddrParseError, IpAddr, SocketAddr},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use crate::{bannable_address::BannableAddress, peer_address::PeerAddress};

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Hash,
    rpc_description::HasValueHint,
)]
pub struct SocketAddress(SocketAddr);

impl SocketAddress {
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }

    pub fn socket_addr(&self) -> SocketAddr {
        self.0
    }

    /// The IP address with IPv4-mapped IPv6 addresses reduced to the embedded IPv4 form,
    /// so that classification, bans and deduplication treat `::ffff:a.b.c.d` as the IPv4
    /// address it represents. Note that code that keys on the raw form must use this
    /// accessor (or [`canonical_socket_address`]) on both the insert and the lookup side;
    /// [`socket_addr`] returns the address unchanged.
    pub fn ip_addr(&self) -> IpAddr {
        canonical_ip_addr(self.0.ip())
    }

    pub fn as_bannable(&self) -> BannableAddress {
        BannableAddress::new(self.ip_addr())
    }

    pub fn as_peer_address(&self) -> PeerAddress {
        self.0.into()
    }
}

/// Reduce an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`) to the embedded IPv4 address;
/// any other address is returned unchanged.
pub fn canonical_ip_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Same reduction as [`canonical_ip_addr`], applied to a socket address including its port.
/// Non-mapped IPv6 addresses are returned untouched, so flowinfo and scope id are preserved.
pub fn canonical_socket_address(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => SocketAddr::V6(v6),
        },
        v4 => v4,
    }
}

impl Display for SocketAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for SocketAddress {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SocketAddr::from_str(s).map(SocketAddress)
    }
}

impl From<SocketAddr> for SocketAddress {
    fn from(value: SocketAddr) -> Self {
        SocketAddress::new(value)
    }
}

#[cfg(test)]
mod mapped_address_tests {
    use super::*;
    use crate::bannable_address::BannableAddress;
    use std::net::SocketAddrV4;

    #[test]
    fn mapped_addresses_are_canonicalized() {
        let mapped: SocketAddr = "[::ffff:1.2.3.4]:12345".parse().unwrap();
        let socket_address = SocketAddress::new(mapped);

        assert_eq!(
            socket_address.ip_addr(),
            IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4))
        );
        assert_eq!(
            socket_address.as_bannable(),
            BannableAddress::new(IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)))
        );

        // Non-mapped addresses are unchanged.
        let plain_v6: SocketAddr = "[2a00:1450:4017:815::200e]:12345".parse().unwrap();
        assert_eq!(
            SocketAddress::new(plain_v6).ip_addr(),
            IpAddr::V6("2a00:1450:4017:815::200e".parse().unwrap())
        );
    }

    #[test]
    fn canonical_socket_address_reduces_mapped_form() {
        let mapped: SocketAddr = "[::ffff:127.0.0.1]:12345".parse().unwrap();
        assert_eq!(
            canonical_socket_address(mapped),
            SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::LOCALHOST, 12345))
        );
    }
}
