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

use serde::Serialize;

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
    Hash,
    rpc_description::HasValueHint,
)]
pub struct SocketAddress(SocketAddr);

// Deserialize routes through the constructor so that mapped forms are folded on the way in,
// matching the wire format of the derived `Serialize`.
impl<'de> serde::Deserialize<'de> for SocketAddress {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        <SocketAddr as serde::Deserialize>::deserialize(deserializer).map(SocketAddress::new)
    }
}

impl SocketAddress {
    /// The stored address is canonical by construction: IPv4-mapped IPv6 forms are reduced
    /// to the embedded IPv4 form, so classification, bans, deduplication and storage treat
    /// `::ffff:a.b.c.d` as the IPv4 address it represents.
    pub fn new(addr: SocketAddr) -> Self {
        Self(canonical_socket_address(addr))
    }

    pub fn socket_addr(&self) -> SocketAddr {
        self.0
    }

    /// The IP address of the canonical form; see [`SocketAddress::new`].
    pub fn ip_addr(&self) -> IpAddr {
        self.0.ip()
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
///
/// Note that only the mapped form is reduced. Other IPv4-embedded encodings (6to4,
/// Teredo, NAT64, IPv4-translated) are treated as plain IPv6 addresses.
pub fn canonical_ip_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Same reduction as [`canonical_ip_addr`], applied to a socket address including its
/// port. Non-mapped IPv6 addresses are returned untouched, so flowinfo and scope id are
/// preserved. Mapped forms are assumed to carry zero flowinfo/scope id (as RFC 4291
/// requires), which are then dropped along with the IPv6 framing.
pub fn canonical_socket_address(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => {
                debug_assert_eq!(
                    (v6.flowinfo(), v6.scope_id()),
                    (0, 0),
                    "mapped IPv4 form is assumed to carry no flowinfo or scope id",
                );
                SocketAddr::new(IpAddr::V4(v4), v6.port())
            }
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
        SocketAddr::from_str(s).map(SocketAddress::new)
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

    #[test]
    fn canonical_socket_address_preserves_v6_flowinfo_and_scope_id() {
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(),
            12345,
            7,
            9,
        ));
        assert_eq!(canonical_socket_address(scoped), scoped);
    }

    #[test]
    fn mapped_forms_are_canonicalized_on_construction() {
        let plain: SocketAddr = "1.2.3.4:12345".parse().unwrap();
        let mapped: SocketAddr = "[::ffff:1.2.3.4]:12345".parse().unwrap();
        assert_eq!(SocketAddress::new(mapped), SocketAddress::new(plain));
        assert_eq!(
            "[::ffff:1.2.3.4]:12345".parse::<SocketAddress>().unwrap(),
            SocketAddress::new(plain)
        );
        assert_eq!(
            serde_json::from_str::<SocketAddress>("\"[::ffff:1.2.3.4]:12345\"").unwrap(),
            SocketAddress::new(plain)
        );
    }
}
