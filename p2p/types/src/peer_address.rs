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

use std::fmt::Display;

use serialization::{Decode, Encode};

use crate::{
    IsGlobalIp,
    ip_address::{Ip4, Ip6},
    socket_address::SocketAddress,
};

#[derive(Debug, Encode, Decode, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct PeerAddressIp4 {
    pub ip: Ip4,
    pub port: u16,
}

#[derive(Debug, Encode, Decode, Clone, PartialOrd, Ord, PartialEq, Eq)]
pub struct PeerAddressIp6 {
    pub ip: Ip6,
    pub port: u16,
}

/// Type used to serialize information about peer address.
///
/// Same as std::net::SocketAddr for now but can be later extended with other address types.
/// Use custom type to be able implement Encode and Decode.
#[derive(Debug, Encode, Decode, Clone, PartialEq, Eq)]
pub enum PeerAddress {
    #[codec(index = 0)]
    Ip4(PeerAddressIp4),
    #[codec(index = 1)]
    Ip6(PeerAddressIp6),
}

impl PeerAddress {
    /// The IP address in canonical form, where an IPv4-mapped IPv6 address
    /// (`::ffff:a.b.c.d`) is reduced to the embedded IPv4 address.
    ///
    /// Note that the derived `Eq` still distinguishes the mapped form from the plain
    /// form, because the wire format keeps them distinct; deduplicate or key collections
    /// on this canonical value rather than on the address itself.
    pub fn canonical_ip(&self) -> std::net::IpAddr {
        crate::socket_address::canonical_ip_addr(std::net::SocketAddr::from(self).ip())
    }

    pub fn is_loopback(&self) -> bool {
        self.canonical_ip().is_loopback()
    }

    pub fn is_global_unicast_ip(&self) -> bool {
        self.canonical_ip().is_global_unicast_ip()
    }

    /// If the address is eligible for being sent to peers via AddrListResponse, return Some,
    /// otherwise return None.
    ///
    /// The address is eligible if it has a public routable IP and any valid (non-zero) port.
    /// Private and local IPs are allowed if `allow_discover_private_ips` is true.
    ///
    /// IPv4-mapped IPv6 addresses are reduced to the embedded IPv4 form, so the eligibility
    /// check sees the IPv4 address they represent and the returned address is the IPv4 form.
    pub fn as_discoverable_socket_address(
        &self,
        allow_discover_private_ips: bool,
    ) -> Option<SocketAddress> {
        let std_address =
            crate::socket_address::canonical_socket_address(std::net::SocketAddr::from(self));
        if (std_address.ip().is_global_unicast_ip() || allow_discover_private_ips)
            && std_address.port() != 0
        {
            Some(SocketAddress::new(std_address))
        } else {
            None
        }
    }
}

impl Display for PeerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let self_copy: std::net::SocketAddr = self.into();
        std::fmt::Display::fmt(&self_copy, f)
    }
}

impl From<std::net::SocketAddr> for PeerAddress {
    fn from(address: std::net::SocketAddr) -> Self {
        match address {
            std::net::SocketAddr::V4(ip) => PeerAddress::Ip4(PeerAddressIp4 {
                ip: (*ip.ip()).into(),
                port: address.port(),
            }),
            std::net::SocketAddr::V6(ip) => PeerAddress::Ip6(PeerAddressIp6 {
                ip: (*ip.ip()).into(),
                port: address.port(),
            }),
        }
    }
}

impl From<&PeerAddress> for std::net::SocketAddr {
    fn from(address: &PeerAddress) -> Self {
        match address {
            PeerAddress::Ip4(socket4) => std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                socket4.ip.into(),
                socket4.port,
            )),
            PeerAddress::Ip6(socket6) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                socket6.ip.into(),
                socket6.port,
                0,
                0,
            )),
        }
    }
}

#[cfg(test)]
mod mapped_address_tests {
    use super::*;

    fn mapped_v6(ip: std::net::Ipv4Addr, port: u16) -> PeerAddress {
        let o = ip.octets();
        PeerAddress::Ip6(PeerAddressIp6 {
            ip: std::net::Ipv6Addr::new(
                0,
                0,
                0,
                0,
                0,
                0xffff,
                u16::from_be_bytes([o[0], o[1]]),
                u16::from_be_bytes([o[2], o[3]]),
            )
            .into(),
            port,
        })
    }

    fn plain_v4(ip: std::net::Ipv4Addr, port: u16) -> PeerAddress {
        PeerAddress::Ip4(PeerAddressIp4 {
            ip: ip.into(),
            port,
        })
    }

    #[test]
    fn mapped_non_routable_addresses_are_not_discoverable() {
        let non_routable = [
            std::net::Ipv4Addr::LOCALHOST,
            std::net::Ipv4Addr::new(10, 0, 0, 1),
            std::net::Ipv4Addr::new(192, 168, 1, 1),
            std::net::Ipv4Addr::new(172, 16, 0, 1),
            std::net::Ipv4Addr::new(169, 254, 1, 1),
            std::net::Ipv4Addr::UNSPECIFIED,
        ];
        for ip in non_routable {
            let address = mapped_v6(ip, 12345);
            assert!(
                address.as_discoverable_socket_address(false).is_none(),
                "mapped {ip} must not pass the discoverable gate"
            );
            // The plain form is rejected by the same gate, both forms must agree.
            assert!(plain_v4(ip, 12345).as_discoverable_socket_address(false).is_none());
        }
    }

    #[test]
    fn mapped_routable_address_is_discoverable_in_the_ipv4_form() {
        let address = mapped_v6(std::net::Ipv4Addr::new(8, 8, 8, 8), 12345);
        let socket_address = address
            .as_discoverable_socket_address(false)
            .expect("mapped global address must pass the discoverable gate");
        assert_eq!(
            socket_address.socket_addr(),
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(8, 8, 8, 8),
                12345
            ))
        );
    }

    #[test]
    fn zero_port_is_rejected_in_the_mapped_form() {
        let address = mapped_v6(std::net::Ipv4Addr::new(8, 8, 8, 8), 0);
        assert!(address.as_discoverable_socket_address(false).is_none());
    }

    #[test]
    fn mapped_loopback_is_detected_by_is_loopback() {
        assert!(mapped_v6(std::net::Ipv4Addr::LOCALHOST, 12345).is_loopback());
        assert!(!mapped_v6(std::net::Ipv4Addr::new(8, 8, 8, 8), 12345).is_loopback());
    }
}
