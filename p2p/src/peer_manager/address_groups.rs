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

use crate::types::peer_address::PeerAddress;

// IPv4 addresses grouped into /16 subnets
pub const IPV4_GROUP_BYTES: usize = 2;
// IPv6 addresses grouped into /32 subnets
pub const IPV6_GROUP_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressGroup {
    Local,
    Private,
    PublicV4([u8; IPV4_GROUP_BYTES]),
    PublicV6([u8; IPV6_GROUP_BYTES]),
}

impl AddressGroup {
    /// Get the canonical identifier of the network group for address.
    ///
    /// The groups are assigned in a way where it should be costly for an attacker to
    /// obtain addresses with many different group identifiers, even if it is cheap
    /// to obtain addresses with the same identifier.
    ///
    /// See `NetGroupManager::GetGroup` in Bitcoin Core for a reference.
    pub fn from_peer_address(address: &PeerAddress) -> AddressGroup {
        // IPv4-mapped IPv6 addresses are reduced to the embedded IPv4 form so that they
        // land in the same group as the IPv4 address they represent.
        let std_ip = crate::types::socket_address::canonical_ip_addr(
            std::net::SocketAddr::from(address).ip(),
        );
        if address.is_global_unicast_ip() {
            match std_ip {
                std::net::IpAddr::V4(ip) => AddressGroup::PublicV4(
                    ip.octets()[0..IPV4_GROUP_BYTES].try_into().expect("must be valid"),
                ),
                std::net::IpAddr::V6(ip) => AddressGroup::PublicV6(
                    ip.octets()[0..IPV6_GROUP_BYTES].try_into().expect("must be valid"),
                ),
            }
        } else if address.is_loopback() {
            AddressGroup::Local
        } else {
            AddressGroup::Private
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use p2p_types::socket_address::SocketAddress;

    use super::*;

    fn check_group(ip: &str, expected: AddressGroup) {
        let addr =
            SocketAddress::new(SocketAddr::new(ip.parse().unwrap(), 12345)).as_peer_address();
        let group = AddressGroup::from_peer_address(&addr);
        assert_eq!(group, expected, "check failed for {ip}");
    }

    #[tracing::instrument]
    #[test]
    fn address_group() {
        check_group("127.0.0.1", AddressGroup::Local);
        check_group("::1", AddressGroup::Local);

        check_group("192.168.0.1", AddressGroup::Private);
        check_group("fe80::", AddressGroup::Private);

        check_group("1.2.3.4", AddressGroup::PublicV4([1, 2]));
        check_group(
            "2a00:1450:4017:815::200e",
            AddressGroup::PublicV6([0x2a, 0x00, 0x14, 0x50]),
        );
    }
}

#[cfg(test)]
mod mapped_address_tests {
    use super::*;

    fn mapped_v6_address(ip: std::net::Ipv4Addr) -> PeerAddress {
        let o = ip.octets();
        PeerAddress::Ip6(crate::types::peer_address::PeerAddressIp6 {
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
            port: 12345,
        })
    }

    #[test]
    fn mapped_addresses_are_grouped_like_the_embedded_ipv4() {
        assert_eq!(
            AddressGroup::from_peer_address(&mapped_v6_address(std::net::Ipv4Addr::LOCALHOST)),
            AddressGroup::Local
        );
        assert_eq!(
            AddressGroup::from_peer_address(&mapped_v6_address(std::net::Ipv4Addr::new(
                192, 168, 1, 1
            ))),
            AddressGroup::Private
        );
        assert_eq!(
            AddressGroup::from_peer_address(&mapped_v6_address(std::net::Ipv4Addr::new(
                10, 0, 0, 1
            ))),
            AddressGroup::Private
        );
        assert_eq!(
            AddressGroup::from_peer_address(&mapped_v6_address(std::net::Ipv4Addr::new(
                1, 2, 3, 4
            ))),
            AddressGroup::PublicV4([1, 2])
        );
    }
}
