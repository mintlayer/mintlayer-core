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

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::types::peer_address::PeerAddress;

use super::global_ip::IsGlobalIp;

// IPv4 addresses /16 groups
const IPV4_GROUP_BYTES: usize = 2;
// IPv4 addresses /32 groups
const IPV6_GROUP_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressGroup {
    Local,
    Private,
    PublicV4([u8; IPV4_GROUP_BYTES]),
    PublicV6([u8; IPV6_GROUP_BYTES]),
}

/// Get the canonical identifier of the network group for address.
///
/// The groups are assigned in a way where it should be costly for an attacker to
/// obtain addresses with many different group identifiers, even if it is cheap
/// to obtain addresses with the same identifier.
///
/// See `NetGroupManager::GetGroup` in Bitcoin Core for a reference.
pub fn get_address_group(address: &PeerAddress) -> AddressGroup {
    match address {
        PeerAddress::Ip4(addr) => {
            let ip = Ipv4Addr::from(addr.ip);
            if ip.is_global_unicast_ip() {
                AddressGroup::PublicV4(
                    ip.octets()[0..IPV4_GROUP_BYTES].try_into().expect("must be valid"),
                )
            } else if ip.is_loopback() {
                AddressGroup::Local
            } else {
                AddressGroup::Private
            }
        }
        PeerAddress::Ip6(addr) => {
            let ip = Ipv6Addr::from(addr.ip);
            if ip.is_global_unicast_ip() {
                AddressGroup::PublicV6(
                    ip.octets()[0..IPV6_GROUP_BYTES].try_into().expect("must be valid"),
                )
            } else if ip.is_loopback() {
                AddressGroup::Local
            } else {
                AddressGroup::Private
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::net::default_backend::transport::TransportAddress;

    use super::*;

    fn check_group(ip: &str, expected: AddressGroup) {
        let addr = SocketAddr::new(ip.parse().unwrap(), 12345).as_peer_address();
        let group = get_address_group(&addr);
        assert_eq!(group, expected, "check failed for {ip}");
    }

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
