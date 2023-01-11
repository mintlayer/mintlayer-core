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

use common::primitives::ip_address::{Ip4, Ip6};
use serialization::{Decode, Encode};

#[derive(Debug, Encode, Decode, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub struct PeerAddressIp4 {
    pub ip: Ip4,
    pub port: u16,
}

#[derive(Debug, Encode, Decode, Clone, PartialOrd, Ord, PartialEq, Eq, Hash)]
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
