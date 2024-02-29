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
    net::{AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use crate::{bannable_address::BannableAddress, peer_address::PeerAddress, IsGlobalIp};

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct SocketAddress(SocketAddr);

impl SocketAddress {
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }

    pub fn socket_addr(&self) -> SocketAddr {
        self.0
    }

    pub fn ip_addr(&self) -> IpAddr {
        self.0.ip()
    }

    pub fn as_bannable(&self) -> BannableAddress {
        BannableAddress::new(self.0.ip())
    }

    pub fn as_peer_address(&self) -> PeerAddress {
        self.0.into()
    }

    pub fn from_peer_address(address: &PeerAddress, allow_private_ips: bool) -> Option<Self> {
        match &address {
            PeerAddress::Ip4(socket)
                if (Ipv4Addr::from(socket.ip).is_global_unicast_ip() || allow_private_ips)
                    && socket.port != 0 =>
            {
                Some(SocketAddress::new(address.into()))
            }
            PeerAddress::Ip6(socket)
                if (Ipv6Addr::from(socket.ip).is_global_unicast_ip() || allow_private_ips)
                    && socket.port != 0 =>
            {
                Some(SocketAddress::new(address.into()))
            }
            _ => None,
        }
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

impl rpc_description::HasValueHint for SocketAddress {
    const HINT: rpc_description::ValueHint = rpc_description::ValueHint::STRING;
}
