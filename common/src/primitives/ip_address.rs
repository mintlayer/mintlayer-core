// Copyright (c) 2022 RBB S.r.l
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

use serialization::{Decode, Encode};

/// IPv4 address
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Decode, Encode)]
pub struct Ip4 {
    inner: [u8; 4],
}

/// IPv6 address
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Decode, Encode)]
pub struct Ip6 {
    inner: [u8; 16],
}

impl From<std::net::Ipv4Addr> for Ip4 {
    fn from(ip: std::net::Ipv4Addr) -> Self {
        Self { inner: ip.octets() }
    }
}

impl From<std::net::Ipv6Addr> for Ip6 {
    fn from(ip: std::net::Ipv6Addr) -> Self {
        Self { inner: ip.octets() }
    }
}

impl From<Ip4> for std::net::Ipv4Addr {
    fn from(ip: Ip4) -> Self {
        ip.inner.into()
    }
}

impl From<Ip6> for std::net::Ipv6Addr {
    fn from(ip: Ip6) -> Self {
        ip.inner.into()
    }
}
