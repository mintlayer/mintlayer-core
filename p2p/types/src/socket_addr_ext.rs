// Copyright (c) 2021-2024 RBB S.r.l
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

use std::net::SocketAddr;

use crate::{bannable_address::BannableAddress, peer_address::PeerAddress};

pub trait SocketAddrExt {
    fn as_bannable(&self) -> BannableAddress;
    fn as_peer_address(&self) -> PeerAddress;
}

impl SocketAddrExt for SocketAddr {
    fn as_bannable(&self) -> BannableAddress {
        BannableAddress::new(self.ip())
    }

    fn as_peer_address(&self) -> PeerAddress {
        (*self).into()
    }
}
