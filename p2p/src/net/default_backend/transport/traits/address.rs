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

/// Allow working with abstract socket address types.
/// For example change socket port or encode for sending on wire.
/// It's might better to completely replace abstract socket types with PeerAddress.
pub trait TransportAddress: Sized {
    /// Convert abstract socket address to concrete type (PeerAddress)
    fn as_peer_address(&self) -> PeerAddress;

    /// Try get address back from PeerAddress.
    ///
    /// This might fail if an address is from some other transport.
    fn from_peer_address(address: &PeerAddress) -> Option<Self>;
}
