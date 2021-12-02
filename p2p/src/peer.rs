// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
use crate::net::NetworkService;

pub type PeerId = u128;

#[allow(unused)]
pub struct Peer<NetworkingBackend: NetworkService> {
    peer_id: PeerId,
    pub socket: NetworkingBackend::Socket,
}

#[allow(unused)]
impl<NetworkingBackend: NetworkService> Peer<NetworkingBackend> {
    /// Create new peer
    ///
    /// # Arguments
    /// `peer_id` - unique ID of the peer
    /// `socket` - socket for the peer
    pub fn new(peer_id: PeerId, socket: NetworkingBackend::Socket) -> Self {
        Self { peer_id, socket }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mock::MockService;

    #[tokio::test]
    async fn test_peer_new() {
        let addr: <MockService as NetworkService>::Address = "[::1]:11111".parse().unwrap();
        let mut server = MockService::new(addr).await.unwrap();
        let peer_fut = <MockService as NetworkService>::Socket::connect(addr);

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        assert_eq!(server_res.is_ok(), true);
        assert_eq!(peer_res.is_ok(), true);

        let _ = Peer::<MockService>::new(1u128, peer_res.unwrap());
    }
}
