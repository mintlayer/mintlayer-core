// Copyright (c) 2022 RBB S.r.l
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
use crate::net::mock::{
    socket,
    types::{MockPeerId, PeerEvent},
};
use tokio::sync::mpsc;

pub struct Peer {
    peer_id: MockPeerId,
    socket: socket::MockSocket,
    tx: mpsc::Sender<(MockPeerId, PeerEvent)>,
    rx: mpsc::Receiver<PeerEvent>,
}

impl Peer {
    pub fn new(
        peer_id: MockPeerId,
        socket: socket::MockSocket,
        tx: mpsc::Sender<(MockPeerId, PeerEvent)>,
        rx: mpsc::Receiver<PeerEvent>,
    ) -> Self {
        Self {
            peer_id,
            socket,
            tx,
            rx,
        }
    }

    pub async fn start(&mut self) -> crate::Result<()> {
        todo!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {
        assert_eq!(1 + 1, 2);
    }
}
