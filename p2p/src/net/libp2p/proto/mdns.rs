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
use crate::{
    error::{self, P2pError},
    net::{
        self,
        libp2p::{backend::Backend, types},
    },
};
use libp2p::{mdns::MdnsEvent, Multiaddr, PeerId};
use logging::log;

impl Backend {
    async fn send_discovery_event(
        &mut self,
        peers: Vec<(PeerId, Multiaddr)>,
        event_fn: impl FnOnce(Vec<(PeerId, Multiaddr)>) -> types::ConnectivityEvent,
    ) -> error::Result<()> {
        if !self.relay_mdns || peers.is_empty() {
            return Ok(());
        }

        self.conn_tx.send(event_fn(peers)).await.map_err(|_| P2pError::ChannelClosed)
    }

    pub async fn on_mdns_event(&mut self, event: MdnsEvent) -> error::Result<()> {
        match event {
            MdnsEvent::Discovered(peers) => {
                self.send_discovery_event(peers.collect(), |peers| {
                    types::ConnectivityEvent::PeerDiscovered { peers }
                })
                .await
            }
            MdnsEvent::Expired(expired) => {
                self.send_discovery_event(expired.collect(), |peers| {
                    types::ConnectivityEvent::PeerExpired { peers }
                })
                .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_works() {}
}
