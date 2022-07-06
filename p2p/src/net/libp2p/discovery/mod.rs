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

//! Discovery behaviour for libp2p

use libp2p::{
    core::{
        connection::{ConnectedPoint, ConnectionId},
        PeerId,
    },
    mdns as libp2pmdns,
    swarm::{handler::DummyConnectionHandler, NetworkBehaviourAction, PollParameters},
    Multiaddr,
};
use std::task::{Context, Poll};

mod mdns;

pub enum DiscoveryEvent {
    /// Peer discovered
    Discovered(Vec<(PeerId, Multiaddr)>),

    /// Peer expired
    Expired(Vec<(PeerId, Multiaddr)>),
}

pub struct DiscoveryManager {
    /// Multicast DNS
    mdns: mdns::Mdns,
}

impl DiscoveryManager {
    pub async fn new(mdns_enabled: bool) -> Self {
        Self {
            mdns: mdns::Mdns::new(mdns_enabled).await,
        }
    }

    pub fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        handler: DummyConnectionHandler, // TODO: connectionmanager
        remaining_established: usize,
    ) {
        self.mdns.inject_connection_closed(
            peer_id,
            connection_id,
            endpoint,
            handler,
            remaining_established,
        );
    }

    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<DiscoveryEvent, DummyConnectionHandler>> {
        if let Poll::Ready(NetworkBehaviourAction::GenerateEvent(event)) =
            self.mdns.poll(cx, params)
        {
            match event {
                libp2pmdns::MdnsEvent::Discovered(addrs) => {
                    return Poll::Ready(NetworkBehaviourAction::GenerateEvent(
                        DiscoveryEvent::Discovered(addrs.collect::<Vec<_>>()),
                    ));
                }
                libp2pmdns::MdnsEvent::Expired(addrs) => {
                    return Poll::Ready(NetworkBehaviourAction::GenerateEvent(
                        DiscoveryEvent::Expired(addrs.collect::<Vec<_>>()),
                    ));
                }
            }
        }

        // TODO: poll future discovery strategies

        Poll::Pending
    }
}
