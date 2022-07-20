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

use crate::config;
use libp2p::{
    core::{
        connection::{ConnectedPoint, ConnectionId},
        PeerId,
    },
    mdns as libp2pmdns,
    swarm::{
        handler::DummyConnectionHandler, ConnectionHandler, IntoConnectionHandler,
        NetworkBehaviour, NetworkBehaviourAction, PollParameters,
    },
    Multiaddr,
};
use std::{
    sync::Arc,
    task::{Context, Poll},
};

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
    pub async fn new(p2p_config: Arc<config::P2pConfig>) -> Self {
        Self {
            mdns: mdns::Mdns::new(
                p2p_config.enable_mdns,
                p2p_config.mdns_enable_ipv6,
                p2p_config.mdns_query_interval,
            )
            .await,
        }
    }
}

impl NetworkBehaviour for DiscoveryManager {
    type ConnectionHandler = DummyConnectionHandler;
    type OutEvent = DiscoveryEvent;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        DummyConnectionHandler::default()
    }

    fn inject_event(
        &mut self,
        _peer_id: PeerId,
        _connection: ConnectionId,
        _event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent,
    ) {
    }

    fn inject_connection_closed(
        &mut self,
        peer_id: &PeerId,
        connection_id: &ConnectionId,
        endpoint: &ConnectedPoint,
        event: DummyConnectionHandler,
        remaining_established: usize,
    ) {
        self.mdns.inject_connection_closed(
            peer_id,
            connection_id,
            endpoint,
            event,
            remaining_established,
        );
    }

    fn poll(
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
