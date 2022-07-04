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
use super::*;
use crate::net::libp2p::behaviour;
use crate::net::libp2p::types::{ConnectivityEvent, Libp2pBehaviourEvent};
use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::Multiaddr;

#[tokio::test]
async fn test_discovered_and_expired() {
    let addr: Multiaddr = test_utils::make_address("/ip6/::1/tcp/");
    let (mut backend1, _, _conn_rx, _, _) = make_libp2p(
        common::chain::config::create_mainnet(),
        addr.clone(),
        &[],
        true,
    )
    .await;

    let (mut backend2, _, _, _, _) = make_libp2p(
        common::chain::config::create_mainnet(),
        test_utils::make_address("/ip6/::1/tcp/"),
        &[],
        true,
    )
    .await;

    connect_swarms::<behaviour::Libp2pBehaviour, behaviour::Libp2pBehaviour>(
        addr,
        &mut backend1.swarm,
        &mut backend2.swarm,
    )
    .await;

    loop {
        tokio::select! {
            event = backend1.swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(Libp2pBehaviourEvent::Connectivity(ConnectivityEvent::Discovered { peers })) => {
                    if peers.iter().any(|(peer_id, _)| peer_id == backend2.swarm.local_peer_id()) {
                        backend1.swarm.disconnect_peer_id(*backend2.swarm.local_peer_id()).unwrap();
                    }
                }
                SwarmEvent::Behaviour(Libp2pBehaviourEvent::Connectivity(ConnectivityEvent::Expired { peers })) => {
                    if peers.iter().any(|(peer_id, _)| peer_id == backend2.swarm.local_peer_id()) {
                        break;
                    }
                }
                _event => {},
            },
            _event = backend2.swarm.next() => {}
        }
    }
}
