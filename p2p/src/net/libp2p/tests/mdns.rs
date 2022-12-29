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

use std::sync::Arc;

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;

use crate::testing_utils::{TestTransportLibp2p, TestTransportMaker};

use crate::{
    config::{MdnsConfig, NodeType, P2pConfig},
    net::libp2p::{
        behaviour,
        tests::{connect_swarms, make_libp2p},
        types::{ConnectivityEvent, Libp2pBehaviourEvent},
    },
};

#[tokio::test]
async fn test_discovered_and_expired() {
    let (mut backend1, _, _conn_rx, _) = make_libp2p(
        common::chain::config::create_mainnet(),
        Arc::new(P2pConfig {
            bind_address: "/ip6/::1/tcp/3031".to_owned().into(),
            ban_threshold: 100.into(),
            ban_duration: Default::default(),
            outbound_connection_timeout: 10.into(),
            mdns_config: MdnsConfig::Enabled {
                query_interval: 200.into(),
                enable_ipv6_mdns_discovery: Default::default(),
            }
            .into(),
            node_type: NodeType::Full.into(),
            max_tip_age: Default::default(),
        }),
        TestTransportLibp2p::make_address(),
        &[],
    )
    .await;

    let (mut backend2, _, _, _) = make_libp2p(
        common::chain::config::create_mainnet(),
        Arc::new(P2pConfig {
            bind_address: "/ip6/::1/tcp/3031".to_owned().into(),
            ban_threshold: 100.into(),
            ban_duration: Default::default(),
            outbound_connection_timeout: 10.into(),
            mdns_config: MdnsConfig::Enabled {
                query_interval: 200.into(),
                enable_ipv6_mdns_discovery: false.into(),
            }
            .into(),
            node_type: NodeType::Full.into(),
            max_tip_age: Default::default(),
        }),
        TestTransportLibp2p::make_address(),
        &[],
    )
    .await;

    connect_swarms::<behaviour::Libp2pBehaviour, behaviour::Libp2pBehaviour>(
        &mut backend1.swarm,
        &mut backend2.swarm,
    )
    .await;

    loop {
        tokio::select! {
            event = backend1.swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(Libp2pBehaviourEvent::Connectivity(ConnectivityEvent::Discovered { peers })) => {
                    if peers.iter().any(|(peer_id, _)| peer_id == backend2.swarm.local_peer_id()) {
                        let _ = backend1.swarm.disconnect_peer_id(*backend2.swarm.local_peer_id());
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
