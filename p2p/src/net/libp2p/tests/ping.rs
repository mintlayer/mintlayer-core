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
use futures::StreamExt;
use libp2p::{
    ping,
    swarm::{SwarmBuilder, SwarmEvent},
};
use p2p_test_utils::make_libp2p_addr;
use std::time::Duration;

#[tokio::test]
async fn test_remote_doesnt_respond() {
    let (mut backend1, _cmd, _conn_rx, _gossip_rx, _sync_rx) = make_libp2p_with_ping(
        common::chain::config::create_mainnet(),
        Arc::new(Default::default()),
        make_libp2p_addr(),
        &[],
        make_ping(
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(2)),
            Some(3),
        ),
    )
    .await;

    let (transport, peer_id, _id_keys) = make_transport_and_keys();
    let mut swarm = SwarmBuilder::new(
        transport,
        make_ping(
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(2)),
            Some(3),
        ),
        peer_id,
    )
    .build();

    connect_swarms::<behaviour::Libp2pBehaviour, ping::Behaviour>(&mut backend1.swarm, &mut swarm)
        .await;

    loop {
        tokio::select! {
            event = backend1.swarm.select_next_some() => match event {
                SwarmEvent::ConnectionClosed { .. } => { break },
                _event => {},
            }
        }
    }
}

#[tokio::test]
async fn test_ping_not_supported() {
    let config = common::chain::config::create_mainnet();
    let (mut backend1, _cmd, _conn_rx, _gossip_rx, _) = make_libp2p_with_ping(
        config.clone(),
        Arc::new(Default::default()),
        make_libp2p_addr(),
        &[],
        make_ping(
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(2)),
            Some(3),
        ),
    )
    .await;

    let (transport, peer_id, id_keys) = make_transport_and_keys();
    let mut swarm = SwarmBuilder::new(transport, make_identify(config, id_keys), peer_id).build();

    connect_swarms::<behaviour::Libp2pBehaviour, libp2p::identify::Identify>(
        &mut backend1.swarm,
        &mut swarm,
    )
    .await;

    loop {
        tokio::select! {
            event = backend1.swarm.select_next_some() => match event {
                SwarmEvent::ConnectionClosed { .. } => { break },
                _event => {},
            },
            _event = swarm.next() => {},
        }
    }
}
