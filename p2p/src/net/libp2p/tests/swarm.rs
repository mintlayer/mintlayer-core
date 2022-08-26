// Copyright (c) 2021-2022 RBB S.r.l
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

use super::*;
use crate::error::P2pError;
use futures::StreamExt;
use libp2p::{
    core::upgrade,
    identify, identity, mplex, noise,
    swarm::{DialError, SwarmBuilder, SwarmEvent},
    PeerId, Swarm,
};
use p2p_test_utils::make_libp2p_addr;

// TODO: add more tests at some point

fn make_dummy_swarm() -> (PeerId, Swarm<identify::Identify>) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .map_err(|_| P2pError::Other("Failed to create Noise keys"))
        .unwrap();

    let transport = TcpTransport::new(GenTcpConfig::new().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .outbound_timeout(std::time::Duration::from_secs(5))
        .boxed();

    (
        peer_id,
        SwarmBuilder::new(
            transport,
            identify::Identify::new(identify::IdentifyConfig::new(
                "test_protocol".to_string(),
                id_keys.public(),
            )),
            peer_id,
        )
        .build(),
    )
}

#[tokio::test]
async fn dial_then_disconnect() {
    let (_peer_id1, mut swarm1) = make_dummy_swarm();
    let (peer_id2, mut swarm2) = make_dummy_swarm();

    swarm2.listen_on(make_libp2p_addr()).unwrap();
    let addr = get_address::<identify::Identify>(&mut swarm2).await;

    tokio::spawn(async move {
        loop {
            let _ = swarm2.select_next_some().await;
        }
    });

    assert!(std::matches!(swarm1.dial(addr), Ok(())));
    assert!(std::matches!(swarm1.disconnect_peer_id(peer_id2), Err(())));
    assert!(std::matches!(
        swarm1.select_next_some().await,
        SwarmEvent::ConnectionEstablished { .. }
    ));
    assert!(std::matches!(swarm1.disconnect_peer_id(peer_id2), Ok(())));
    assert!(std::matches!(
        swarm1.select_next_some().await,
        SwarmEvent::ConnectionClosed { .. }
    ));
}

#[tokio::test]
async fn diconnect_closing_connection() {
    let (_peer_id1, mut swarm1) = make_dummy_swarm();
    let (peer_id2, mut swarm2) = make_dummy_swarm();

    swarm2.listen_on(make_libp2p_addr()).unwrap();
    let addr = get_address(&mut swarm2).await;

    tokio::spawn(async move {
        loop {
            let _ = swarm2.select_next_some().await;
        }
    });

    assert!(std::matches!(swarm1.dial(addr), Ok(())));
    assert!(std::matches!(swarm1.disconnect_peer_id(peer_id2), Err(())));
    assert!(std::matches!(
        swarm1.select_next_some().await,
        SwarmEvent::ConnectionEstablished { .. }
    ));

    // send multiple disconnect events
    assert!(std::matches!(swarm1.disconnect_peer_id(peer_id2), Ok(())));
    assert!(std::matches!(swarm1.disconnect_peer_id(peer_id2), Ok(())));
    assert!(std::matches!(swarm1.disconnect_peer_id(peer_id2), Ok(())));

    assert!(std::matches!(
        swarm1.select_next_some().await,
        SwarmEvent::ConnectionClosed { .. }
    ));

    // try to disconnect already disconnected peer
    assert!(std::matches!(swarm1.disconnect_peer_id(peer_id2), Err(())));
}

#[tokio::test]
async fn connect_to_banned_peer() {
    let (_peer_id1, mut swarm1) = make_dummy_swarm();

    let peer_id = PeerId::random();
    swarm1.ban_peer_id(peer_id);
    assert!(std::matches!(swarm1.dial(peer_id), Err(DialError::Banned)));
}
