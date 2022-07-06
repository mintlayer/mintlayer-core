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
use crate::net::{
    self,
    libp2p::sync::*,
    libp2p::{backend::Backend, behaviour, discovery, connectivity, types},
};
use futures::prelude::*;
use libp2p::{
    core::{muxing::StreamMuxerBox, transport::Boxed, upgrade, PeerId},
    gossipsub::{Gossipsub, GossipsubConfigBuilder, MessageAuthenticity, ValidationMode},
    identify::{Identify, IdentifyConfig},
    identity, mplex, noise, ping as libp2p_ping,
    request_response::*,
    swarm::NetworkBehaviour,
    swarm::{SwarmBuilder, SwarmEvent},
    tcp::TcpConfig,
    Multiaddr, Swarm, Transport,
};
use logging::log;
use std::{
    collections::{HashMap, VecDeque},
    iter,
    num::NonZeroU32,
};
use tokio::sync::mpsc;

#[cfg(test)]
mod frontend;
#[cfg(test)]
mod gossipsub;
#[cfg(test)]
mod identify;
#[cfg(test)]
mod mdns;
#[cfg(test)]
mod ping;
#[cfg(test)]
mod swarm;

#[allow(dead_code)]
pub async fn make_libp2p(
    config: common::chain::ChainConfig,
    addr: Multiaddr,
    topics: &[net::types::PubSubTopic],
    enable_mdns: bool,
) -> (
    Backend,
    mpsc::Sender<types::Command>,
    mpsc::Receiver<types::ConnectivityEvent>,
    mpsc::Receiver<types::PubSubEvent>,
    mpsc::Receiver<types::SyncingEvent>,
) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("noise keys not authentic");

    let transport = TcpConfig::new()
        .nodelay(true)
        .port_reuse(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .outbound_timeout(std::time::Duration::from_secs(10))
        .boxed();

    let mut swarm = {
        let gossipsub_config = GossipsubConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .validation_mode(ValidationMode::Strict)
            .validate_messages()
            .build()
            .expect("configuration to be valid");

        let version = config.version();
        let magic = config.magic_bytes();
        let protocol = format!(
            "/mintlayer/{}.{}.{}-{:x}",
            version.major,
            version.minor,
            version.patch,
            ((magic[0] as u32) << 24)
                | ((magic[1] as u32) << 16)
                | ((magic[2] as u32) << 8)
                | (magic[3] as u32)
        );

        let mut behaviour = behaviour::Libp2pBehaviour {
            ping: libp2p_ping::Behaviour::new(
                libp2p_ping::Config::new()
                    .with_timeout(std::time::Duration::from_secs(60))
                    .with_interval(std::time::Duration::from_secs(60))
                    .with_max_failures(NonZeroU32::new(3).expect("max failures > 0")),
            ),
            identify: Identify::new(IdentifyConfig::new(protocol, id_keys.public())),
            sync: RequestResponse::new(
                SyncingCodec(),
                iter::once((SyncingProtocol(), ProtocolSupport::Full)),
                RequestResponseConfig::default(),
            ),
            gossipsub: Gossipsub::new(
                MessageAuthenticity::Signed(id_keys.clone()),
                gossipsub_config,
            )
            .expect("configuration to be valid"),
            connmgr: connectivity::ConnectionManager::new(),
            discovery: discovery::DiscoveryManager::new(enable_mdns).await,
            events: VecDeque::new(),
            pending_reqs: HashMap::new(),
            waker: None,
        };

        for topic in topics.iter() {
            log::info!("subscribing to gossipsub topic {:?}", topic);
            behaviour.gossipsub.subscribe(&topic.into()).expect("subscription to work");
        }

        // subscribes to our topic
        SwarmBuilder::new(transport, behaviour, peer_id).build()
    };

    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (gossip_tx, gossip_rx) = mpsc::channel(64);
    let (conn_tx, conn_rx) = mpsc::channel(64);
    let (sync_tx, sync_rx) = mpsc::channel(64);

    swarm.listen_on(addr).expect("swarm listen failed");
    (
        Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx),
        cmd_tx,
        conn_rx,
        gossip_rx,
        sync_rx,
    )
}

#[allow(dead_code)]
pub async fn make_libp2p_with_ping(
    config: common::chain::ChainConfig,
    addr: Multiaddr,
    topics: &[net::types::PubSubTopic],
    ping: libp2p_ping::Behaviour,
    enable_mdns: bool,
) -> (
    Backend,
    mpsc::Sender<types::Command>,
    mpsc::Receiver<types::ConnectivityEvent>,
    mpsc::Receiver<types::PubSubEvent>,
    mpsc::Receiver<types::SyncingEvent>,
) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("noise keys not authentic");

    let transport = TcpConfig::new()
        .nodelay(true)
        .port_reuse(true)
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .outbound_timeout(std::time::Duration::from_secs(10))
        .boxed();

    let mut swarm = {
        let gossipsub_config = GossipsubConfigBuilder::default()
            .heartbeat_interval(std::time::Duration::from_secs(10))
            .validation_mode(ValidationMode::Strict)
            .validate_messages()
            .build()
            .expect("configuration to be valid");

        let version = config.version();
        let magic = config.magic_bytes();
        let protocol = format!(
            "/mintlayer/{}.{}.{}-{:x}",
            version.major,
            version.minor,
            version.patch,
            ((magic[0] as u32) << 24)
                | ((magic[1] as u32) << 16)
                | ((magic[2] as u32) << 8)
                | (magic[3] as u32)
        );

        let mut behaviour = behaviour::Libp2pBehaviour {
            ping,
            identify: Identify::new(IdentifyConfig::new(protocol, id_keys.public())),
            sync: RequestResponse::new(
                SyncingCodec(),
                iter::once((SyncingProtocol(), ProtocolSupport::Full)),
                RequestResponseConfig::default(),
            ),
            gossipsub: Gossipsub::new(
                MessageAuthenticity::Signed(id_keys.clone()),
                gossipsub_config,
            )
            .expect("configuration to be valid"),
            connmgr: connectivity::ConnectionManager::new(),
            discovery: discovery::DiscoveryManager::new(enable_mdns).await,
            events: VecDeque::new(),
            pending_reqs: HashMap::new(),
            waker: None,
        };

        for topic in topics.iter() {
            log::info!("subscribing to gossipsub topic {:?}", topic);
            behaviour.gossipsub.subscribe(&topic.into()).expect("subscription to work");
        }

        // subscribes to our topic
        SwarmBuilder::new(transport, behaviour, peer_id).build()
    };

    let (cmd_tx, cmd_rx) = mpsc::channel(16);
    let (gossip_tx, gossip_rx) = mpsc::channel(64);
    let (conn_tx, conn_rx) = mpsc::channel(64);
    let (sync_tx, sync_rx) = mpsc::channel(64);

    swarm.listen_on(addr).expect("swarm listen failed");
    (
        Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx),
        cmd_tx,
        conn_rx,
        gossip_rx,
        sync_rx,
    )
}

#[allow(dead_code)]
pub async fn connect_swarms<A, B>(addr: Multiaddr, swarm1: &mut Swarm<A>, swarm2: &mut Swarm<B>)
where
    A: NetworkBehaviour,
    B: NetworkBehaviour,
{
    swarm2.dial(addr).expect("swarm dial failed");

    loop {
        tokio::select! {
            event = swarm1.next() => match event {
                Some(SwarmEvent::ConnectionEstablished { peer_id, .. }) => {
                    if peer_id == *swarm2.local_peer_id() {
                        break;
                    }
                }
                Some(_) => {},
                None => panic!("got None"),
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                panic!("didn't receive ConnectionEstablished event in time");
            }
        }
    }
}

#[allow(dead_code)]
pub fn make_transport_and_keys() -> (Boxed<(PeerId, StreamMuxerBox)>, PeerId, identity::Keypair) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("noise keys not authentic");

    (
        TcpConfig::new()
            .nodelay(true)
            .port_reuse(true)
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(mplex::MplexConfig::new())
            .outbound_timeout(std::time::Duration::from_secs(10))
            .boxed(),
        peer_id,
        id_keys,
    )
}

#[allow(dead_code)]
pub fn make_identify(config: common::chain::ChainConfig, id_keys: identity::Keypair) -> Identify {
    let version = config.version();
    let magic = config.magic_bytes();
    let protocol = format!(
        "/mintlayer/{}.{}.{}-{:x}",
        version.major,
        version.minor,
        version.patch,
        ((magic[0] as u32) << 24)
            | ((magic[1] as u32) << 16)
            | ((magic[2] as u32) << 8)
            | (magic[3] as u32)
    );

    Identify::new(IdentifyConfig::new(protocol, id_keys.public()))
}

#[allow(dead_code)]
pub fn make_ping(
    timeout: Option<std::time::Duration>,
    interval: Option<std::time::Duration>,
    max_failures: Option<u32>,
) -> libp2p_ping::Behaviour {
    libp2p_ping::Behaviour::new(
        libp2p_ping::Config::new()
            .with_timeout(timeout.unwrap_or(std::time::Duration::from_secs(60)))
            .with_interval(interval.unwrap_or(std::time::Duration::from_secs(60)))
            .with_max_failures(
                NonZeroU32::new(max_failures.unwrap_or(20)).expect("max failures > 0"),
            ),
    )
}
