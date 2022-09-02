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

use behaviour::sync_codec::*;

use crate::net::{
    self, config,
    libp2p::{backend::Libp2pBackend, behaviour, types},
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
    tcp::{GenTcpConfig, TokioTcpTransport},
    Multiaddr, Swarm, Transport,
};
use logging::log;
use std::{
    collections::{HashMap, VecDeque},
    iter,
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};
use tokio::{sync::mpsc, time::timeout};

use super::behaviour::{connection_manager, discovery};

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
mod request_response;
#[cfg(test)]
mod swarm;

#[allow(dead_code)]
pub async fn make_libp2p(
    config: common::chain::ChainConfig,
    p2p_config: Arc<config::P2pConfig>,
    addr: Multiaddr,
    topics: &[net::types::PubSubTopic],
) -> (
    Libp2pBackend,
    mpsc::UnboundedSender<types::Command>,
    mpsc::UnboundedReceiver<types::ConnectivityEvent>,
    mpsc::UnboundedReceiver<types::PubSubEvent>,
    mpsc::UnboundedReceiver<types::SyncingEvent>,
) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("noise keys not authentic");

    let transport = TokioTcpTransport::new(GenTcpConfig::new().nodelay(true))
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
                SyncMessagingCodec(),
                iter::once((SyncingProtocol(), ProtocolSupport::Full)),
                RequestResponseConfig::default(),
            ),
            gossipsub: Gossipsub::new(
                MessageAuthenticity::Signed(id_keys.clone()),
                gossipsub_config,
            )
            .expect("configuration to be valid"),
            connmgr: connection_manager::ConnectionManager::new(),
            discovery: discovery::DiscoveryManager::new(p2p_config).await,
            events: VecDeque::new(),
            pending_reqs: HashMap::new(),
            waker: None,
        };

        for topic in topics.iter() {
            log::info!("subscribing to gossipsub topic {:?}", topic);
            behaviour.gossipsub.subscribe(&topic.into()).expect("subscription to work");
        }

        // subscribes to our topic
        SwarmBuilder::new(transport, behaviour, peer_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build()
    };

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (gossip_tx, gossip_rx) = mpsc::unbounded_channel();
    let (conn_tx, conn_rx) = mpsc::unbounded_channel();
    let (sync_tx, sync_rx) = mpsc::unbounded_channel();

    swarm.listen_on(addr).expect("swarm listen failed");
    (
        Libp2pBackend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx),
        cmd_tx,
        conn_rx,
        gossip_rx,
        sync_rx,
    )
}

#[allow(dead_code)]
pub async fn make_libp2p_with_ping(
    config: common::chain::ChainConfig,
    p2p_config: Arc<config::P2pConfig>,
    addr: Multiaddr,
    topics: &[net::types::PubSubTopic],
    ping: libp2p_ping::Behaviour,
) -> (
    Libp2pBackend,
    mpsc::UnboundedSender<types::Command>,
    mpsc::UnboundedReceiver<types::ConnectivityEvent>,
    mpsc::UnboundedReceiver<types::PubSubEvent>,
    mpsc::UnboundedReceiver<types::SyncingEvent>,
) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("noise keys not authentic");

    let transport = TokioTcpTransport::new(GenTcpConfig::new().nodelay(true))
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
                SyncMessagingCodec(),
                iter::once((SyncingProtocol(), ProtocolSupport::Full)),
                RequestResponseConfig::default(),
            ),
            gossipsub: Gossipsub::new(
                MessageAuthenticity::Signed(id_keys.clone()),
                gossipsub_config,
            )
            .expect("configuration to be valid"),
            connmgr: connection_manager::ConnectionManager::new(),
            discovery: discovery::DiscoveryManager::new(Arc::clone(&p2p_config)).await,
            events: VecDeque::new(),
            pending_reqs: HashMap::new(),
            waker: None,
        };

        for topic in topics.iter() {
            log::info!("subscribing to gossipsub topic {:?}", topic);
            behaviour.gossipsub.subscribe(&topic.into()).expect("subscription to work");
        }

        // subscribes to our topic
        SwarmBuilder::new(transport, behaviour, peer_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build()
    };

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (gossip_tx, gossip_rx) = mpsc::unbounded_channel();
    let (conn_tx, conn_rx) = mpsc::unbounded_channel();
    let (sync_tx, sync_rx) = mpsc::unbounded_channel();

    swarm.listen_on(addr).expect("swarm listen failed");
    (
        Libp2pBackend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx),
        cmd_tx,
        conn_rx,
        gossip_rx,
        sync_rx,
    )
}

async fn get_address<T: NetworkBehaviour>(swarm: &mut Swarm<T>) -> Multiaddr {
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } =
            timeout(Duration::from_secs(5), swarm.select_next_some())
                .await
                .expect("event to be received")
        {
            return address;
        }
    }
}

#[allow(dead_code)]
pub async fn connect_swarms<A, B>(swarm1: &mut Swarm<A>, swarm2: &mut Swarm<B>)
where
    A: NetworkBehaviour,
    B: NetworkBehaviour,
{
    let addr = get_address::<A>(swarm1).await;

    for _ in 0..3 {
        swarm2.dial(addr.clone()).expect("dial to succeed");

        loop {
            tokio::select! {
                event = swarm1.select_next_some() => {
                    if let  SwarmEvent::ConnectionEstablished { peer_id, .. } = event {
                        if peer_id == *swarm2.local_peer_id() {
                            return;
                        }
                    }
                },
                _ = tokio::time::sleep(Duration::from_secs(5)) => {
                    break;
                }
            }
        }
    }

    panic!("failed to establish connection with other swarm");
}

#[allow(dead_code)]
pub fn make_transport_and_keys() -> (Boxed<(PeerId, StreamMuxerBox)>, PeerId, identity::Keypair) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&id_keys)
        .expect("noise keys not authentic");

    (
        TokioTcpTransport::new(GenTcpConfig::new().nodelay(true))
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
