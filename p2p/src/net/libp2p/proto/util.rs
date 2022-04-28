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
    error::{self, Libp2pError, P2pError, ProtocolError},
    message,
    net::{
        self,
        libp2p::sync::*,
        libp2p::{backend::Backend, types},
        ConnectivityEvent, ConnectivityService, NetworkService, PubSubEvent, PubSubService,
        PubSubTopic, SyncingMessage, SyncingService,
    },
};
use async_trait::async_trait;
use futures::prelude::*;
use itertools::*;
use libp2p::{
    core::{
        muxing::StreamMuxerBox,
        transport::Boxed,
        upgrade::{self, read_length_prefixed, write_length_prefixed},
        PeerId,
    },
    gossipsub::{
        Gossipsub, GossipsubConfigBuilder, GossipsubEvent, GossipsubMessage, IdentTopic as Topic,
        MessageAuthenticity, MessageId, ValidationMode,
    },
    identify::{Identify, IdentifyConfig, IdentifyInfo},
    identity,
    mdns::Mdns,
    mplex,
    multiaddr::Protocol,
    noise, ping,
    request_response::*,
    swarm::NetworkBehaviour,
    swarm::{NegotiatedSubstream, SwarmBuilder, SwarmEvent},
    tcp::TcpConfig,
    Multiaddr, Swarm, Transport,
};
use logging::log;
use parity_scale_codec::{Decode, Encode};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    io, iter,
    num::NonZeroU32,
    sync::Arc,
};
use tokio::sync::{mpsc, oneshot};

// TODO: add config parameters
pub async fn make_libp2p(
    // TODO: convert these into `Option<T> + unwrap_or()`
    config: common::chain::ChainConfig,
    addr: Multiaddr,
    topics: &[net::PubSubTopic],
) -> (
    Backend,
    mpsc::Sender<types::Command>,
    mpsc::Receiver<types::ConnectivityEvent>,
    mpsc::Receiver<types::PubSubEvent>,
    mpsc::Receiver<types::SyncingEvent>,
) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys).unwrap();

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

        // TODO: impl display for semver/magic bytes?
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

        let mut behaviour = types::ComposedBehaviour {
            mdns: Mdns::new(Default::default()).await.unwrap(),
            ping: ping::Behaviour::new(
                ping::Config::new()
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

    swarm.listen_on(addr).unwrap();
    (
        Backend::new(swarm, cmd_rx, conn_tx, gossip_tx, sync_tx, true),
        cmd_tx,
        conn_rx,
        gossip_rx,
        sync_rx,
    )
}

pub async fn connect_swarms<A, B>(addr: Multiaddr, swarm1: &mut Swarm<A>, swarm2: &mut Swarm<B>)
where
    A: NetworkBehaviour,
    B: NetworkBehaviour,
{
    swarm2.dial(addr).unwrap();

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

pub fn make_transport_and_keys() -> (Boxed<(PeerId, StreamMuxerBox)>, PeerId, identity::Keypair) {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = id_keys.public().to_peer_id();
    let noise_keys = noise::Keypair::<noise::X25519Spec>::new().into_authentic(&id_keys).unwrap();

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

pub fn make_identify(config: common::chain::ChainConfig, id_keys: identity::Keypair) -> Identify {
    // TODO: impl display for semver/magic bytes?
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
