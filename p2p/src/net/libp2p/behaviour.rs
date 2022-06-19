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
#![allow(unused)]

//! Network behaviour configuration for libp2p

use crate::{
    error::{ConversionError, DialError, P2pError, ProtocolError, PublishError},
    message,
    net::{
        self,
        libp2p::{
            constants::*,
            sync::*,
            types::{self, ComposedEvent},
        },
        types::{ConnectivityEvent, PubSubEvent, PubSubTopic, SyncingEvent},
        ConnectivityService, NetworkingService, PubSubService, SyncingCodecService,
    },
};
use async_trait::async_trait;
use common::chain::config::ChainConfig;
use itertools::*;
use libp2p::{
    core::{upgrade, PeerId},
    gossipsub::{
        self, Gossipsub, GossipsubConfigBuilder, MessageAuthenticity, MessageId, ValidationMode,
    },
    identify, identity, mdns, mplex,
    multiaddr::Protocol,
    noise, ping,
    request_response::*,
    swarm::{
        NetworkBehaviour as Libp2pNetworkBehaviour, NetworkBehaviourEventProcess, SwarmBuilder,
    },
    tcp::TcpConfig,
    Multiaddr, NetworkBehaviour, Transport,
};
use logging::log;
use serialization::{Decode, Encode};
use std::{iter, num::NonZeroU32, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};
use utils::ensure;

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ComposedEvent")]
pub struct Libp2pBehaviour {
    pub mdns: mdns::Mdns,
    pub gossipsub: Gossipsub,
    pub ping: ping::Behaviour,
    pub identify: identify::Identify,
    pub sync: RequestResponse<SyncingCodec>,
}

impl Libp2pBehaviour {
    pub async fn new(
        config: Arc<ChainConfig>,
        id_keys: identity::Keypair,
        topics: &[PubSubTopic],
    ) -> Self {
        let gossipsub_config = GossipsubConfigBuilder::default()
            .heartbeat_interval(GOSSIPSUB_HEARTBEAT)
            .validation_mode(ValidationMode::Strict)
            .max_transmit_size(GOSSIPSUB_MAX_TRANSMIT_SIZE)
            .validate_messages()
            .build()
            .expect("configuration to be valid");

        // TODO: impl display for semver/magic bytes?
        let version = config.version();
        let protocol = format!(
            "/mintlayer/{}.{}.{}-{:x}",
            version.major,
            version.minor,
            version.patch,
            config.magic_bytes_as_u32(),
        );
        let mut req_cfg = RequestResponseConfig::default();
        req_cfg.set_request_timeout(REQ_RESP_TIMEOUT);

        let mut behaviour = Libp2pBehaviour {
            mdns: mdns::Mdns::new(Default::default()).await.expect("mDNS to succeed"),
            ping: ping::Behaviour::new(
                ping::Config::new()
                    .with_timeout(PING_TIMEOUT)
                    .with_interval(PING_INTERVAL)
                    .with_max_failures(
                        NonZeroU32::new(PING_MAX_RETRIES).expect("max failures > 0"),
                    ),
            ),
            identify: identify::Identify::new(identify::IdentifyConfig::new(
                protocol,
                id_keys.public(),
            )),
            sync: RequestResponse::new(
                SyncingCodec(),
                iter::once((SyncingProtocol(), ProtocolSupport::Full)),
                req_cfg,
            ),
            gossipsub: Gossipsub::new(
                MessageAuthenticity::Signed(id_keys.clone()),
                gossipsub_config,
            )
            .expect("configuration to be valid"),
        };

        // subscribes to our topic
        for topic in topics.iter() {
            log::debug!("subscribing to gossipsub topic {:?}", topic);
            behaviour.gossipsub.subscribe(&topic.into()).expect("subscription to work");
        }

        behaviour
    }
}

impl NetworkBehaviourEventProcess<ping::PingEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: ping::PingEvent) {
        println!("ping");
    }
}

impl NetworkBehaviourEventProcess<identify::IdentifyEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: identify::IdentifyEvent) {
        println!("identify");
    }
}

impl NetworkBehaviourEventProcess<gossipsub::GossipsubEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: gossipsub::GossipsubEvent) {
        println!("gossipsub");
    }
}

impl NetworkBehaviourEventProcess<RequestResponseEvent<SyncRequest, SyncResponse>>
    for Libp2pBehaviour
{
    fn inject_event(&mut self, event: RequestResponseEvent<SyncRequest, SyncResponse>) {
        println!("syncing");
    }
}

impl NetworkBehaviourEventProcess<mdns::MdnsEvent> for Libp2pBehaviour {
    fn inject_event(&mut self, event: mdns::MdnsEvent) {
        println!("mdns");
    }
}
