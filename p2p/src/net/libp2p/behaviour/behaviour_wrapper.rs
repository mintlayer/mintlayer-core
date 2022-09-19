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

use std::{iter, num::NonZeroU32, sync::Arc};

use libp2p::{
    gossipsub::{Gossipsub, GossipsubConfigBuilder, MessageAuthenticity, ValidationMode},
    identify::{Identify, IdentifyConfig},
    identity::Keypair,
    ping,
    request_response::{ProtocolSupport, RequestResponse, RequestResponseConfig},
    swarm::NetworkBehaviour,
    NetworkBehaviour,
};

use common::chain::config::ChainConfig;

use crate::{
    config::P2pConfig,
    net::libp2p::{
        behaviour::{
            connection_manager::ConnectionManager,
            discovery::DiscoveryManager,
            sync_codec::{SyncMessagingCodec, SyncingProtocol},
        },
        constants::{
            GOSSIPSUB_HEARTBEAT, GOSSIPSUB_MAX_TRANSMIT_SIZE, PING_INTERVAL, PING_MAX_RETRIES,
            PING_TIMEOUT, REQ_RESP_TIMEOUT,
        },
        types::Libp2pBehaviourEvent,
    },
};

// The `NetworkBehaviour` derive requires that every field implements the `NetworkBehaviour` trait,
// so this wrapper is needed to separate behaviours from other fields of the `Libp2pBehaviour`
// struct.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Libp2pBehaviourEvent")]
pub struct NetworkBehaviourWrapper {
    pub connmgr: ConnectionManager,
    pub identify: Identify,
    pub discovery: DiscoveryManager,
    pub gossipsub: Gossipsub,
    pub ping: ping::Behaviour,
    pub sync: RequestResponse<SyncMessagingCodec>,
}

impl NetworkBehaviourWrapper {
    pub async fn new(
        config: Arc<ChainConfig>,
        p2p_config: Arc<P2pConfig>,
        id_keys: Keypair,
    ) -> Self {
        let gossipsub_config = GossipsubConfigBuilder::default()
            .heartbeat_interval(GOSSIPSUB_HEARTBEAT)
            .validation_mode(ValidationMode::Strict)
            .max_transmit_size(GOSSIPSUB_MAX_TRANSMIT_SIZE)
            .validate_messages()
            .build()
            .expect("configuration to be valid");

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

        let connmgr = ConnectionManager::new();
        let identify = Identify::new(IdentifyConfig::new(protocol, id_keys.public()));
        let discovery = DiscoveryManager::new(Arc::clone(&p2p_config)).await;
        let gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(id_keys.clone()),
            gossipsub_config,
        )
        .expect("configuration to be valid");
        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_timeout(PING_TIMEOUT)
                .with_interval(PING_INTERVAL)
                .with_max_failures(NonZeroU32::new(PING_MAX_RETRIES).expect("max failures > 0")),
        );
        let sync = RequestResponse::new(
            SyncMessagingCodec(),
            iter::once((SyncingProtocol(), ProtocolSupport::Full)),
            req_cfg,
        );

        Self {
            connmgr,
            identify,
            discovery,
            gossipsub,
            ping,
            sync,
        }
    }
}
