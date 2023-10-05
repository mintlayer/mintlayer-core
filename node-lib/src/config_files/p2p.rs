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

use std::{num::NonZeroU64, str::FromStr, time::Duration};

use common::primitives::user_agent::mintlayer_core_user_agent;
use serde::{Deserialize, Serialize};

use p2p::{
    config::{NodeType, P2pConfig},
    types::ip_or_socket_address::IpOrSocketAddress,
};

/// A node type.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, Eq, PartialEq)]
pub enum NodeTypeConfigFile {
    /// A full node.
    #[serde(rename = "full-node", alias = "full")]
    FullNode,
    /// A node that only download blocks, but ignores transactions.
    #[serde(rename = "blocks-only-node", alias = "blocks")]
    BlocksOnlyNode,
}

impl From<NodeTypeConfigFile> for NodeType {
    fn from(t: NodeTypeConfigFile) -> Self {
        match t {
            NodeTypeConfigFile::FullNode => Self::Full,
            NodeTypeConfigFile::BlocksOnlyNode => Self::BlocksOnly,
        }
    }
}

impl FromStr for NodeTypeConfigFile {
    type Err = serde::de::value::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let de = serde::de::value::StrDeserializer::new(s);
        Deserialize::deserialize(de)
    }
}

/// The p2p subsystem configuration.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct P2pConfigFile {
    /// Address to bind P2P to.
    pub bind_addresses: Option<Vec<String>>,
    /// SOCKS5 proxy.
    pub socks5_proxy: Option<String>,
    /// Disable p2p encryption (for tests only).
    pub disable_noise: Option<bool>,
    /// Optional list of boot node addresses to connect.
    pub boot_nodes: Option<Vec<IpOrSocketAddress>>,
    /// Optional list of reserved node addresses to connect.
    pub reserved_nodes: Option<Vec<IpOrSocketAddress>>,
    /// Maximum allowed number of inbound connections.
    pub max_inbound_connections: Option<usize>,
    /// The score threshold after which a peer is banned.
    pub ban_threshold: Option<u32>,
    /// Duration of bans in seconds.
    pub ban_duration: Option<u64>,
    /// Maximum acceptable time difference between this node and the remote peer (in seconds).
    /// If a large difference is detected, the peer will be disconnected.
    pub max_clock_diff: Option<u64>,
    /// The outbound connection timeout value in seconds.
    pub outbound_connection_timeout: Option<NonZeroU64>,
    /// How often send ping requests to peers.
    pub ping_check_period: Option<u64>,
    /// When a peer is detected as dead and disconnected.
    pub ping_timeout: Option<NonZeroU64>,
    /// A timeout after which a peer is disconnected.
    pub sync_stalling_timeout: Option<NonZeroU64>,
    /// A node type.
    pub node_type: Option<NodeTypeConfigFile>,
}

impl From<P2pConfigFile> for P2pConfig {
    fn from(c: P2pConfigFile) -> Self {
        P2pConfig {
            bind_addresses: c.bind_addresses.clone().unwrap_or_default(),
            socks5_proxy: c.socks5_proxy.clone(),
            disable_noise: c.disable_noise,
            boot_nodes: c.boot_nodes.clone().unwrap_or_default(),
            reserved_nodes: c.reserved_nodes.clone().unwrap_or_default(),
            max_inbound_connections: c.max_inbound_connections.into(),
            ban_threshold: c.ban_threshold.into(),
            ban_duration: c.ban_duration.map(Duration::from_secs).into(),
            max_clock_diff: c.max_clock_diff.map(Duration::from_secs).into(),
            outbound_connection_timeout: c
                .outbound_connection_timeout
                .map(|t| Duration::from_secs(t.into()))
                .into(),
            ping_check_period: c.ping_check_period.map(Duration::from_secs).into(),
            ping_timeout: c.ping_timeout.map(|t| Duration::from_secs(t.into())).into(),
            node_type: c.node_type.map(Into::into).into(),
            allow_discover_private_ips: Default::default(),
            msg_header_count_limit: Default::default(),
            msg_max_locator_count: Default::default(),
            max_request_blocks_count: Default::default(),
            user_agent: mintlayer_core_user_agent(),
            max_message_size: Default::default(),
            max_peer_tx_announcements: Default::default(),
            max_singular_unconnected_headers: Default::default(),
            sync_stalling_timeout: c
                .sync_stalling_timeout
                .map(|t| Duration::from_secs(t.into()))
                .into(),
            enable_block_relay_peers: Default::default(),
        }
    }
}
