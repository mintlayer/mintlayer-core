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

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use common::primitives::user_agent::UserAgent;
use utils::make_config_setting;
use utils_networking::IpOrSocketAddress;

use crate::{
    ban_config::BanConfig,
    net::types::services::{Service, Services},
    peer_manager::config::PeerManagerConfig,
    protocol::ProtocolConfig,
};

make_config_setting!(OutboundConnectionTimeout, Duration, Duration::from_secs(10));
make_config_setting!(NodeTypeSetting, NodeType, NodeType::Full);
make_config_setting!(AllowDiscoverPrivateIps, bool, false);
make_config_setting!(PingCheckPeriod, Duration, Duration::from_secs(60));
make_config_setting!(PingTimeout, Duration, Duration::from_secs(150));
make_config_setting!(MaxClockDiff, Duration, Duration::from_secs(10));
make_config_setting!(SyncStallingTimeout, Duration, Duration::from_secs(25));
make_config_setting!(PeerHandshakeTimeout, Duration, Duration::from_secs(10));

/// A node type.
#[derive(Debug, Copy, Clone)]
pub enum NodeType {
    /// A full node.
    Full,
    /// A node that only download blocks, but ignores transactions.
    BlocksOnly,
    /// A node interested only in network address announcements.
    DnsServer,
    /// A node that doesn't subscribe to any events.
    ///
    /// This node type isn't useful outside of the tests.
    Inactive,
}

impl From<NodeType> for Services {
    fn from(t: NodeType) -> Self {
        match t {
            NodeType::Full => [Service::Blocks, Service::Transactions, Service::PeerAddresses]
                .as_slice()
                .into(),
            NodeType::BlocksOnly => [Service::Blocks, Service::PeerAddresses].as_slice().into(),
            NodeType::DnsServer => [Service::PeerAddresses].as_slice().into(),
            NodeType::Inactive => [].as_slice().into(),
        }
    }
}

/// The p2p subsystem configuration.
#[derive(Debug)]
pub struct P2pConfig {
    /// Address to bind P2P to.
    pub bind_addresses: Vec<SocketAddr>,
    /// SOCKS5 proxy.
    pub socks5_proxy: Option<String>,
    /// Disable p2p encryption (for tests only).
    pub disable_noise: Option<bool>,
    /// Optional list of initial node addresses.
    /// Boot node addresses are added to PeerDb as regular discovered addresses.
    pub boot_nodes: Vec<IpOrSocketAddress>,
    /// Optional list of reserved node addresses.
    /// PeerManager will try to maintain persistent connections to the reserved nodes.
    /// Ban scores are not adjusted for the reserved nodes.
    pub reserved_nodes: Vec<IpOrSocketAddress>,
    /// Optional list of whitelisted addresses. Such addresses cannot be automatically banned.
    pub whitelisted_addresses: Vec<IpAddr>,
    /// Settings related to banning and discouragement.
    pub ban_config: BanConfig,
    /// The outbound connection timeout value in seconds.
    pub outbound_connection_timeout: OutboundConnectionTimeout,
    /// How often send ping requests to peers
    pub ping_check_period: PingCheckPeriod,
    /// When a peer is detected as dead and disconnected
    pub ping_timeout: PingTimeout,
    /// Timeout for initial peer handshake
    pub peer_handshake_timeout: PeerHandshakeTimeout,
    /// Maximum acceptable time difference between this node and the remote peer.
    /// If a large difference is detected, the peer will be disconnected.
    pub max_clock_diff: MaxClockDiff,
    /// A node type.
    pub node_type: NodeTypeSetting,
    /// Allow announcing and discovering local and private IPs. Should be used for testing only.
    pub allow_discover_private_ips: AllowDiscoverPrivateIps,
    /// User agent value of this node (sent to peers over the network).
    pub user_agent: UserAgent,
    /// A timeout after which a peer is disconnected.
    pub sync_stalling_timeout: SyncStallingTimeout,
    /// Various settings used internally by the peer manager.
    pub peer_manager_config: PeerManagerConfig,
    /// Various limits related to the protocol; these should only be overridden in tests.
    pub protocol_config: ProtocolConfig,
}

impl P2pConfig {
    /// Effective max clock difference between our node and a peer.
    ///
    /// It is calculated as the max clock diff setting plus handshake timeout to allow for
    /// imprecisions caused by the network latency.
    pub fn effective_max_clock_diff(&self) -> Duration {
        *self.max_clock_diff + *self.peer_handshake_timeout
    }
}
