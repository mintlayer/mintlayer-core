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

use std::{collections::BTreeSet, time::Duration};

use utils::make_config_setting;

use crate::net::types::PubSubTopic;

// TODO: does this constant make sense to be zero? Find the justification for it.
pub const MDNS_DEFAULT_QUERY_INTERVAL: u64 = 0;
pub const MDNS_DEFAULT_IPV6_STATE: bool = false;

make_config_setting!(P2pBindAddress, String, "/ip6/::1/tcp/3031".into());
make_config_setting!(BanThreshold, u32, 100);
make_config_setting!(BanDuration, Duration, Duration::from_secs(60 * 60 * 24));
make_config_setting!(OutboundConnectionTimeout, u64, 10);
make_config_setting!(MdnsConfigSetting, MdnsConfig, MdnsConfig::Disabled);
make_config_setting!(MdnsQueryInterval, u64, MDNS_DEFAULT_QUERY_INTERVAL);
make_config_setting!(MdnsEnableIpV6Discovery, bool, MDNS_DEFAULT_IPV6_STATE);
make_config_setting!(
    /// The request timeout value.
    RequestTimeout,
    Duration,
    Duration::from_secs(10)
);
make_config_setting!(
    AnnouncementSubscriptions,
    BTreeSet<PubSubTopic>,
    [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect()
);
make_config_setting!(NodeTypeSetting, NodeType, NodeType::Full);

/// Multicast DNS configuration.
#[derive(Debug, Clone)]
pub enum MdnsConfig {
    Enabled {
        /// Interval (in milliseconds) at which to poll the network for new peers.
        query_interval: MdnsQueryInterval,
        /// Use IPv6 for multicast DNS
        enable_ipv6_mdns_discovery: MdnsEnableIpV6Discovery,
    },
    Disabled,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        MdnsConfig::Disabled
    }
}

/// A node type.
#[derive(Debug, Copy, Clone)]
pub enum NodeType {
    /// A full node.
    Full,
    /// A node that only download blocks, but ignores transactions.
    BlocksOnly,
    /// A node that doesn't subscribe to any events.
    ///
    /// This node type isn't useful outside of the tests.
    Inactive,
}

impl From<NodeType> for BTreeSet<PubSubTopic> {
    fn from(t: NodeType) -> Self {
        match t {
            NodeType::Full => {
                [PubSubTopic::Blocks, PubSubTopic::Transactions].into_iter().collect()
            }
            NodeType::BlocksOnly => [PubSubTopic::Blocks].into_iter().collect(),
            NodeType::Inactive => BTreeSet::new(),
        }
    }
}

/// The p2p subsystem configuration.
#[derive(Debug, Default)]
pub struct P2pConfig {
    /// Address to bind P2P to.
    pub bind_address: P2pBindAddress,
    /// The score threshold after which a peer is banned.
    pub ban_threshold: BanThreshold,
    /// Duration of bans in seconds.
    pub ban_duration: BanDuration,
    /// The outbound connection timeout value in seconds.
    pub outbound_connection_timeout: OutboundConnectionTimeout,
    /// Multicast DNS configuration.
    pub mdns_config: MdnsConfigSetting,
    /// The request timeout value.
    ///
    /// The peers that failed to respond before this timeout are disconnected.
    pub request_timeout: RequestTimeout,
    /// A node type.
    pub node_type: NodeTypeSetting,
}
