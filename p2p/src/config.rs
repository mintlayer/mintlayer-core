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

make_config_setting!(BanThreshold, u32, 100);
make_config_setting!(BanDuration, Duration, Duration::from_secs(60 * 60 * 24));
make_config_setting!(OutboundConnectionTimeout, Duration, Duration::from_secs(10));
make_config_setting!(NodeTypeSetting, NodeType, NodeType::Full);
make_config_setting!(AllowDiscoverPrivateIps, bool, false);
make_config_setting!(PingCheckPeriod, Duration, Duration::from_secs(60));
make_config_setting!(PingTimeout, Duration, Duration::from_secs(150));

/// A node type.
#[derive(Debug, Copy, Clone)]
pub enum NodeType {
    /// A full node.
    Full,
    /// A node that only download blocks, but ignores transactions.
    BlocksOnly,
    /// A node that only is interested in network address announcements
    DnsServer,
    /// A node that doesn't subscribe to any events.
    ///
    /// This node type isn't useful outside of the tests.
    Inactive,
}

impl From<NodeType> for BTreeSet<PubSubTopic> {
    fn from(t: NodeType) -> Self {
        match t {
            NodeType::Full => {
                [PubSubTopic::Blocks, PubSubTopic::Transactions, PubSubTopic::PeerAddresses]
                    .into_iter()
                    .collect()
            }
            NodeType::BlocksOnly => [PubSubTopic::Blocks].into_iter().collect(),
            NodeType::DnsServer => [PubSubTopic::PeerAddresses].into_iter().collect(),
            NodeType::Inactive => BTreeSet::new(),
        }
    }
}

/// The p2p subsystem configuration.
#[derive(Debug, Default)]
pub struct P2pConfig {
    /// Address to bind P2P to.
    pub bind_addresses: Vec<String>,
    /// Optional list of initial node addresses, could be used to specify boot nodes for example.
    pub added_nodes: Vec<String>,
    /// The score threshold after which a peer is banned.
    pub ban_threshold: BanThreshold,
    /// Duration of bans in seconds.
    pub ban_duration: BanDuration,
    /// The outbound connection timeout value in seconds.
    pub outbound_connection_timeout: OutboundConnectionTimeout,
    /// How often send ping requests to peers
    pub ping_check_period: PingCheckPeriod,
    /// When a peer is detected as dead and disconnected
    pub ping_timeout: PingTimeout,
    /// A node type.
    pub node_type: NodeTypeSetting,
    /// Allow announcing and discovering local and private IPs. Should be used for testing only.
    pub allow_discover_private_ips: AllowDiscoverPrivateIps,
}
