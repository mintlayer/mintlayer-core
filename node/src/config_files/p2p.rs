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

use std::{str::FromStr, time::Duration};

use serde::{Deserialize, Serialize};

use p2p::config::{MdnsConfig, NodeType, P2pConfig};

/// Multicast DNS configuration.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "state")]
pub enum MdnsConfigFile {
    Enabled {
        /// Interval (in milliseconds) at which to poll the network for new peers.
        query_interval: Option<u64>,
        /// Use IPv6 for multicast DNS
        enable_ipv6_mdns_discovery: Option<bool>,
    },
    Disabled,
}

impl MdnsConfigFile {
    pub fn from_options(
        enable_mdns: Option<bool>,
        query_interval: Option<u64>,
        enable_ipv6_mdns_discovery: Option<bool>,
    ) -> Option<Self> {
        match enable_mdns {
            Some(enable_mdns) => {
                if enable_mdns {
                    Some(MdnsConfigFile::Enabled {
                        query_interval,
                        enable_ipv6_mdns_discovery,
                    })
                } else {
                    assert!(
                        query_interval.is_none(),
                        "mDNS is disabled but query interval is specified"
                    );
                    assert!(
                        enable_ipv6_mdns_discovery.is_none(),
                        "mDNS is disabled but transport over IPv6 is enabled"
                    );

                    Some(MdnsConfigFile::Disabled)
                }
            }
            None => {
                assert!(
                    query_interval.is_none(),
                    "mDNS enable state not specified but query interval is specified"
                );
                assert!(
                    enable_ipv6_mdns_discovery.is_none(),
                    "mDNS enable state not specified but transport over IPv6 is enabled"
                );

                None
            }
        }
    }
}

impl From<MdnsConfigFile> for MdnsConfig {
    fn from(c: MdnsConfigFile) -> Self {
        match c {
            MdnsConfigFile::Enabled {
                query_interval,
                enable_ipv6_mdns_discovery,
            } => MdnsConfig::Enabled {
                query_interval: query_interval.into(),
                enable_ipv6_mdns_discovery: enable_ipv6_mdns_discovery.into(),
            },
            MdnsConfigFile::Disabled => MdnsConfig::Disabled,
        }
    }
}

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
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct P2pConfigFile {
    /// Address to bind P2P to.
    pub bind_address: Option<String>,
    /// The score threshold after which a peer is banned.
    pub ban_threshold: Option<u32>,
    /// Duration of bans in seconds.
    pub ban_duration: Option<u64>,
    /// The outbound connection timeout value in seconds.
    pub outbound_connection_timeout: Option<u64>,
    /// Multicast DNS configuration.
    pub mdns_config: Option<MdnsConfigFile>,
    /// A node type.
    pub node_type: Option<NodeTypeConfigFile>,
    /// A maximum tip age in seconds.
    ///
    /// The initial block download is finished if the difference between the current time and the
    /// tip time is less than this value.
    pub max_tip_age: Option<u64>,
}

impl From<P2pConfigFile> for P2pConfig {
    fn from(c: P2pConfigFile) -> Self {
        let mdns_config: Option<MdnsConfig> = c.mdns_config.map(|v| v.into());
        P2pConfig {
            bind_address: c.bind_address.into(),
            ban_threshold: c.ban_threshold.into(),
            ban_duration: c.ban_duration.map(Duration::from_secs).into(),
            outbound_connection_timeout: c.outbound_connection_timeout.into(),
            mdns_config: mdns_config.into(),
            node_type: c.node_type.map(Into::into).into(),
            max_tip_age: c.max_tip_age.map(Duration::from_secs).into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn mdns_disabled_but_query_interval_specified() {
        MdnsConfigFile::from_options(Some(false), Some(200), None);
    }

    #[test]
    #[should_panic]
    fn mdns_disabled_but_ipv6_enabled() {
        MdnsConfigFile::from_options(Some(false), None, Some(true));
    }
}
