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

use p2p::config::{NodeType, P2pConfig};

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
    pub bind_addresses: Option<Vec<String>>,
    /// Optional list of initial node addresses to connect.
    pub added_nodes: Option<Vec<String>>,
    /// The score threshold after which a peer is banned.
    pub ban_threshold: Option<u32>,
    /// Duration of bans in seconds.
    pub ban_duration: Option<u64>,
    /// The outbound connection timeout value in seconds.
    pub outbound_connection_timeout: Option<u64>,
    /// A node type.
    pub node_type: Option<NodeTypeConfigFile>,
}

impl From<P2pConfigFile> for P2pConfig {
    fn from(c: P2pConfigFile) -> Self {
        P2pConfig {
            bind_addresses: c.bind_addresses.clone().unwrap_or_default(),
            added_nodes: c.added_nodes.clone().unwrap_or_default(),
            ban_threshold: c.ban_threshold.into(),
            ban_duration: c.ban_duration.map(Duration::from_secs).into(),
            outbound_connection_timeout: c.outbound_connection_timeout.into(),
            node_type: c.node_type.map(Into::into).into(),
        }
    }
}
