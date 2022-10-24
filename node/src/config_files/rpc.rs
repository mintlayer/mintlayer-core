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

use std::net::SocketAddr;

use rpc::RpcConfig;
use serde::{Deserialize, Serialize};

/// The rpc subsystem configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcConfigFile {
    /// Address to bind http RPC to.
    pub http_bind_address: Option<SocketAddr>,

    /// Whether http RPC is enabled
    pub http_enabled: Option<bool>,

    /// Address to bind websocket RPC to.
    pub ws_bind_address: Option<SocketAddr>,

    /// Whether websocket RPC is enabled
    pub ws_enabled: Option<bool>,
}

impl From<RpcConfigFile> for RpcConfig {
    fn from(c: RpcConfigFile) -> Self {
        RpcConfig {
            http_bind_address: c.http_bind_address.into(),
            http_enabled: c.http_enabled.into(),
            ws_bind_address: c.ws_bind_address.into(),
            ws_enabled: c.ws_enabled.into(),
        }
    }
}

impl Default for RpcConfigFile {
    fn default() -> Self {
        Self {
            http_bind_address: None,
            http_enabled: None,
            ws_bind_address: None,
            ws_enabled: None,
        }
    }
}
