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

use rpc::RpcConfig;
use serde::{Deserialize, Serialize};

/// The rpc subsystem configuration.
#[must_use]
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RpcConfigFile {
    /// Address to bind http RPC to
    pub http_rpc_addr: Option<String>,

    /// Whether http RPC is enabled
    pub http_enabled: Option<bool>,

    /// Username for RPC HTTP and WebSocket server basic authorization
    pub username: Option<String>,

    /// Password for RPC HTTP and WebSocket server basic authorization
    pub password: Option<String>,

    /// Custom file path for the RPC cookie file
    pub cookie_file: Option<String>,
}

impl From<RpcConfigFile> for RpcConfig {
    fn from(c: RpcConfigFile) -> Self {
        RpcConfig {
            http_rpc_addr: c.http_rpc_addr,
            http_enabled: c.http_enabled.into(),
        }
    }
}
