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

use std::{net::SocketAddr, str::FromStr};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// The rpc subsystem configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct RpcConfig {
    /// Address to bind http RPC to.
    pub http_bind_address: Option<SocketAddr>,

    /// Whether http RPC is enabled
    pub http_enabled: Option<bool>,

    /// Address to bind websocket RPC to.
    pub ws_bind_address: Option<SocketAddr>,

    /// Whether websocket RPC is enabled
    pub ws_enabled: Option<bool>,
}

impl RpcConfig {
    /// Creates a new rpc configuration instance.
    pub fn new() -> Result<Self> {
        Ok(Self {
            http_bind_address: Some(SocketAddr::from_str("127.0.0.1:3030")?),
            http_enabled: Some(true),
            ws_bind_address: Some(SocketAddr::from_str("127.0.0.1:3031")?),
            ws_enabled: Some(true),
        })
    }
}
