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

use utils::make_config_setting;

make_config_setting!(
    HttpBindAddress,
    SocketAddr,
    SocketAddr::from_str("127.0.0.1:3030").expect("Address must be correct")
);

make_config_setting!(HttpRpcEnabled, bool, true);

make_config_setting!(
    WebsocketBindAddress,
    SocketAddr,
    SocketAddr::from_str("127.0.0.1:3032").expect("Address must be correct")
);

make_config_setting!(WebsocketRpcEnabled, bool, true);

/// The rpc subsystem configuration.
#[derive(Debug, Default)]
pub struct RpcConfig {
    /// Address to bind http RPC to.
    pub http_bind_address: HttpBindAddress,

    /// Whether http RPC is enabled
    pub http_enabled: HttpRpcEnabled,

    /// Address to bind websocket RPC to.
    pub ws_bind_address: WebsocketBindAddress,

    /// Whether websocket RPC is enabled
    pub ws_enabled: WebsocketRpcEnabled,
}
