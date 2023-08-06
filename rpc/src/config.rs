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

use std::fmt::Debug;

use utils::make_config_setting;

make_config_setting!(
    HttpBindAddress,
    Option<String>,
    Some("127.0.0.1:3030".to_string())
);

make_config_setting!(HttpRpcEnabled, bool, true);

/// The rpc subsystem configuration.
#[derive(Debug, Default)]
pub struct RpcConfig {
    /// Address to bind http RPC to.
    pub http_rpc_addr: Option<String>,

    /// Whether http RPC is enabled
    pub http_enabled: HttpRpcEnabled,
}
