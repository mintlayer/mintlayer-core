// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::net::SocketAddr;

/// The rpc subsystem configuration.
#[derive(serde::Deserialize, Debug)]
pub struct Config {
    /// Address to bind RPC to.
    #[clap(long, value_name = "ADDR", default_value = "127.0.0.1:3030")]
    pub rpc_addr: SocketAddr,
}
