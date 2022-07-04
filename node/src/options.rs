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

//! Node configuration options

use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;
use strum::VariantNames;

use common::chain::config::ChainType;

/// Mintlayer node executable
#[derive(clap::Parser, Debug)]
#[clap(author, version, about)]
pub struct Options {
    /// Where to write logs
    #[clap(long, value_name = "PATH")]
    pub log_path: Option<PathBuf>,

    /// Address to bind RPC to
    #[clap(long, value_name = "ADDR", default_value = "127.0.0.1:3030")]
    pub rpc_addr: SocketAddr,

    /// Blockchain type
    #[clap(long, possible_values = ChainType::VARIANTS, default_value = "mainnet")]
    pub net: ChainType,

    /// Address to bind P2P to
    #[clap(long, value_name = "ADDR", default_value = "/ip6/::1/tcp/3031")]
    pub p2p_addr: String,
}

impl Options {
    pub fn from_args<A: Into<OsString> + Clone>(args: impl IntoIterator<Item = A>) -> Self {
        clap::Parser::parse_from(args)
    }
}
