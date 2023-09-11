// Copyright (c) 2023 RBB S.r.l
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

use clap::Parser;
use std::{net::SocketAddr, ops::Deref};

const LISTEN_ADDRESS: &str = "127.0.0.1:3000";

#[derive(Debug, Parser)]
pub struct ApiServerWebServerConfig {
    /// The optional network address and port to listen on
    ///
    /// Format: `<ip>:<port>`
    ///
    /// Default: `127.0.0.1:3000`
    #[clap(long)]
    pub address: Option<ListenAddress>,
}

#[derive(Clone, Debug, Parser)]
pub struct ListenAddress {
    address: SocketAddr,
}

impl Default for ListenAddress {
    fn default() -> Self {
        Self {
            address: LISTEN_ADDRESS.to_string().parse().expect("Valid listining address"),
        }
    }
}

impl Deref for ListenAddress {
    type Target = SocketAddr;

    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl From<String> for ListenAddress {
    fn from(address: String) -> Self {
        Self {
            address: address.parse().expect("Valid listining address"),
        }
    }
}
