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

use serde::{Deserialize, Serialize};

use common::{chain::config::ChainType, primitives::semver::SemVer};

/// The p2p subsystem configuration.
#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// Address to bind P2P to.
    pub address: String,
    pub version: SemVer,
    pub magic_bytes: [u8; 4],
}

impl Config {
    /// Creates a new p2p configuration instance.
    pub fn new(net: ChainType) -> Self {
        Self {
            address: "/ip6/::1/tcp/3031".into(),
            version: SemVer::new(0, 1, 0),
            magic_bytes: net.default_magic_bytes(),
        }
    }

    /// Returns magic bytes as little endian `u32`.
    pub fn magic_bytes_as_u32(&self) -> u32 {
        u32::from_le_bytes(self.magic_bytes)
    }
}
