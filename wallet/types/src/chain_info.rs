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

use common::{
    chain::{config::MagicBytes, ChainConfig, GenBlock},
    primitives::Id,
};
use serialization::{Decode, Encode};

#[derive(Clone, Encode, Decode, Debug)]
pub struct ChainInfo {
    chain_type: String,
    genesis_block_id: Id<GenBlock>,
    magic_bytes: MagicBytes,
}

impl ChainInfo {
    pub fn new(config: &ChainConfig) -> Self {
        Self {
            chain_type: config.chain_type().name().to_string(),
            genesis_block_id: config.genesis_block_id(),
            magic_bytes: *config.magic_bytes(),
        }
    }

    pub fn chain_type(&self) -> &String {
        &self.chain_type
    }

    pub fn genesis_block_id(&self) -> Id<GenBlock> {
        self.genesis_block_id
    }

    pub fn magic_bytes(&self) -> MagicBytes {
        self.magic_bytes
    }

    pub fn is_same(&self, chain_config: &ChainConfig) -> bool {
        self.chain_type() == chain_config.chain_type().name()
            && self.genesis_block_id() == chain_config.genesis_block_id()
            && self.magic_bytes() == *chain_config.magic_bytes()
    }
}
