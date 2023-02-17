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

use serialization::{Decode, Encode};

use crate::pos_randomness::PoSRandomness;

/// ConsensusExtraData contains any data that can be derived from consensus and has to be separately persisted
#[derive(Debug, Encode, Decode, Clone)]
pub enum ConsensusExtraData {
    None,
    PoS(PoSRandomness),
}

/// BlockPreconnectData is data that we can extract from a block before having to connect it (before it being part of mainchain)
/// This can be important to avoid having to collect data during a specific block height; like for accumulated randomness, for example
#[derive(Debug, Encode, Decode, Clone)]
pub struct BlockPreconnectData {
    consensus_extra: ConsensusExtraData,
}

impl BlockPreconnectData {
    pub fn new(consensus_extra: ConsensusExtraData) -> Self {
        Self { consensus_extra }
    }

    pub fn consensus_extra_data(&self) -> &ConsensusExtraData {
        &self.consensus_extra
    }

    pub fn pos_randomness(&self) -> Option<&PoSRandomness> {
        match &self.consensus_extra {
            ConsensusExtraData::None => None,
            ConsensusExtraData::PoS(randomness) => Some(randomness),
        }
    }
}
