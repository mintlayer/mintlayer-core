// Copyright (c) 2024 RBB S.r.l
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
    chain::GenBlock,
    primitives::{BlockHeight, Id},
};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CreatedBlockInfo {
    pub id: Id<GenBlock>,
    pub height: BlockHeight,
    pub pool_id: String,
}

impl rpc_description::HasValueHint for CreatedBlockInfo {
    const HINT: rpc_description::ValueHint = rpc_description::ValueHint::Object(&[
        ("id", &<Id<GenBlock>>::HINT),
        ("height", &BlockHeight::HINT),
        ("pool_id", &rpc_description::ValueHint::BECH32_STRING),
    ]);
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BlockInfo {
    pub id: Id<GenBlock>,
    pub height: BlockHeight,
}

impl BlockInfo {
    pub fn from_tuple((id, height): (Id<GenBlock>, BlockHeight)) -> Self {
        Self { id, height }
    }
}

impl rpc_description::HasValueHint for BlockInfo {
    const HINT: rpc_description::ValueHint = rpc_description::ValueHint::Object(&[
        ("id", &<Id<GenBlock>>::HINT),
        ("height", &BlockHeight::HINT),
    ]);
}
