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
    chain::Block,
    primitives::{BlockHeight, Id},
};
use rpc::description::ValueHint as VH;

use crate::ChainstateEvent;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum RpcEvent {
    NewTip { id: Id<Block>, height: BlockHeight },
}

impl RpcEvent {
    pub fn from_event(event: ChainstateEvent) -> Self {
        match event {
            ChainstateEvent::NewTip(id, height) => Self::NewTip { id, height },
        }
    }
}

impl rpc::description::HasValueHint for RpcEvent {
    const HINT: VH = VH::Object(&[(
        "NewTip",
        &VH::Object(&[("id", &<Id<Block>>::HINT), ("height", &BlockHeight::HINT)]),
    )]);
}
