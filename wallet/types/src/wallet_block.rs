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

use common::{
    chain::{Block, TxInput, TxOutput},
    primitives::{BlockHeight, Id},
};

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct WalletBlock {
    block_id: Id<Block>,

    height: BlockHeight,

    kernel_inputs: Vec<TxInput>,

    reward: Vec<TxOutput>,
}

impl WalletBlock {
    pub fn new(
        block_id: Id<Block>,
        height: BlockHeight,
        kernel_inputs: Vec<TxInput>,
        reward: Vec<TxOutput>,
    ) -> Self {
        WalletBlock {
            block_id,
            height,
            kernel_inputs,
            reward,
        }
    }

    pub fn height(&self) -> BlockHeight {
        self.height
    }

    pub fn kernel_inputs(&self) -> &[TxInput] {
        &self.kernel_inputs
    }

    pub fn reward(&self) -> &[TxOutput] {
        &self.reward
    }
}
