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
    chain::{
        block::ConsensusData, Block, GenBlock, Genesis, OutPoint, OutPointSourceId, TxInput,
        TxOutput,
    },
    primitives::{BlockHeight, Id, Idable},
};

#[derive(Debug, PartialEq, Eq, Clone, Decode, Encode)]
pub struct WalletBlock {
    // `GenBlock` because this may be the genesis block (kernel_inputs will be empty in this case)
    block_id: Id<GenBlock>,

    height: BlockHeight,

    kernel_inputs: Vec<TxInput>,

    reward: Vec<TxOutput>,
}

impl WalletBlock {
    pub fn from_genesis(genesis: &Genesis) -> Self {
        WalletBlock {
            block_id: genesis.get_id().into(),
            height: BlockHeight::zero(),
            kernel_inputs: Vec::new(),
            reward: genesis.utxos().to_vec(),
        }
    }

    pub fn from_block(block: &Block, block_height: BlockHeight) -> Self {
        let kernel_inputs = match block.header().consensus_data() {
            ConsensusData::PoS(pos) => pos.kernel_inputs().to_vec(),
            ConsensusData::PoW(_) | ConsensusData::None => Vec::new(),
        };

        WalletBlock {
            block_id: block.get_id().into(),
            height: block_height,
            kernel_inputs,
            reward: block.block_reward().outputs().to_vec(),
        }
    }

    pub fn block_id(&self) -> &Id<GenBlock> {
        &self.block_id
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

    pub fn outpoints(&self) -> impl Iterator<Item = OutPoint> + '_ {
        self.reward.iter().enumerate().map(|(index, _output)| {
            OutPoint::new(OutPointSourceId::BlockReward(self.block_id), index as u32)
        })
    }
}
