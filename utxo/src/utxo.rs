// Copyright (c) 2022 RBB S.r.l
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

use crate::Error;
use common::{chain::TxOutput, primitives::BlockHeight};
use serialization::{Decode, Encode};
use std::fmt::Debug;

/// Determines whether the utxo is for the blockchain of for mempool
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub enum UtxoSource {
    /// At which height this containing tx was included in the active block chain
    Blockchain(BlockHeight),
    Mempool,
}

impl UtxoSource {
    pub fn is_mempool(&self) -> bool {
        match self {
            UtxoSource::Blockchain(_) => false,
            UtxoSource::Mempool => true,
        }
    }

    pub fn blockchain_height(&self) -> Result<BlockHeight, Error> {
        match self {
            UtxoSource::Blockchain(h) => Ok(*h),
            UtxoSource::Mempool => Err(crate::Error::NoBlockchainHeightFound),
        }
    }
}

/// The Unspent Transaction Output
#[derive(Debug, Clone, Eq, PartialEq, Encode, Decode)]
pub struct Utxo {
    output: TxOutput,
    is_block_reward: bool,
    /// identifies whether the utxo is for the blockchain or for mempool.
    source: UtxoSource,
}

impl Utxo {
    pub fn new(output: TxOutput, is_block_reward: bool, source: UtxoSource) -> Self {
        Self {
            output,
            is_block_reward,
            source,
        }
    }

    pub fn new_for_blockchain(
        output: TxOutput,
        is_block_reward: bool,
        height: BlockHeight,
    ) -> Self {
        Self {
            output,
            is_block_reward,
            source: UtxoSource::Blockchain(height),
        }
    }

    pub fn new_for_mempool(output: TxOutput, is_block_reward: bool) -> Self {
        Self {
            output,
            is_block_reward,
            source: UtxoSource::Mempool,
        }
    }

    pub fn is_block_reward(&self) -> bool {
        self.is_block_reward
    }

    pub fn source(&self) -> &UtxoSource {
        &self.source
    }

    pub fn output(&self) -> &TxOutput {
        &self.output
    }

    pub fn set_height(&mut self, value: UtxoSource) {
        self.source = value
    }
}
