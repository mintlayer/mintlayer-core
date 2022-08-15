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

use super::block::{timestamp::BlockTimestamp, BlockRewardTransactable};
use super::TxOutput;
use crate::primitives::{id, Id, Idable};

use serialization::{Decode, Encode};

/// Genesis defines the initial state of the blockchain
#[derive(Eq, PartialEq, Clone, Encode, Decode, Debug)]
pub struct Genesis {
    /// Arbitrary message included in the genesis
    fun_message: String,
    /// Timestamp
    timestamp: BlockTimestamp,
    /// The initial UTXO set
    utxos: Vec<TxOutput>,
}

impl Genesis {
    pub fn new(fun_message: String, timestamp: BlockTimestamp, utxos: Vec<TxOutput>) -> Self {
        Self {
            fun_message,
            timestamp,
            utxos,
        }
    }

    pub fn utxos(&self) -> &[TxOutput] {
        &self.utxos
    }

    pub fn timestamp(&self) -> BlockTimestamp {
        self.timestamp
    }

    pub fn block_reward_transactable(&self) -> BlockRewardTransactable {
        BlockRewardTransactable {
            inputs: None,
            outputs: Some(self.utxos()),
        }
    }
}

impl Idable for Genesis {
    type Tag = Genesis;
    fn get_id(&self) -> Id<Self::Tag> {
        Id::new(id::hash_encoded(&self))
    }
}
