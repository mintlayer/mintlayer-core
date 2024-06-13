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

use serialization::{Decode, Encode};

use crate::{
    chain::{
        signature::{inputsig::InputWitness, Signable, Transactable},
        TxInput, TxOutput,
    },
    primitives::id::{self, H256},
};

/// Represents a block reward.
#[derive(Debug, Clone, PartialEq, Eq, Encode, Decode)]
pub struct BlockReward {
    reward_outputs: Vec<TxOutput>,
}

impl BlockReward {
    /// Constructs a new block reward instance with given outputs.
    pub fn new(reward_outputs: Vec<TxOutput>) -> Self {
        Self { reward_outputs }
    }

    /// Returns reward outputs.
    pub fn outputs(&self) -> &[TxOutput] {
        &self.reward_outputs
    }

    pub fn serialized_hash(&self) -> H256 {
        id::hash_encoded(self)
    }
}

pub struct BlockRewardTransactable<'a> {
    inputs: Option<&'a [TxInput]>,
    outputs: Option<&'a [TxOutput]>,
    witness: Option<&'a [InputWitness]>,
}

impl<'a> BlockRewardTransactable<'a> {
    pub fn new(
        inputs: Option<&'a [TxInput]>,
        outputs: Option<&'a [TxOutput]>,
        witness: Option<&'a [InputWitness]>,
    ) -> Self {
        Self {
            inputs,
            outputs,
            witness,
        }
    }

    pub fn witness(&self) -> Option<&[InputWitness]> {
        self.witness
    }
}

impl<'a> Signable for BlockRewardTransactable<'a> {
    fn inputs(&self) -> Option<&[TxInput]> {
        self.inputs
    }

    fn outputs(&self) -> Option<&[TxOutput]> {
        self.outputs
    }

    fn version_byte(&self) -> Option<u8> {
        None
    }

    fn flags(&self) -> Option<u128> {
        None
    }
}

impl<'a> Transactable for BlockRewardTransactable<'a> {
    fn signatures(&self) -> Vec<Option<InputWitness>> {
        self.witness.map_or(vec![], |w| w.iter().map(|s| Some(s.clone())).collect())
    }
}
