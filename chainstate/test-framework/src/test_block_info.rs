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

use crate::TestChainstate;
use chainstate::chainstate_interface::ChainstateInterface;
use common::{
    chain::{gen_block::GenBlockId, Block, GenBlock, Genesis, OutPointSourceId, TxOutput},
    primitives::{Id, Idable},
};

// TODO: Replace by a proper UTXO set abstraction
// (https://github.com/mintlayer/mintlayer-core/issues/312).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestBlockInfo {
    pub txns: Vec<(OutPointSourceId, Vec<TxOutput>)>,
    pub id: Id<GenBlock>,
}

impl TestBlockInfo {
    pub fn from_block(blk: &Block) -> Self {
        let txns = blk
            .transactions()
            .iter()
            .map(|tx| {
                (
                    OutPointSourceId::Transaction(tx.transaction().get_id()),
                    tx.transaction().outputs().clone(),
                )
            })
            .collect();
        let id = blk.get_id().into();
        Self { txns, id }
    }

    pub fn from_genesis(genesis: &Genesis) -> Self {
        let id: Id<GenBlock> = genesis.get_id().into();
        let outsrc = OutPointSourceId::BlockReward(id);
        let txns = vec![(outsrc, genesis.utxos().to_vec())];
        Self { txns, id }
    }

    pub fn from_id(cs: &TestChainstate, id: Id<GenBlock>) -> Self {
        match id.classify(&cs.get_chain_config()) {
            GenBlockId::Genesis(_) => Self::from_genesis(cs.get_chain_config().genesis_block()),
            GenBlockId::Block(id) => {
                let block = cs.get_block(id).unwrap().unwrap();
                Self::from_block(&block)
            }
        }
    }
}
