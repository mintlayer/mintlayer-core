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
    chain::{Block, Transaction},
    primitives::{BlockHeight, Id},
};

use crate::{
    error::{Error, MempoolBanScore},
    TxOrigin,
};

/// Event triggered when an orphan has been fully validated
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OrphanProcessed {
    tx_id: Id<Transaction>,
    origin: TxOrigin,
    result: crate::Result<()>,
}

impl OrphanProcessed {
    fn new(tx_id: Id<Transaction>, origin: TxOrigin, result: crate::Result<()>) -> Self {
        Self {
            tx_id,
            origin,
            result,
        }
    }

    pub fn accepted(tx_id: Id<Transaction>, origin: TxOrigin) -> Self {
        Self::new(tx_id, origin, Ok(()))
    }

    pub fn rejected(tx_id: Id<Transaction>, err: Error, origin: TxOrigin) -> Self {
        Self::new(tx_id, origin, Err(err))
    }

    pub fn result(&self) -> &crate::Result<()> {
        &self.result
    }

    pub fn was_accepted(&self) -> bool {
        self.result.is_ok()
    }

    pub fn ban_score(&self) -> u32 {
        self.result.as_ref().map_or_else(|err| err.mempool_ban_score(), |_| 0)
    }

    pub fn tx_id(&self) -> &Id<Transaction> {
        &self.tx_id
    }

    pub fn origin(&self) -> TxOrigin {
        self.origin
    }
}

/// Event triggered when mempool has synced up to given tip
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NewTip {
    block_id: Id<Block>,
    height: BlockHeight,
}

impl NewTip {
    pub fn new(block_id: Id<Block>, height: BlockHeight) -> Self {
        Self { block_id, height }
    }

    pub fn block_id(&self) -> &Id<Block> {
        &self.block_id
    }

    pub fn block_height(&self) -> BlockHeight {
        self.height
    }
}

/// Events emitted by mempool
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MempoolEvent {
    NewTip(NewTip),
    OrphanProcessed(OrphanProcessed),
}

impl From<OrphanProcessed> for MempoolEvent {
    fn from(event: OrphanProcessed) -> Self {
        Self::OrphanProcessed(event)
    }
}

impl From<NewTip> for MempoolEvent {
    fn from(event: NewTip) -> Self {
        Self::NewTip(event)
    }
}
