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

use std::collections::{BTreeMap, BTreeSet};

use common::chain::OutPoint;
use wallet_types::{
    account_id::AccountBlockHeight, wallet_block::WalletBlock, AccountTxId, WalletTx,
};

pub struct TxoCache {
    blocks: BTreeMap<AccountBlockHeight, WalletBlock>,
    txs: BTreeMap<AccountTxId, WalletTx>,
    outpoints: BTreeSet<OutPoint>,
}

impl TxoCache {
    pub fn empty() -> Self {
        Self {
            blocks: BTreeMap::new(),
            txs: BTreeMap::new(),
            outpoints: BTreeSet::new(),
        }
    }

    pub fn new(
        blocks: BTreeMap<AccountBlockHeight, WalletBlock>,
        txs: BTreeMap<AccountTxId, WalletTx>,
    ) -> Self {
        let mut cache = Self::empty();
        for (block_height, block) in blocks {
            cache.add_block(block_height, block);
        }
        for (tx_id, tx) in txs {
            cache.add_tx(tx_id, tx);
        }
        cache
    }

    pub fn blocks(&self) -> &BTreeMap<AccountBlockHeight, WalletBlock> {
        &self.blocks
    }

    pub fn txs(&self) -> &BTreeMap<AccountTxId, WalletTx> {
        &self.txs
    }

    pub fn outpoints(&self) -> &BTreeSet<OutPoint> {
        &self.outpoints
    }

    pub fn add_block(&mut self, block_height: AccountBlockHeight, block: WalletBlock) {
        for outpoint in block.outpoints() {
            self.outpoints.insert(outpoint);
        }
        self.blocks.insert(block_height, block);
    }

    pub fn add_tx(&mut self, tx_id: AccountTxId, tx: WalletTx) {
        for outpoint in tx.outpoints() {
            self.outpoints.insert(outpoint);
        }
        self.txs.insert(tx_id, tx);
    }

    pub fn remove_block(&mut self, block_height: &AccountBlockHeight) {
        let block_opt = self.blocks.remove(block_height);
        if let Some(block) = block_opt {
            for outpoint in block.outpoints() {
                self.outpoints.remove(&outpoint);
            }
        }
    }

    pub fn remove_tx(&mut self, tx_id: &AccountTxId) {
        let tx_opt = self.txs.remove(tx_id);
        if let Some(tx) = tx_opt {
            for outpoint in tx.outpoints() {
                self.outpoints.remove(&outpoint);
            }
        }
    }
}
