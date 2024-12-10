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

use common::chain::UtxoOutPoint;
use utxo::{Utxo, UtxosView};

use super::TxPool;

#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum Error<P> {
    #[error("Transaction output index out of range")]
    OutputOutOfRange,
    #[error(transparent)]
    ParentError(#[from] P),
}

/// Utxo view sourcing UTXOs from chainstate and mempool
///
/// This sources the UTXOs from mempool and chainstate if not available in mempool. All mempool
/// UTXOs are considered available, double spending is not checked by this view. This is useful for
/// checking transactions that connect anywhere, not just the unspent boundary of mempool. That may
/// be used to check RBF transactions without having to disconnect conflicting transactions or to
/// check transactions to be included in the next block for time locks.
/// However, it also means double spending has to be checked separately.
pub struct MempoolUtxoView<'m, M, P> {
    mempool: &'m TxPool<M>,
    parent: P,
}

impl<'m, M, P> MempoolUtxoView<'m, M, P> {
    pub fn new(mempool: &'m TxPool<M>, parent: P) -> Self {
        Self { mempool, parent }
    }
}

impl<M, P: UtxosView> UtxosView for MempoolUtxoView<'_, M, P> {
    type Error = Error<P::Error>;

    fn utxo(&self, outpoint: &UtxoOutPoint) -> Result<Option<Utxo>, Self::Error> {
        let tx_id = match outpoint.source_id().get_tx_id() {
            Some(tx_id) => *tx_id,
            None => return Ok(self.parent.utxo(outpoint)?),
        };

        self.mempool.store.txs_by_id.get(&tx_id).map_or_else(
            || Ok(self.parent.utxo(outpoint)?),
            |tx_entry| {
                let tx = tx_entry.transaction();
                let output = tx
                    .outputs()
                    .get(outpoint.output_index() as usize)
                    .ok_or(Error::OutputOutOfRange)?;
                Ok(Some(Utxo::new_for_mempool(output.clone())))
            },
        )
    }

    fn has_utxo(&self, outpoint: &UtxoOutPoint) -> Result<bool, Self::Error> {
        // TODO: A more efficient implementation is possible here
        self.utxo(outpoint).map(|u| u.is_some())
    }

    fn best_block_hash(
        &self,
    ) -> Result<common::primitives::Id<common::chain::GenBlock>, Self::Error> {
        Ok(self.mempool.best_block_id())
    }

    fn estimated_size(&self) -> Option<usize> {
        None
    }
}
