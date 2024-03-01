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

use chainstate_storage::BlockchainStorageRead;
use chainstate_types::{ConsumedEpochDataCache, EpochDataCache, GenBlockIndex, PropertyQueryError};
use common::{
    chain::{block::BlockHeader, Block, GenBlock, GenBlockId},
    primitives::{id::WithId, Id},
};
use tx_verifier::{
    flush_to_storage, transaction_verifier::TransactionVerifierDelta, TransactionVerifier,
};
use utils::{log_error, tap_error_log::TapLog};

use crate::{calculate_median_time_past, CheckBlockError, TransactionVerificationStrategy};

use super::{epoch_seal, ChainstateRef};

impl<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy> ChainstateRef<'a, S, V> {
    // Disconnect all blocks from the mainchain up until common ancestor of provided block
    // and then connect all block in the new branch.
    // All these operations are performed via `TransactionVerifier` without db modifications
    // and the resulting delta is returned.
    #[log_error]
    pub fn reorganize_in_memory(
        &self,
        new_block_header: &BlockHeader,
        best_block_id: Id<GenBlock>,
    ) -> Result<(TransactionVerifierDelta, ConsumedEpochDataCache), CheckBlockError> {
        let prev_block_id = new_block_header.prev_block_id();
        let new_chain = match self
            .get_gen_block_index(prev_block_id)
            .log_err()?
            .ok_or(PropertyQueryError::PrevBlockIndexNotFound(*prev_block_id))?
        {
            GenBlockIndex::Block(block_index) => self.get_new_chain(&block_index).log_err()?,
            GenBlockIndex::Genesis(_) => Vec::new(),
        };

        let common_ancestor_id = match new_chain.first() {
            Some(block_index) => block_index.prev_block_id(),
            None => prev_block_id,
        };

        let mut tx_verifier = TransactionVerifier::new(self, self.chain_config);

        // during reorg epoch seal can change so it needs to be tracked as well
        let mut epoch_data_cache = EpochDataCache::new(&self.db_tx);

        // Disconnect the current chain if it is not a genesis
        if let GenBlockId::Block(best_block_id) = best_block_id.classify(self.chain_config) {
            let mainchain_tip = self
                .get_block_index(&best_block_id)
                .map_err(|_| CheckBlockError::BlockNotFound(best_block_id.into()))
                .log_err()?
                .expect("Can't get block index. Inconsistent DB");

            let mut to_disconnect = GenBlockIndex::Block(mainchain_tip);
            while to_disconnect.block_id() != *common_ancestor_id {
                let to_disconnect_block = match to_disconnect {
                    GenBlockIndex::Genesis(_) => panic!("Attempt to disconnect genesis"),
                    GenBlockIndex::Block(block_index) => block_index,
                };

                let block = self
                    .get_block_from_index(&to_disconnect_block)
                    .log_err()?
                    .expect("Inconsistent DB");

                // Disconnect transactions
                let cached_inputs = self
                    .tx_verification_strategy
                    .disconnect_block(
                        TransactionVerifier::new,
                        &tx_verifier,
                        self.chain_config,
                        &block.into(),
                    )?
                    .consume()?;

                flush_to_storage(&mut tx_verifier, cached_inputs)?;

                to_disconnect = self
                    .get_previous_block_index(&to_disconnect_block)
                    .expect("Previous block index retrieval failed");

                epoch_seal::update_epoch_data(
                    &mut epoch_data_cache,
                    &tx_verifier,
                    self.chain_config,
                    epoch_seal::BlockStateEventWithIndex::Disconnect(to_disconnect.block_height()),
                )?;
            }
        }

        // Connect the new chain
        for new_tip_block_index in new_chain {
            let new_tip: WithId<Block> = self
                .get_block_from_index(&new_tip_block_index)
                .log_err()?
                .ok_or(CheckBlockError::BlockNotFound(
                    (*new_tip_block_index.block_id()).into(),
                ))?
                .into();

            // The comparison for timelock is done with median_time_past based on BIP-113, i.e., the median time instead of the block timestamp
            let median_time_past = calculate_median_time_past(self, &new_tip.prev_block_id());

            let connected_txs = self
                .tx_verification_strategy
                .connect_block(
                    TransactionVerifier::new,
                    &tx_verifier,
                    self.chain_config,
                    &new_tip_block_index,
                    &new_tip,
                    median_time_past,
                )
                .log_err()?
                .consume()?;

            flush_to_storage(&mut tx_verifier, connected_txs)?;

            epoch_seal::update_epoch_data(
                &mut epoch_data_cache,
                &tx_verifier,
                self.chain_config,
                epoch_seal::BlockStateEventWithIndex::Connect(
                    new_tip_block_index.block_height(),
                    &new_tip,
                ),
            )?;
        }

        let consumed_verifier = tx_verifier.consume()?;
        let consumed_epoch_data = epoch_data_cache.consume();
        Ok((consumed_verifier, consumed_epoch_data))
    }
}
