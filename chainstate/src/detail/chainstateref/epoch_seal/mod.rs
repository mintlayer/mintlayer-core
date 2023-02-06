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

use chainstate_storage::{BlockchainStorageWrite, SealedStorageTag};
use common::{
    chain::{ChainConfig, GenBlockId},
    primitives::BlockHeight,
};
use pos_accounting::{FlushablePoSAccountingView, PoSAccountingDB, PoSAccountingDeltaData};
use utils::tap_error_log::LogError;

use crate::BlockError;

mod epoch_seal_op;
use epoch_seal_op::EpochSealOp;

pub fn activate_epoch_seal<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    chain_config: &ChainConfig,
    tip_height: BlockHeight,
) -> Result<(), BlockError> {
    let sealed_epoch_height = db_tx.get_sealed_epoch_height()?;
    let epoch_seal_op = EpochSealOp::new(chain_config, sealed_epoch_height, tip_height);
    match epoch_seal_op {
        EpochSealOp::Seal => advance_epoch_seal(db_tx, chain_config, tip_height),
        EpochSealOp::Unseal => rollback_epoch_seal(db_tx, chain_config, tip_height),
        EpochSealOp::None => Ok(()),
    }
}

fn advance_epoch_seal<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    chain_config: &ChainConfig,
    tip_height: BlockHeight,
) -> Result<(), BlockError> {
    let current_epoch_index = chain_config.epoch_index_from_height(&tip_height);
    let epoch_index_to_seal =
        current_epoch_index - chain_config.sealed_epoch_distance_from_tip() as u64;
    let epoch_length = chain_config.epoch_length().get();
    let first_block_epoch_to_seal = epoch_index_to_seal * epoch_length;
    let end_block_epoch_to_seal = first_block_epoch_to_seal + epoch_length;

    // iterate over every block in the epoch and merge every block delta into a singe delta
    let epoch_delta = (first_block_epoch_to_seal..end_block_epoch_to_seal)
        .try_fold(
            None,
            |delta: Option<PoSAccountingDeltaData>, height| -> Result<_, BlockError> {
                let genblock_id = db_tx
                    .get_block_id_by_height(&BlockHeight::new(height))?
                    .ok_or_else(|| BlockError::BlockAtHeightNotFound(BlockHeight::new(height)))?;
                match genblock_id.classify(chain_config) {
                    GenBlockId::Genesis(_) => (), /* skip genesis block for now */
                    GenBlockId::Block(block_id) => {
                        if let Some(block_delta) = db_tx.get_accounting_delta(block_id)? {
                            let mut delta = delta.unwrap_or_default();
                            delta.merge_with_delta(block_delta)?;
                            return Ok(Some(delta));
                        }
                    }
                };
                // TODO: delete block deltas?
                Ok(delta)
            },
        )
        .log_err()?;

    // it is possible that an epoch doesn't have any accounting data so no delta is stored in that case
    if let Some(epoch_delta) = epoch_delta {
        // apply delta to sealed storage
        let mut db = PoSAccountingDB::<_, SealedStorageTag>::new(&mut *db_tx);
        let epoch_undo = db.batch_write_delta(epoch_delta).map_err(BlockError::from).log_err()?;

        // store undo delta for sealed epoch
        db_tx
            .set_accounting_epoch_undo_delta(epoch_index_to_seal, &epoch_undo)
            .log_err()?;
    }

    // update sealed epoch height anyway
    db_tx
        .set_sealed_epoch_height((epoch_index_to_seal * epoch_length).into())
        .log_err()?;

    Ok(())
}

fn rollback_epoch_seal<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    chain_config: &ChainConfig,
    tip_height: BlockHeight,
) -> Result<(), BlockError> {
    let current_epoch_index = chain_config.epoch_index_from_height(&tip_height.next_height());
    let epoch_index_to_unseal = current_epoch_index
        .checked_sub(chain_config.sealed_epoch_distance_from_tip() as u64)
        .expect("always positive");

    let epoch_undo = db_tx
        .get_accounting_epoch_undo_delta(epoch_index_to_unseal)
        .map_err(BlockError::from)
        .log_err()?;

    // if no undo found just skip
    if let Some(epoch_undo) = epoch_undo {
        let mut db = PoSAccountingDB::<_, SealedStorageTag>::new(&mut *db_tx);
        db.undo_merge_with_delta(epoch_undo)?;

        db_tx.del_accounting_epoch_undo_delta(epoch_index_to_unseal)?;
    }

    // update sealed epoch height anyway
    let sealed_epoch_height = epoch_index_to_unseal * chain_config.epoch_length().get();
    db_tx.set_sealed_epoch_height(sealed_epoch_height.into()).log_err()?;

    Ok(())
}
