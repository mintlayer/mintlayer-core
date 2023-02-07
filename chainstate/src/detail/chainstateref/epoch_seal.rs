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

use chainstate_storage::{BlockchainStorageWrite, SealedStorageTag};
use common::{chain::ChainConfig, primitives::BlockHeight};
use pos_accounting::{FlushablePoSAccountingView, PoSAccountingDB};
use utils::tap_error_log::LogError;

use crate::BlockError;

pub enum BlockStateEvent {
    Connect(BlockHeight),
    Disconnect(BlockHeight),
}

pub fn update_epoch_seal<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    chain_config: &ChainConfig,
    block_op: BlockStateEvent,
) -> Result<(), BlockError> {
    match block_op {
        BlockStateEvent::Connect(tip_height) => {
            if chain_config.is_due_for_epoch_seal(&tip_height) {
                advance_epoch_seal(db_tx, chain_config, tip_height)?;
            }
        }
        BlockStateEvent::Disconnect(tip_height) => {
            let disconnected_tip = tip_height.next_height();
            if chain_config.is_due_for_epoch_seal(&disconnected_tip) {
                rollback_epoch_seal(db_tx, chain_config, disconnected_tip)?;
            }
        }
    };
    Ok(())
}

fn advance_epoch_seal<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    chain_config: &ChainConfig,
    tip_height: BlockHeight,
) -> Result<(), BlockError> {
    let current_epoch_index = chain_config.epoch_index_from_height(&tip_height);
    let epoch_index_to_seal =
        current_epoch_index - chain_config.sealed_epoch_distance_from_tip() as u64;

    // retrieve delta for the epoch to seal
    let epoch_delta = db_tx.get_accounting_epoch_delta(epoch_index_to_seal).log_err()?;

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

    Ok(())
}

fn rollback_epoch_seal<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    chain_config: &ChainConfig,
    tip_height: BlockHeight,
) -> Result<(), BlockError> {
    let current_epoch_index = chain_config.epoch_index_from_height(&tip_height);
    let epoch_index_to_unseal = current_epoch_index
        .checked_sub(chain_config.sealed_epoch_distance_from_tip() as u64)
        .expect("always positive");

    // retrieve delta undo for the epoch to unseal
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

    Ok(())
}
