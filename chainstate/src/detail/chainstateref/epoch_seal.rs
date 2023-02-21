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
use chainstate_types::{BlockIndex, EpochData};
use common::{chain::ChainConfig, primitives::BlockHeight};
use pos_accounting::{FlushablePoSAccountingView, PoSAccountingDB};
use utils::tap_error_log::LogError;

use crate::BlockError;

/// Indicates whether a block was connected or disconnected.
/// Stores current tip height.
pub enum BlockStateEvent {
    Connect(BlockHeight),
    Disconnect(BlockHeight),
}

/// Every time a block is connected or disconnected, it should be checked if the epoch seal
/// should be updated.
/// Sealed epoch is the state of accounting that is `epoch_length` * `sealed_epoch_distance_from_tip` blocks
/// behind the tip and is used for PoS calculations.
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

/// If a block was connected and it was the last block of the epoch, the epoch seal must be advanced.
/// Meaning merging all the data from the epoch after current sealed state.
fn advance_epoch_seal<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    chain_config: &ChainConfig,
    tip_height: BlockHeight,
) -> Result<(), BlockError> {
    let current_epoch_index = chain_config.epoch_index_from_height(&tip_height);
    let epoch_index_to_seal = current_epoch_index
        .checked_sub(chain_config.sealed_epoch_distance_from_tip() as u64)
        .expect("always >= 0; because the epoch to seal cannot be higher than the current epoch");

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

/// If a block was disconnected and it was the last block of the epoch, the epoch seal must be rolled back.
/// Meaning undo merging of all the data from the last sealed epoch.
fn rollback_epoch_seal<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    chain_config: &ChainConfig,
    tip_height: BlockHeight,
) -> Result<(), BlockError> {
    let current_epoch_index = chain_config.epoch_index_from_height(&tip_height);
    let epoch_index_to_unseal = current_epoch_index
        .checked_sub(chain_config.sealed_epoch_distance_from_tip() as u64)
        .expect("always >= 0; because the epoch to unseal cannot be higher than the current epoch");

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

/// Indicates whether a block was connected or disconnected.
/// Stores current tip height and index if necessary.
pub enum BlockStateEventWithIndex<'a> {
    Connect(BlockHeight, &'a BlockIndex),
    Disconnect(BlockHeight),
}

/// Every epoch has data associated with it.
/// On every block change check whether this data should be updated.
pub fn update_epoch_data<S: BlockchainStorageWrite>(
    db_tx: &mut S,
    chain_config: &ChainConfig,
    block_op: BlockStateEventWithIndex<'_>,
) -> Result<(), BlockError> {
    match block_op {
        BlockStateEventWithIndex::Connect(tip_height, block_index) => {
            if chain_config.is_last_block_in_epoch(&tip_height) {
                // Consider the randomness of the last block to be the randomness of the epoch
                if let Some(epoch_randomness) = block_index.preconnect_data().pos_randomness() {
                    db_tx
                        .set_epoch_data(
                            chain_config.epoch_index_from_height(&tip_height),
                            &EpochData::new(epoch_randomness.clone()),
                        )
                        .log_err()?;
                }
            }
        }
        BlockStateEventWithIndex::Disconnect(tip_height) => {
            if chain_config.is_last_block_in_epoch(&tip_height) {
                // If current tip is the last block of the epoch
                // it means that the first block of next epoch was just disconnected
                // and the epoch data for the next epoch should be deleted
                let disconnected_tip = tip_height.next_height();
                db_tx
                    .del_epoch_data(chain_config.epoch_index_from_height(&disconnected_tip))
                    .log_err()?;
            }
        }
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use super::*;
    use chainstate_storage::mock::MockStoreTxRw;
    use chainstate_types::{
        pos_randomness::PoSRandomness, BlockPreconnectData, ConsensusExtraData,
    };
    use common::{
        chain::{block::timestamp::BlockTimestamp, config::Builder as ConfigBuilder, Block},
        primitives::H256,
        uint::BitArray,
        Uint256,
    };
    use mockall::predicate::eq;
    use rstest::rstest;

    fn make_block_index(height: BlockHeight) -> BlockIndex {
        let block = Block::new_with_no_consensus(
            vec![],
            H256::zero().into(),
            BlockTimestamp::from_int_seconds(1),
        )
        .unwrap();
        BlockIndex::new(
            &block,
            Uint256::zero(),
            H256::zero().into(),
            height,
            BlockTimestamp::from_int_seconds(1),
            BlockPreconnectData::new(ConsensusExtraData::PoS(PoSRandomness::new(H256::zero()))),
        )
    }

    #[rstest]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(0), false)]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(1), false)]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(2), true)]
    fn test_update_epoch_data_connect(
        #[case] epoch_length: NonZeroU64,
        #[case] tip_height: BlockHeight,
        #[case] expect_call_to_db: bool,
    ) {
        let mut db = MockStoreTxRw::new();
        let chain_config = ConfigBuilder::test_chain().epoch_length(epoch_length).build();
        let block_index = make_block_index(tip_height);
        let expected_modified_epoch = chain_config.epoch_index_from_height(&tip_height);

        if expect_call_to_db {
            db.expect_set_epoch_data()
                .times(1)
                .withf(move |epoch_index, _| *epoch_index == expected_modified_epoch)
                .return_const(Ok(()));
        }

        update_epoch_data(
            &mut db,
            &chain_config,
            BlockStateEventWithIndex::Connect(tip_height, &block_index),
        )
        .unwrap();
    }

    #[rstest]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(0), false)]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(1), false)]
    #[case(NonZeroU64::new(3).unwrap(), BlockHeight::from(2), true)]
    fn test_update_epoch_data_disconnect(
        #[case] epoch_length: NonZeroU64,
        #[case] tip_height: BlockHeight,
        #[case] expect_call_to_db: bool,
    ) {
        let mut db = MockStoreTxRw::new();
        let chain_config = ConfigBuilder::test_chain().epoch_length(epoch_length).build();
        let expected_modified_epoch =
            chain_config.epoch_index_from_height(&tip_height.next_height());

        if expect_call_to_db {
            db.expect_del_epoch_data()
                .times(1)
                .with(eq(expected_modified_epoch))
                .return_const(Ok(()));
        }

        update_epoch_data(
            &mut db,
            &chain_config,
            BlockStateEventWithIndex::Disconnect(tip_height),
        )
        .unwrap();
    }

    #[rstest]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(0), false)]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(1), true)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(0), false)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(1), false)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(2), false)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(3), true)]
    fn test_update_epoch_seal_connect(
        #[case] epoch_length: NonZeroU64,
        #[case] stride: usize,
        #[case] tip_height: BlockHeight,
        #[case] expect_call_to_db: bool,
    ) {
        let mut db = MockStoreTxRw::new();
        let chain_config = ConfigBuilder::test_chain()
            .epoch_length(epoch_length)
            .sealed_epoch_distance_from_tip(stride)
            .build();

        if expect_call_to_db {
            db.expect_get_accounting_epoch_delta()
                .times(1)
                .return_const(Ok(Some(pos_accounting::PoSAccountingDeltaData::new())));
            db.expect_set_accounting_epoch_undo_delta().times(1).return_const(Ok(()));
        }

        update_epoch_seal(&mut db, &chain_config, BlockStateEvent::Connect(tip_height)).unwrap();
    }

    #[rstest]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(0), true)]
    #[case(NonZeroU64::new(2).unwrap(), 0, BlockHeight::from(1), false)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(0), false)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(1), false)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(2), true)]
    #[case(NonZeroU64::new(2).unwrap(), 1, BlockHeight::from(3), false)]
    fn test_update_epoch_seal_disconnect(
        #[case] epoch_length: NonZeroU64,
        #[case] stride: usize,
        #[case] tip_height: BlockHeight,
        #[case] expect_call_to_db: bool,
    ) {
        let mut db = MockStoreTxRw::new();
        let chain_config = ConfigBuilder::test_chain()
            .epoch_length(epoch_length)
            .sealed_epoch_distance_from_tip(stride)
            .build();

        if expect_call_to_db {
            db.expect_get_accounting_epoch_undo_delta()
                .times(1)
                .return_const(Ok(Some(pos_accounting::DeltaMergeUndo::new())));
            db.expect_del_accounting_epoch_undo_delta().times(1).return_const(Ok(()));
        }

        update_epoch_seal(
            &mut db,
            &chain_config,
            BlockStateEvent::Disconnect(tip_height),
        )
        .unwrap();
    }
}
