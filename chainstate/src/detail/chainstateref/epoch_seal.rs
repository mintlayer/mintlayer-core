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

use chainstate_storage::BlockchainStorageWrite;
use chainstate_types::{
    pos_randomness::{PoSRandomness, PoSRandomnessError},
    EpochData, EpochStorageRead, EpochStorageWrite, SealedStorageTag,
};
use common::{
    chain::{
        block::{consensus_data::PoSData, ConsensusData},
        Block, ChainConfig, PoolId, TxOutput,
    },
    primitives::BlockHeight,
};
use pos_accounting::{FlushablePoSAccountingView, PoSAccountingDB, PoSAccountingView};
use thiserror::Error;
use tx_verifier::transaction_verifier::error::SpendStakeError;
use utils::{log_error, tap_log::TapLog};

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
#[log_error]
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
#[log_error]
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
#[log_error]
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

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum EpochSealError {
    #[error("Block storage error: `{0}`")]
    StorageError(#[from] chainstate_storage::Error),
    #[error("PoS accounting error: {0}")]
    PoSAccountingError(#[from] pos_accounting::Error),
    #[error("Error during stake spending: {0}")]
    SpendStakeError(#[from] SpendStakeError),
    #[error("PoS randomness error: `{0}`")]
    RandomnessError(#[from] PoSRandomnessError),
    #[error("Data of pool {0} not found")]
    PoolDataNotFound(PoolId),
}

/// Indicates whether a block was connected or disconnected.
/// Stores current tip height and index if necessary.
pub enum BlockStateEventWithIndex<'a> {
    Connect(BlockHeight, &'a Block),
    Disconnect(BlockHeight),
}

#[log_error]
fn create_randomness_from_block<S, P>(
    epoch_data_cache: &S,
    pos_view: &P,
    chain_config: &ChainConfig,
    block: &Block,
    block_height: &BlockHeight,
    pos_data: &PoSData,
) -> Result<PoSRandomness, EpochSealError>
where
    S: EpochStorageRead,
    P: PoSAccountingView,
    EpochSealError: From<<P as PoSAccountingView>::Error>,
{
    let reward_output = block
        .block_reward()
        .outputs()
        .first()
        .ok_or(SpendStakeError::NoBlockRewardOutputs)?;

    let vrf_pub_key = match reward_output {
        TxOutput::Transfer(_, _)
        | TxOutput::LockThenTransfer(_, _, _)
        | TxOutput::Burn(_)
        | TxOutput::CreateDelegationId(_, _)
        | TxOutput::DelegateStaking(_, _)
        | TxOutput::IssueFungibleToken(_)
        | TxOutput::IssueNft(_, _, _)
        | TxOutput::DataDeposit(_)
        | TxOutput::Htlc(_, _)
        | TxOutput::CreateOrder(_) => {
            return Err(EpochSealError::SpendStakeError(
                SpendStakeError::InvalidBlockRewardOutputType,
            ));
        }
        TxOutput::CreateStakePool(_, d) => d.as_ref().vrf_public_key().clone(),
        TxOutput::ProduceBlockFromStake(_, pool_id) => {
            let pool_data = pos_view
                .get_pool_data(*pool_id)?
                .ok_or(EpochSealError::PoolDataNotFound(*pool_id))?;
            pool_data.vrf_public_key().clone()
        }
    };

    let sealed_epoch_randomness = chain_config
        .sealed_epoch_index(block_height)
        .map(|index| epoch_data_cache.get_epoch_data(index))
        .transpose()?
        .flatten()
        .map_or_else(
            || PoSRandomness::at_genesis(chain_config),
            |d| *d.randomness(),
        );

    let epoch_index = chain_config.epoch_index_from_height(block_height);
    PoSRandomness::from_block(
        epoch_index,
        block.header().timestamp(),
        &sealed_epoch_randomness,
        pos_data.vrf_data(),
        &vrf_pub_key,
    )
    .map_err(EpochSealError::RandomnessError)
}

/// Every epoch has data associated with it.
/// On every block change check whether this data should be updated.
#[log_error]
pub fn update_epoch_data<S, P>(
    epoch_data_cache: &mut S,
    pos_view: &P,
    chain_config: &ChainConfig,
    block_op: BlockStateEventWithIndex<'_>,
) -> Result<(), EpochSealError>
where
    S: EpochStorageWrite,
    P: PoSAccountingView,
    EpochSealError: From<<P as PoSAccountingView>::Error>,
{
    match block_op {
        BlockStateEventWithIndex::Connect(tip_height, tip) => {
            if chain_config.is_last_block_in_epoch(&tip_height) {
                match tip.header().consensus_data() {
                    ConsensusData::None | ConsensusData::PoW(_) => return Ok(()),
                    ConsensusData::PoS(pos_data) => {
                        // Consider the randomness of the last block to be the randomness of the epoch
                        let epoch_randomness = create_randomness_from_block(
                            epoch_data_cache,
                            pos_view,
                            chain_config,
                            tip,
                            &tip_height,
                            pos_data.as_ref(),
                        )?;

                        epoch_data_cache
                            .set_epoch_data(
                                chain_config.epoch_index_from_height(&tip_height),
                                &EpochData::new(epoch_randomness),
                            )
                            .log_err()?;
                    }
                };
            }
        }
        BlockStateEventWithIndex::Disconnect(tip_height) => {
            if chain_config.is_last_block_in_epoch(&tip_height) {
                // If current tip is the last block of the epoch
                // it means that the first block of next epoch was just disconnected
                // and the epoch data for the next epoch should be deleted
                let disconnected_tip = tip_height.next_height();
                epoch_data_cache
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
    use chainstate_types::{vrf_tools::construct_transcript, EpochDataCache, TipStorageTag};
    use common::{
        chain::{
            block::{consensus_data::PoSData, timestamp::BlockTimestamp, BlockReward},
            config::{Builder as ConfigBuilder, ChainType, EpochIndex},
            get_initial_randomness,
            stakelock::StakePoolData,
            Block, Destination, PoolId, TxOutput,
        },
        primitives::{per_thousand::PerThousand, Amount, Compact, H256},
    };
    use crypto::vrf::{VRFKeyKind, VRFPrivateKey};
    use mockall::predicate::eq;
    use rstest::rstest;

    fn make_block(epoch_index: EpochIndex) -> Block {
        let pool_id = PoolId::new(H256::zero());
        let timestamp = BlockTimestamp::from_int_seconds(1);
        let randomness = get_initial_randomness(ChainType::Testnet);

        let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_entropy(VRFKeyKind::Schnorrkel);
        let vrf_transcript = construct_transcript(epoch_index, &randomness, timestamp);
        let vrf_data = vrf_sk.produce_vrf_data(vrf_transcript);

        let stake_pool_data = StakePoolData::new(
            Amount::from_atoms(1),
            Destination::AnyoneCanSpend,
            vrf_pk,
            Destination::AnyoneCanSpend,
            PerThousand::new(0).unwrap(),
            Amount::ZERO,
        );
        let reward_output = TxOutput::CreateStakePool(pool_id, Box::new(stake_pool_data));
        let pos_data = PoSData::new(vec![], vec![], pool_id, vrf_data, Compact(1));
        Block::new(
            vec![],
            H256::zero().into(),
            timestamp,
            ConsensusData::PoS(pos_data.into()),
            BlockReward::new(vec![reward_output]),
        )
        .unwrap()
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
        let epoch_index = chain_config.epoch_index_from_height(&tip_height);
        let block_index = make_block(epoch_index);
        let expected_modified_epoch = chain_config.epoch_index_from_height(&tip_height);

        if expect_call_to_db {
            db.expect_set_epoch_data()
                .times(1)
                .withf(move |epoch_index, _| *epoch_index == expected_modified_epoch)
                .return_const(Ok(()));
        }

        let mut epoch_data_cache = EpochDataCache::new(&db);
        let pos_db = PoSAccountingDB::<_, TipStorageTag>::new(&db);
        update_epoch_data(
            &mut epoch_data_cache,
            &pos_db,
            &chain_config,
            BlockStateEventWithIndex::Connect(tip_height, &block_index),
        )
        .unwrap();
        epoch_data_cache.consume().flush(&mut db).unwrap();
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

        let mut epoch_data_cache = EpochDataCache::new(&db);
        let pos_db = PoSAccountingDB::<_, TipStorageTag>::new(&db);
        update_epoch_data(
            &mut epoch_data_cache,
            &pos_db,
            &chain_config,
            BlockStateEventWithIndex::Disconnect(tip_height),
        )
        .unwrap();
        epoch_data_cache.consume().flush(&mut db).unwrap();
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
