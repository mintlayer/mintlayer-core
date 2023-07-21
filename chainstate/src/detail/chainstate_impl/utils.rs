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

use super::{Chainstate, TxRw};
use crate::{detail::chainstateref::ChainstateRef, BlockError, TransactionVerificationStrategy};
use chainstate_storage::{BlockchainStorage, BlockchainStorageRead};
use chainstate_types::{BlockIndex, GenBlockIndex};
use common::{
    chain::{Block, GenBlock},
    primitives::{BlockHeight, Id},
};
use utils::tap_error_log::LogError;

impl<S: BlockchainStorage, V: TransactionVerificationStrategy> Chainstate<S, V> {
    /// Create a read-write transaction, call `main_action` on it and commit.
    /// If committing fails, repeat the whole process again until it succeeds or
    /// the maximum number of commit attempts is reached.
    /// If the maximum number of attempts is reached, use `on_db_err` to create
    /// a BlockError and return it.
    /// On each iteration, before doing anything else, call `on_new_attempt`
    /// (this can be used for logging).
    pub(super) fn with_rw_tx<MainAction, OnNewAttempt, OnDbCommitErr, Res, Err>(
        &mut self,
        mut main_action: MainAction,
        mut on_new_attempt: OnNewAttempt,
        on_db_commit_err: OnDbCommitErr,
    ) -> Result<Res, Err>
    where
        MainAction: FnMut(&mut ChainstateRef<TxRw<'_, S>, V>) -> Result<Res, Err>,
        OnNewAttempt: FnMut(/*attempt_number:*/ usize),
        OnDbCommitErr: FnOnce(/*attempts_count:*/ usize, chainstate_storage::Error) -> Err,
        Err: From<chainstate_storage::Error> + std::fmt::Display,
    {
        let mut attempts_count = 0;
        loop {
            on_new_attempt(attempts_count);
            attempts_count += 1;

            let mut chainstate_ref = self.make_db_tx().map_err(Err::from).log_err()?;
            let result = main_action(&mut chainstate_ref).log_err()?;
            let db_commit_result = chainstate_ref.commit_db_tx().log_err();

            match db_commit_result {
                Ok(_) => return Ok(result),
                Err(err) => {
                    if attempts_count >= *self.chainstate_config().max_db_commit_attempts {
                        return Err(on_db_commit_err(attempts_count, err));
                    }
                }
            }
        }
    }
}

pub(super) fn get_block_index<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    block_id: &Id<Block>,
) -> Result<Option<BlockIndex>, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_block_index(block_id)
        .map_err(|err| BlockError::BlockIndexQueryError(err, (*block_id).into()))
}

pub(super) fn get_existing_block_index<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    block_id: &Id<Block>,
) -> Result<BlockIndex, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_existing_block_index(block_id)
        .map_err(|err| BlockError::BlockIndexQueryError(err, (*block_id).into()))
}

pub(super) fn is_block_in_main_chain<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
    block_id: &Id<GenBlock>,
) -> Result<bool, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .is_block_in_main_chain(block_id)
        .map_err(|err| BlockError::IsBlockInMainChainQueryError(err, *block_id))
}

pub(super) fn get_min_height_with_allowed_reorg<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
) -> Result<BlockHeight, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_min_height_with_allowed_reorg()
        .map_err(BlockError::MinHeightForReorgQueryError)
}

pub(super) fn get_best_block_index<S, V>(
    chainstate_ref: &ChainstateRef<S, V>,
) -> Result<GenBlockIndex, BlockError>
where
    S: BlockchainStorageRead,
    V: TransactionVerificationStrategy,
{
    chainstate_ref
        .get_best_block_index()
        .map_err(BlockError::BestBlockIndexQueryError)
}
