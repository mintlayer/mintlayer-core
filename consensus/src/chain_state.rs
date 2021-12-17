// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): Anton Sinitsyn

use thiserror::Error;

type BlockHeight = u64;

//
// todo: We should discuss what errors we have to processing. I've just copied errors from BTC
//
#[derive(Error, Debug)]
pub enum ChainstateLoadingError {
    #[error("Error loading block database")]
    LoadingBlockDb,
    #[error("Incorrect or no genesis block found")]
    BadGenesisBlock,
    #[error("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain")]
    PrunedNeedsReindex,
    #[error("Error initializing block database")]
    LoadGenesisBlockFailed,
    #[error("Error upgrading chainstate database")]
    ChainstateUpgradeFailed,
    #[error(
        "Unable to replay blocks. You will need to rebuild the database using -reindex-chainstate"
    )]
    ReplayblocksFailed,
    #[error("Error initializing block database")]
    LoadChainTipFailed,
    #[error("Error opening block database")]
    GenericBlockDBOpenFailed,
    #[error(
        "Witness data for blocks after height `{0}` requires validation. Please restart with -reindex"
    )]
    BlocksWintessInsufficientlyValidated(BlockHeight),
}

#[derive(Error, Debug)]
pub enum ChainstateLoadVerifyError {
    #[error(
    "The block database contains a block which appears to be from the future.\
    This may be due to your computer's date and time being set incorrectly.\
    Only rebuild the block database if you are sure that your computer's date and time are correct."
    )]
    BlockFromFuture,
    #[error("Corrupted block database detected")]
    CorruptedBlockDB,
    #[error("Error opening block database")]
    GenericFailure,
}

pub struct ChainStateManager;

pub struct ChainState;

pub struct MemPool;

pub fn load_chain_state(
    reset: bool,
    chain_manager: &ChainStateManager,
    mempool: &Mempool,
    prune_mode: bool,
    consensus_params: &ConsensusParams,
    reindex_chain_state: bool,
    block_tree_db_cache: i64,
    coin_db_cache: i64,
    coin_cache_usage: i64,
    block_tree_db_in_memory: bool,
    coins_db_in_memory: bool,
    shutdown_requested: Box<dyn FnOnce<bool, Output = ()>>,
    coins_error_db: Box<dyn FnOnce<(), Output = ()>>,
) -> Result<ChainState, ChainstateLoadingError> {
}
