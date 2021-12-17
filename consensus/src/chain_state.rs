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

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!! This code is just a MOC to discuss what is the proper way to implement ChainState   !!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

// Can we use Uint256 from Bitcoin types or it will be better to copy the implementation to our code?
use bitcoin::util::uint::Uint256;
use common::chain::block::BlockHeader;
use common::chain::block::BlockV1;
use common::primitives::BlockHeight;
// use common::chain::block::BlockIndex;
// use common::chain::block::BlockManager;

use common::chain::Transaction;
use std::cell::RefCell;
use std::rc::Rc;
use thiserror::Error;

type Block = BlockV1;

// todo: When Roy will merge his PR, we should use his implementation
pub struct MemPool;

// todo: Implement these types

#[derive(Debug)]
pub struct Chain;

#[allow(dead_code, unused_variables)]
impl Chain {
    pub fn height(&self) -> BlockHeight {
        unimplemented!()
    }

    pub fn tip(&self) -> BlockIndex {
        unimplemented!()
    }

    pub fn set_tip(&self, index: BlockIndex) -> BlockIndex {
        unimplemented!()
    }

    pub fn find_fork(&self, index: BlockIndex) -> BlockIndex {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct ChainState {
    main_chain: Chain,
}

#[derive(Debug, Default)]
pub struct ConsensusParams;

#[derive(Debug, Default, Clone, Copy)]
#[allow(dead_code, unused_variables)]
pub struct BlockIndex {
    status: BlockStatus,
}

#[derive(Debug, Clone, Copy)]
pub struct BlockMap;

#[derive(Debug)]
pub struct BlockManager {
    block_index: BlockMap,
}

#[derive(Debug)]
pub struct BlockValidationState;

impl BlockValidationState {
    pub fn is_valid(&self) -> bool {
        unimplemented!()
    }

    pub fn get_result(&self) -> BlockValidationResult {
        unimplemented!()
    }
}

#[derive(Debug)]
// todo: We should discuss, is it works for if we will use here ChainConfig
pub struct ChainParams;

#[derive(Debug)]
pub struct SnapshotMetadata;

#[derive(Debug)]
pub struct MempoolAcceptResult;

type Callback = fn();

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockStatus {
    // Unused.
    ValidUnknown = 0,

    // Reserved (was BLOCK_VALID_HEADER).
    ValidReserved = 1,

    // All parent headers found, difficulty matches, timestamp >= median previous, checkpoint. Implies all parents
    // are also at least TREE.
    ValidTree = 2,

    /**
     * Only first tx is coinbase, 2 <= coinbase input script length <= 100, transactions valid, no duplicate txids,
     * sigops, size, merkle root. Implies all parents are at least TREE but not necessarily TRANSACTIONS. When all
     * parent blocks also have TRANSACTIONS, CBlockIndex::nChainTx will be set.
     */
    ValidTransactions = 3,

    // Outputs do not overspend inputs, no double spends, coinbase output ok, no immature coinbase spends, BIP30.
    // Implies all parents are also at least CHAIN.
    ValidChain = 4,

    // Scripts & signatures ok. Implies all parents are also at least SCRIPTS.
    ValidScripts = 5,

    // All validity bits.
    ValidMask = 7,

    HaveData = 8,  // < full block available in blk*.dat
    HaveUndo = 16, // < undo data available in rev*.dat
    HaveMask = 24,

    FailedValid = 32, // < stage after last reached validness failed
    FailedChild = 64, // < descends from failed block
    FailedMask = 96,

    OptWitness = 128, // < block data in blk*.dat was received with a witness-enforcing client

    /**
     * If set, this indicates that the block index entry is assumed-valid.
     * Certain diagnostics will be skipped in e.g. CheckBlockIndex().
     * It almost certainly means that the block's full validation is pending
     * on a background chainstate. See `doc/assumeutxo.md`.
     */
    AssumedValid = 256,
}

impl Default for BlockStatus {
    fn default() -> Self {
        BlockStatus::ValidUnknown
    }
}

/** A "reason" why a block was invalid, suitable for determining whether the
 * provider of the block should be banned/ignored/disconnected/etc.
 * These are much more granular than the rejection codes, which may be more
 * useful for some other use-cases.
 */
#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
pub enum BlockValidationResult {
    ResultUnset = 0,           // < initial value. Block has not yet been rejected
    InvalidConsensusRules = 1, // < invalid by consensus rules (excluding any below reasons)
    /**
     * Invalid by a change to consensus rules more recent than SegWit.
     * Currently unused as there are no such consensus rule changes, and any download
     * sources realistically need to support SegWit in order to provide useful data,
     * so differentiating between always-invalid and invalid-by-pre-SegWit-soft-fork
     * is uninteresting.
     */
    RecentConsensusChane = 2,
    CachedInvalid = 3, // < this block was cached as being invalid and we didn't store the reason why
    InvalidHeader = 4, // < invalid proof of work or time too old
    BlockMutated = 5,  // < the block's data didn't match the data committed to by the consensus
    BlockMissingPrev = 6, // < We don't have the previous block the checked one is built on
    BlockInvalidPrev = 7, // < A block this one builds on is invalid
    BlockTimeFuture = 8, // < block timestamp was > 2 hours in the future (or our clock is bad)
    BlockCheckpoint = 9, // < the block failed to meet one of our checkpoints
}

//
// todo: We should discuss what errors we have to processing. I've just copied errors from BTC
//
#[allow(dead_code)]
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

#[allow(dead_code)]
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

//
// Provides an interface for creating and interacting with one or two
// chainstates: an IBD chainstate generated by downloading blocks, and
// an optional snapshot chainstate loaded from a UTXO snapshot. Managed
// chainstates can be maintained at different heights simultaneously.
//
// This class provides abstractions that allow the retrieval of the current
// most-work chainstate ("Active") as well as chainstates which may be in
// background use to validate UTXO snapshots.
//
#[allow(dead_code)]
pub struct ChainStateManager {
    // *IBD chainstate*: a chainstate whose current state has been "fully"
    // validated by the initial block download process.
    ibd_chainstate: Rc<ChainState>,

    //  *Snapshot chainstate*: a chainstate populated by loading in an
    //  assume utxo UTXO snapshot.
    snapshot_chainstate: Rc<ChainState>,

    // *Active chainstate*: the chainstate containing the current most-work
    // chain. Consulted by most parts of the system (net_processing,
    // wallet) as a reflection of the current chain and UTXO set.
    // This may either be an IBD chainstate or a snapshot chainstate.
    active_chainstate: Rc<ChainState>,

    // If true, the assumed-valid chainstate has been fully validated
    // by the background validation chainstate.
    snapshot_validated: bool,

    best_invalid: BlockIndex,

    // A single BlockManager instance is shared across each constructed
    // chainstate to avoid duplicating block metadata.
    pub block_manager: Rc<RefCell<BlockManager>>,

    //   In order to efficiently track invalidity of headers, we keep the set of
    //   blocks which we tried to connect and found to be invalid here (ie which
    //   were set to BLOCK_FAILED_VALID since the last restart). We can then
    //   walk this set and check if a new header is a descendant of something in
    //   this set, preventing us from having to walk block_index when we try
    //   to connect a bad block and fail.
    //
    //   While this is more complicated than marking everything which descends
    //   from an invalid block as invalid at the time we discover it to be
    //   invalid, doing so would require walking all of m_block_index to find all
    //   descendants. Since this case should be very rare, keeping track of all
    //   BLOCK_FAILED_VALID blocks in a set should be just fine and work just as
    //   well.
    //
    //   Because we already walk block_index in height-order at startup, we go
    //   ahead and mark descendants of invalid blocks as FAILED_CHILD at that time,
    //   instead of putting things in this set.
    pub failed_blocks: Vec<BlockIndex>,

    // The total number of bytes available for us to use across all in-memory
    // coins caches. This will be split somehow across chainstates.
    pub total_coinstrip_cache: usize,

    // The total number of bytes available for us to use across all leveldb
    // coins databases. This will be split somehow across chainstates.
    pub total_coinsdb_cache: usize,
}

impl ChainStateManager {
    #[allow(dead_code)]
    fn populate_and_validate_snapshot(&mut self) -> Result<(), ChainstateLoadingError> {
        unimplemented!()
    }

    #[allow(dead_code)]
    fn accept_block_header(
        _block: &BlockHeader,
        _state: &BlockValidationState,
        _chainparams: &ChainParams,
        _index: &mut BlockIndex,
    ) -> bool {
        // 1. Check for duplicate. If Block header is already known, we should return false
        // 2. Is the previous block not found?
        // 3. Is the previous block are wrong?
        // 4. Is the previous block are invalid?
        // 5. Update block index

        /* Determine if this block descends from any block which has been found
         * invalid (m_failed_blocks), then mark pindexPrev and any blocks between
         * them as failed. For example:
         *
         *                D3
         *              /
         *      B2 - C2
         *    /         \
         *  A             D2 - E2 - F2
         *    \
         *      B1 - C1 - D1 - E1
         *
         * In the case that we attempted to reorg from E1 to F2, only to find
         * C2 to be invalid, we would mark D2, E2, and F2 as BLOCK_FAILED_CHILD
         * but NOT D3 (it was not in any of our candidate sets at the time).
         *
         * In any case D3 will also be marked as BLOCK_FAILED_CHILD at restart
         * in LoadBlockIndex.
         */

        unimplemented!()
    }

    // Instantiate a new chainstate and assign it based upon whether it is
    // from a snapshot.
    //
    // @param[in] mempool              The mempool to pass to the chainstate
    //                                  constructor
    // @param[in] snapshot_blockhash   If given, signify that this chainstate
    //                                 is based on a snapshot.
    #[allow(dead_code)]
    pub fn initialize_chainstate(
        _mempool: &MemPool,
        _snapshot_blockhash: Option<Uint256>,
    ) -> ChainState {
        unimplemented!()
    }

    // Get all chainstates currently being used.
    #[allow(dead_code)]
    pub fn get_all_chainstates(&self) -> Vec<ChainState> {
        unimplemented!()
    }

    // Construct and activate a Chainstate on the basis of UTXO snapshot data.
    //
    // Steps in BITCOIN:
    //
    // - Initialize an unused ChainState.
    // - Load its `CoinsViews` contents from `coins_file`.
    // - Verify that the hash of the resulting coinsdb matches the expected hash
    //   per assumeutxo chain parameters.
    // - Wait for our headers chain to include the base block of the snapshot.
    // - "Fast forward" the tip of the new chainstate to the base of the snapshot,
    //   faking nTx* block index data along the way.
    // - Move the new chainstate to `m_snapshot_chainstate` and make it our
    //   ChainstateActive().
    //
    #[allow(dead_code)]
    pub fn active_snapshot(
        &self,
        /* We should use CoinsFile or DB ? */
        _metadata: &SnapshotMetadata,
        _in_memory: bool,
    ) -> bool {
        unimplemented!()
    }

    // The most-work chain.
    #[allow(dead_code)]
    pub fn active_chainstate(&self) -> ChainState {
        unimplemented!()
    }

    #[allow(dead_code)]
    pub fn active_chain(&self) -> Chain {
        self.active_chainstate().main_chain
    }

    #[allow(dead_code)]
    pub fn active_height(&self) -> BlockHeight {
        self.active_chain().height()
    }

    #[allow(dead_code)]
    pub fn active_tip(&self) -> BlockIndex {
        self.active_chain().tip()
    }

    #[allow(dead_code)]
    pub fn block_index(&self) -> BlockMap {
        let block_manager = &*self.block_manager.borrow_mut();
        block_manager.block_index
    }

    // @returns true if a snapshot-based chainstate is in use. Also implies
    //          that a background validation chainstate is also in use.
    #[allow(dead_code)]
    pub fn is_snapshot_active(&self) -> bool {
        unimplemented!()
    }

    #[allow(dead_code)]
    pub fn snapshot_blockhash(&self) -> Option<Uint256> {
        unimplemented!()
    }

    // Is there a snapshot in use and has it been fully validated?
    #[allow(dead_code)]
    pub fn is_snapshot_validated(&self) -> bool {
        self.snapshot_validated
    }

    //
    //   Process an incoming block. This only returns after the best known valid
    //   block is made active. Note that it does not, however, guarantee that the
    //   specific block passed to it has been checked for validity!
    //
    //   If you want to *possibly* get feedback on whether block is valid, you must
    //   install a CValidationInterface (see validationinterface.h) - this will have
    //   its BlockChecked method called whenever *any* block completes validation.
    //
    //   Note that we guarantee that either the proof-of-work is valid on block, or
    //   (and possibly also) BlockChecked will have been called.
    //
    //   May not be called in a validationinterface callback.
    //
    //   @param[in]   block The block we want to process.
    //   @param[in]   force_processing Process this block even if unrequested; used for non-network block sources.
    //   @param[out]  new_block A boolean which is set to indicate if the block was first received via this call
    //   @returns     If the block was processed, independently of block validity
    //
    #[allow(dead_code)]
    pub fn process_new_block(
        &self,
        _chainparams: &ChainParams,
        _block: &Block,
        _force_processing: bool,
        _new_block: bool,
    ) -> bool {
        unimplemented!()
    }

    //   Process incoming block headers.
    //
    //   May not be called in a
    //   validationinterface callback.
    //
    //   @param[in]  block The block headers themselves
    //   @param[out] state This may be set to an Error state if any error occurred processing them
    //   @param[in]  chainparams The params for the chain we want to connect to
    //   @param[out] ppindex If set, the pointer will be set to point to the last new block index object for the given headers
    //
    #[allow(dead_code)]
    pub fn process_new_block_headers(
        &self,
        headers: &Vec<BlockHeader>,
        state: &BlockValidationState,
        chainparams: &ChainParams,
        block_index: &mut BlockIndex,
    ) -> bool {
        // 1. Call in the loop accept_block_header
        for header in headers {
            let mut new_block_index = BlockIndex::default();
            if Self::accept_block_header(header, state, chainparams, &mut new_block_index) {
                *block_index = new_block_index;
            } else {
                return false;
            }
        }
        // 2. Send block tip changed notifications about active chainstate
        unimplemented!()
    }

    //
    //  Try to add a transaction to the memory pool.
    //
    //  @param[in]  tx              The transaction to submit for mempool acceptance.
    //  @param[in]  test_accept     When true, run validation checks but don't submit to mempool.
    //
    #[allow(dead_code)]
    pub fn process_transaction(
        &self,
        _tx: &Transaction,
        _test_accept: bool,
    ) -> MempoolAcceptResult {
        unimplemented!()
    }

    // Load the block tree and coins database from disk, initializing state if we're running with -reindex
    #[allow(dead_code)]
    pub fn load_block_index(&self) -> bool {
        unimplemented!()
    }

    // Clear (deconstruct) chainstate data.
    #[allow(dead_code)]
    pub fn clear(&self) -> bool {
        unimplemented!()
    }
}

impl Drop for ChainStateManager {
    fn drop(&mut self) {
        println!(" Unload block index and chain data before shutdown.!");
    }
}

impl ChainState {
    #[allow(dead_code, unused_variables)]
    pub fn accept_block(
        block: &Block,
        state: &BlockValidationState,
        index: &mut BlockIndex,
        requested: bool,
        new_block: bool,
    ) -> bool {
        // 1. We have to accept header - chain_manager.accept_block_header
        // 2. Check block index
        // 3. Try to process all requested blocks that we don't have, but only process an unrequested
        // block if it's new and has enough work to advance our tip, and isn't too many blocks ahead.
        // Blocks that are too out-of-order needlessly limit the effectiveness of
        // pruning, because pruning will not delete block files that contain any
        // blocks which are too close in height to the tip.  Apply this test
        // regardless of whether pruning is enabled; it should generally be safe to
        // not process unrequested blocks.
        // 4. Check block
        let params = ConsensusParams::default();
        let prev_block = BlockIndex::default();
        if check_block(block, state, &params, true)
            && contextual_check_block(block, state, &params, prev_block)
        {
            if !state.is_valid() && state.get_result() != BlockValidationResult::BlockMutated {
                // index.status |= BlockStatus::FailedValid;
                // In BTC a global object
                // set_dirty_block_index.insert(index);
            }
            // return error
            return false;
        }
        // 5. Header is valid, has merkle tree and segwit merkle tree are good...RELAY NOW
        // (but if it does not build on our best tip, let the SendMessages loop relay it)
        // 6. Write block to history
        unimplemented!()
    }
}

#[allow(dead_code, unused_variables)]
pub fn load_chain_state(
    reset: bool,
    chain_manager: &ChainStateManager,
    mempool: &MemPool,
    prune_mode: bool,
    consensus_params: &ConsensusParams,
    reindex_chain_state: bool,
    block_tree_db_cache: i64,
    coin_db_cache: i64,
    coin_cache_usage: i64,
    block_tree_db_in_memory: bool,
    coins_db_in_memory: bool,
    shutdown_requested: Callback,
    coins_error_db: Callback,
) -> Result<ChainState, ChainstateLoadingError> {
    // 1. Initialize the chain state from mempool
    // 2. Unload block index
    // 3. Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
    // in the past, but is now trying to run unpruned.
    // 4. ReplayBlocks is a no-op if we cleared the coinsviewdb with -reindex or -reindex-chainstate

    // Ok(ChainState { main_chain: Chain })
    unimplemented!()
}

#[allow(dead_code, unused_variables)]
pub fn check_block(
    block: &Block,
    state: &BlockValidationState,
    params: &ConsensusParams,
    check_merkle_root: bool,
) -> bool {
    // 1. These are checks that are independent of context.
    // 2. Check that the block header is valid.  This is mostly redundant with the call in AcceptBlockHeader
    // 3. Check the merkle root:
    //      Check for merkle tree malleability (CVE-2012-2459): repeating sequences
    //      of transactions in a block without affecting the merkle root of a block,
    //      while still invalidating it.
    // 4. All potential-corruption validation must be done before we do any transaction validation,
    // as otherwise we may mark the header as invalid because we receive the wrong transactions for it.
    // 5. Size limits
    // 6. Check transactions
    //      Must check for duplicate inputs (see CVE-2018-17144)

    // Something else here?
    unimplemented!()
}

//  Context-dependent validity checks.
//   By "context", we mean only the previous block headers, but not the UTXO
//   set; UTXO-related validity checks are done in ConnectBlock().
//   NOTE: This function is not currently invoked by ConnectBlock(), so we
//   should consider upgrade issues if we change which consensus rules are
//   enforced in this function (eg by adding a new consensus rule). See comment
//   in ConnectBlock().
//   Note that -reindex-chainstate skips the validation that happens here!
#[allow(dead_code, unused_variables)]
pub fn contextual_check_block_header(
    block: &Block,
    state: &BlockValidationState,
    block_manager: &BlockManager,
    params: &ChainParams,
    prev_index: BlockIndex,
    adjusted_time: i64,
) -> bool {
    // 1. Check the consensus rules that were applied to blocks
    // 2. Check against checkpoints
    //      Don't accept any forks from the main chain prior to last checkpoint.
    //      GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
    //      BlockIndex().
    // 3. Check timestamp against prev
    // 4. Check timestamp
    // 5. Reject blocks with outdated version
    unimplemented!()
}

#[allow(dead_code, unused_variables)]
pub fn contextual_check_block(
    block: &Block,
    state: &BlockValidationState,
    consensus: &ConsensusParams,
    prev_index: BlockIndex,
) -> bool {
    // 1. Check that all transactions are finalized
    // 2. Enforce rule that the coinbase starts with serialized block height
    // 3. Validation for witness commitments.

    // After the coinbase witness reserved value and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    unimplemented!()
}
