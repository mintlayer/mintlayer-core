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

use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use blockprod::TimestampSearchData;
use chainstate::ChainInfo;
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        tokens::{RPCTokenInfo, TokenId},
        DelegationId, Destination, OrderId, PoolId, RpcOrderInfo, SignedTransaction, Transaction,
    },
    primitives::{time::Time, Amount},
};
use consensus::GenerateBlockInputData;
use crypto::ephemeral_e2e::EndToEndPublicKey;
use futures::executor::block_on;
use logging::log;
use mempool::{tx_accumulator::PackingStrategy, FeeRate};
use mempool_types::tx_options::TxOptionsOverrides;
use node_comm::{
    node_traits::{ConnectedPeer, PeerId},
    rpc_client::NodeRpcError,
};
use p2p_types::{bannable_address::BannableAddress, socket_address::SocketAddress};
use randomness::{seq::IteratorRandom, CryptoRng, Rng};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use tokio::sync::mpsc;
use utils_networking::IpOrSocketAddress;
use wallet::wallet_events::WalletEventsNoOp;
use wallet_types::{account_info::DEFAULT_ACCOUNT_INDEX, wallet_type::WalletControllerMode};

use super::*;

struct MockWallet {
    genesis_id: Id<GenBlock>,
    blocks: Vec<Id<Block>>,
    next_unused_blocks: Vec<Id<Block>>,
    new_tip_tx: mpsc::Sender<(AccountType, Id<Block>)>,
    latest_median_time: BlockTimestamp,
}

impl MockWallet {
    fn new(chain_config: &ChainConfig, new_tip_tx: mpsc::Sender<(AccountType, Id<Block>)>) -> Self {
        Self {
            genesis_id: chain_config.genesis_block_id(),
            blocks: Vec::new(),
            next_unused_blocks: Vec::new(),
            new_tip_tx,
            latest_median_time: chain_config.genesis_block().timestamp(),
        }
    }

    fn get_best_block_id(&self) -> Id<GenBlock> {
        self.blocks.last().cloned().map_or(self.genesis_id, Into::into)
    }

    fn get_block_height(&self) -> BlockHeight {
        BlockHeight::from(self.blocks.len() as u64)
    }

    fn get_unused_acc_best_block_id(&self) -> Id<GenBlock> {
        self.next_unused_blocks.last().cloned().map_or(self.genesis_id, Into::into)
    }

    fn get_unused_acc_block_height(&self) -> BlockHeight {
        BlockHeight::from(self.next_unused_blocks.len() as u64)
    }

    pub fn reset_unused_account_to_height(&mut self, height: usize) {
        self.next_unused_blocks.truncate(height);
    }
}

impl SyncingWallet for MockWallet {
    fn syncing_state(&self) -> WalletSyncingState {
        WalletSyncingState {
            account_best_blocks: BTreeMap::from([(
                DEFAULT_ACCOUNT_INDEX,
                (self.get_best_block_id(), self.get_block_height()),
            )]),
            unused_account_best_block: (
                self.get_unused_acc_best_block_id(),
                self.get_unused_acc_block_height(),
            ),
        }
    }

    fn scan_blocks(
        &mut self,
        account: U31,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
        _wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        assert!(account == DEFAULT_ACCOUNT_INDEX);
        assert!(!blocks.is_empty());
        assert!(
            common_block_height <= self.get_block_height(),
            "Invalid common block height: {common_block_height}, max: {}",
            self.get_block_height()
        );

        self.blocks.truncate(common_block_height.into_int() as usize);
        for block in blocks {
            assert_eq!(*block.header().prev_block_id(), self.get_best_block_id());
            self.blocks.push(block.header().block_id());
            block_on(async {
                self.new_tip_tx
                    .send((
                        AccountType::Account(DEFAULT_ACCOUNT_INDEX),
                        block.header().block_id(),
                    ))
                    .await
            })
            .unwrap();
        }

        log::debug!(
            "new block added to wallet: {}, block height: {}",
            self.get_best_block_id(),
            self.get_block_height()
        );

        Ok(())
    }

    fn scan_blocks_for_unused_account(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
        _wallet_events: &impl WalletEvents,
    ) -> WalletResult<()> {
        assert!(!blocks.is_empty());
        assert!(
            common_block_height <= self.get_unused_acc_block_height(),
            "Invalid common block height: {common_block_height}, max: {}",
            self.get_unused_acc_block_height()
        );

        self.next_unused_blocks.truncate(common_block_height.into_int() as usize);
        for block in blocks {
            assert_eq!(
                *block.header().prev_block_id(),
                self.get_unused_acc_best_block_id()
            );
            self.next_unused_blocks.push(block.header().block_id());
            block_on(async {
                self.new_tip_tx
                    .send((AccountType::UnusedAccount, block.header().block_id()))
                    .await
            })
            .unwrap();
        }

        log::debug!(
            "new block added to wallet: {}, block height: {}",
            self.get_unused_acc_best_block_id(),
            self.get_unused_acc_block_height(),
        );

        Ok(())
    }

    fn update_median_time(&mut self, median_time: BlockTimestamp) -> WalletResult<()> {
        self.latest_median_time = median_time;
        Ok(())
    }
}

#[derive(Clone)]
struct MockNode {
    tf: Arc<Mutex<TestFramework>>,
}

impl MockNode {
    fn new(rng: &mut (impl Rng + CryptoRng)) -> Self {
        let tf = Arc::new(Mutex::new(TestFramework::builder(rng).build()));
        Self { tf }
    }
}

#[async_trait::async_trait]
impl NodeInterface for MockNode {
    type Error = NodeRpcError;

    fn is_cold_wallet_node(&self) -> WalletControllerMode {
        WalletControllerMode::Hot
    }

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        Ok(self.tf.lock().unwrap().chainstate.info().unwrap())
    }
    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        unreachable!()
    }
    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        Ok(self.tf.lock().unwrap().chainstate.get_block(block_id).unwrap())
    }
    async fn get_mainchain_blocks(
        &self,
        from: BlockHeight,
        max_count: usize,
    ) -> Result<Vec<Block>, Self::Error> {
        Ok(self
            .tf
            .lock()
            .unwrap()
            .chainstate
            .get_mainchain_blocks(from, max_count)
            .unwrap())
    }
    async fn get_block_ids_as_checkpoints(
        &self,
        start_height: BlockHeight,
        end_height: BlockHeight,
        step: NonZeroUsize,
    ) -> Result<Vec<(BlockHeight, Id<GenBlock>)>, Self::Error> {
        Ok(self
            .tf
            .lock()
            .unwrap()
            .chainstate
            .get_block_ids_as_checkpoints(start_height, end_height, step)
            .unwrap())
    }
    async fn get_best_block_height(&self) -> Result<BlockHeight, Self::Error> {
        unreachable!()
    }
    async fn get_block_id_at_height(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Id<GenBlock>>, Self::Error> {
        Ok(self.tf.lock().unwrap().chainstate.get_block_id_from_height(&height).unwrap())
    }
    async fn get_last_common_ancestor(
        &self,
        first_block: Id<GenBlock>,
        second_block: Id<GenBlock>,
    ) -> Result<Option<(Id<GenBlock>, BlockHeight)>, Self::Error> {
        Ok(self
            .tf
            .lock()
            .unwrap()
            .chainstate
            .last_common_ancestor_by_id(&first_block, &second_block)
            .unwrap())
    }
    async fn get_stake_pool_balance(
        &self,
        _pool_id: PoolId,
    ) -> Result<Option<Amount>, Self::Error> {
        unreachable!()
    }

    async fn get_staker_balance(&self, _pool_id: PoolId) -> Result<Option<Amount>, Self::Error> {
        unreachable!()
    }

    async fn get_pool_decommission_destination(
        &self,
        _pool_id: PoolId,
    ) -> Result<Option<Destination>, Self::Error> {
        unreachable!()
    }

    async fn get_delegation_share(
        &self,
        _pool_id: PoolId,
        _delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Self::Error> {
        unreachable!()
    }

    async fn get_token_info(
        &self,
        _token_id: TokenId,
    ) -> Result<Option<RPCTokenInfo>, Self::Error> {
        unreachable!()
    }

    async fn get_order_info(
        &self,
        _order_id: OrderId,
    ) -> Result<Option<RpcOrderInfo>, Self::Error> {
        unreachable!()
    }

    async fn generate_block_e2e(
        &self,
        _encrypted_input_data: Vec<u8>,
        _public_key: EndToEndPublicKey,
        _transactions: Vec<SignedTransaction>,
        _transaction_ids: Vec<Id<Transaction>>,
        _packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error> {
        unreachable!()
    }

    async fn collect_timestamp_search_data(
        &self,
        _pool_id: PoolId,
        _min_height: BlockHeight,
        _max_height: Option<BlockHeight>,
        _seconds_to_check_for_height: u64,
        _all_timestamps_between_blocks: bool,
    ) -> Result<TimestampSearchData, Self::Error> {
        unreachable!()
    }

    async fn blockprod_e2e_public_key(&self) -> Result<EndToEndPublicKey, Self::Error> {
        unreachable!()
    }

    async fn get_utxo(
        &self,
        _outpoint: common::chain::UtxoOutPoint,
    ) -> Result<Option<common::chain::TxOutput>, Self::Error> {
        unreachable!()
    }

    async fn generate_block(
        &self,
        _input_data: GenerateBlockInputData,
        _transactions_hex: Vec<SignedTransaction>,
        _transaction_ids: Vec<Id<Transaction>>,
        _packing_strategy: PackingStrategy,
    ) -> Result<Block, Self::Error> {
        unreachable!()
    }
    async fn submit_block(&self, _block: Block) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn submit_transaction(
        &self,
        _tx: SignedTransaction,
        _options: TxOptionsOverrides,
    ) -> Result<(), Self::Error> {
        unreachable!()
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn node_enable_networking(&self, _enable: bool) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn node_version(&self) -> Result<String, Self::Error> {
        unreachable!()
    }

    async fn p2p_connect(&self, _address: IpOrSocketAddress) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn p2p_disconnect(&self, _peer_id: PeerId) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn p2p_list_banned(&self) -> Result<Vec<(BannableAddress, Time)>, Self::Error> {
        unreachable!()
    }
    async fn p2p_ban(
        &self,
        _address: BannableAddress,
        _duration: Duration,
    ) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn p2p_unban(&self, _address: BannableAddress) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn p2p_list_discouraged(&self) -> Result<Vec<(BannableAddress, Time)>, Self::Error> {
        unreachable!()
    }
    async fn p2p_undiscourage(&self, _address: BannableAddress) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error> {
        unreachable!()
    }
    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        unreachable!()
    }
    async fn p2p_get_reserved_nodes(&self) -> Result<Vec<SocketAddress>, Self::Error> {
        unreachable!()
    }
    async fn p2p_add_reserved_node(&self, _address: IpOrSocketAddress) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn p2p_remove_reserved_node(
        &self,
        _address: IpOrSocketAddress,
    ) -> Result<(), Self::Error> {
        unreachable!()
    }

    async fn mempool_get_fee_rate(&self, _in_top_x_mb: usize) -> Result<FeeRate, Self::Error> {
        Ok(FeeRate::from_amount_per_kb(Amount::ZERO))
    }

    async fn mempool_get_fee_rate_points(&self) -> Result<Vec<(usize, FeeRate)>, Self::Error> {
        Ok(vec![(
            1,
            FeeRate::from_amount_per_kb(Amount::from_atoms(1)),
        )])
    }
}

fn create_chain(node: &MockNode, rng: &mut (impl Rng + CryptoRng), parent: u64, count: usize) {
    let mut tf = node.tf.lock().unwrap();
    let parent_id = tf.chainstate.get_block_id_from_height(&parent.into()).unwrap().unwrap();
    tf.create_chain(&parent_id, count, rng).unwrap();
}

async fn wait_new_tip(node: &MockNode, new_tip_tx: &mut mpsc::Receiver<(AccountType, Id<Block>)>) {
    let expected_block_id = node.tf.lock().unwrap().best_block_id();
    let mut reached = BTreeMap::<AccountType, Option<Id<Block>>>::new();
    reached.insert(AccountType::Account(DEFAULT_ACCOUNT_INDEX), None);
    reached.insert(AccountType::UnusedAccount, None);

    let wait_fut = async move {
        while !reached
            .values()
            .all(|block| block.map_or(false, |block| block == expected_block_id))
        {
            let (acc, block_id) = new_tip_tx.recv().await.unwrap();
            reached.entry(acc).or_default().replace(block_id);
        }
    };
    tokio::time::timeout(Duration::from_secs(60), wait_fut).await.unwrap();
}

fn run_sync(chain_config: Arc<ChainConfig>, node: MockNode, mut wallet: MockWallet) {
    tokio::spawn(async move {
        loop {
            let _ = sync_once(&chain_config, &node, &mut wallet, &WalletEventsNoOp).await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn basic_sync(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let node = MockNode::new(&mut rng);
    let chain_config = Arc::clone(node.tf.lock().unwrap().chainstate.get_chain_config());
    let (new_tip_tx, mut new_tip_rx) = mpsc::channel(100);
    let wallet = MockWallet::new(&chain_config, new_tip_tx);

    run_sync(Arc::clone(&chain_config), node.clone(), wallet);

    // Build blocks
    for height in 1..10 {
        create_chain(&node, &mut rng, height - 1, 1);
        wait_new_tip(&node, &mut new_tip_rx).await;
    }

    // Reorgs
    for height in 10..20 {
        create_chain(&node, &mut rng, height - 5, 5);
        wait_new_tip(&node, &mut new_tip_rx).await;
    }

    // More blocks
    for height in 20..30 {
        create_chain(&node, &mut rng, height - 1, 1);
        wait_new_tip(&node, &mut new_tip_rx).await;
    }

    // More reorgs
    for height in 30..40 {
        create_chain(&node, &mut rng, height - 5, 5);
        wait_new_tip(&node, &mut new_tip_rx).await;
    }
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn restart_from_genesis(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let node = MockNode::new(&mut rng);
    let chain_config = Arc::clone(node.tf.lock().unwrap().chainstate.get_chain_config());
    let (new_tip_tx, mut new_tip_rx) = mpsc::channel(100);
    let wallet = MockWallet::new(&chain_config, new_tip_tx);

    run_sync(Arc::clone(&chain_config), node.clone(), wallet);

    create_chain(&node, &mut rng, 0, 10);
    wait_new_tip(&node, &mut new_tip_rx).await;

    *node.tf.lock().unwrap() = TestFramework::builder(&mut rng).build();

    create_chain(&node, &mut rng, 0, 10);
    wait_new_tip(&node, &mut new_tip_rx).await;
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn randomized(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let node = MockNode::new(&mut rng);
    let chain_config = Arc::clone(node.tf.lock().unwrap().chainstate.get_chain_config());
    let (new_tip_tx, mut new_tip_rx) = mpsc::channel(100);
    let wallet = MockWallet::new(&chain_config, new_tip_tx);

    run_sync(Arc::clone(&chain_config), node.clone(), wallet);

    create_chain(&node, &mut rng, 0, 1);
    wait_new_tip(&node, &mut new_tip_rx).await;

    for _ in 0..100 {
        let new_tip = {
            let mut tf = node.tf.lock().unwrap();
            let old_best_block = tf.best_block_id();
            // Select a random block from the 5 latest to build a new chain
            let parent =
                *tf.block_indexes.iter().rev().take(5).choose(&mut rng).unwrap().block_id();
            tf.create_chain(&parent.into(), 1, &mut rng).unwrap();
            old_best_block != tf.best_block_id()
        };

        if new_tip {
            wait_new_tip(&node, &mut new_tip_rx).await;
        }
    }
}

#[rstest]
#[trace]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test]
async fn account_out_of_sync(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let node = MockNode::new(&mut rng);
    let chain_config = Arc::clone(node.tf.lock().unwrap().chainstate.get_chain_config());
    let (new_tip_tx, mut new_tip_rx) = mpsc::channel(100);
    let mut wallet = MockWallet::new(&chain_config, new_tip_tx);

    // Build blocks
    for height in 1..10 {
        create_chain(&node, &mut rng, height - 1, 1);
    }

    let _ = sync_once(&chain_config, &node, &mut wallet, &WalletEventsNoOp).await;
    wait_new_tip(&node, &mut new_tip_rx).await;

    let reset_to = rng.gen_range(1..9);
    wallet.reset_unused_account_to_height(reset_to);

    // Build new blocks
    for height in 10..20 {
        create_chain(&node, &mut rng, height - 1, 1);
    }

    // DEFAULT_ACCOUNT_INDEX is 10 blocks behind but unused account is a bit more
    let _ = sync_once(&chain_config, &node, &mut wallet, &WalletEventsNoOp).await;

    // check that we receive that first the unused account was borough to height 10
    for height in (reset_to + 1)..10 {
        let (acc, block_id) = new_tip_rx.recv().await.unwrap();

        let expected_block_id = node
            .get_block_id_at_height(BlockHeight::new(height as u64))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(acc, AccountType::UnusedAccount);
        assert_eq!(block_id, expected_block_id);
    }

    // Next in order of highest to lowest the accounts will be synced to 20
    for expected_acc in [AccountType::Account(DEFAULT_ACCOUNT_INDEX), AccountType::UnusedAccount] {
        for height in 10..20 {
            let (acc, block_id) = new_tip_rx.recv().await.unwrap();

            let expected_block_id = node
                .get_block_id_at_height(BlockHeight::new(height as u64))
                .await
                .unwrap()
                .unwrap();

            assert_eq!(acc, expected_acc);
            assert_eq!(block_id, expected_block_id);
        }
    }
}
