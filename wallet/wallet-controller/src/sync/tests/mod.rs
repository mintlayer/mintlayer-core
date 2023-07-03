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
    sync::{Arc, Mutex},
    time::Duration,
};

use chainstate::ChainInfo;
use chainstate_test_framework::TestFramework;
use common::{
    chain::{PoolId, SignedTransaction},
    primitives::Amount,
};
use consensus::GenerateBlockInputData;
use crypto::random::{seq::IteratorRandom, CryptoRng, Rng};
use logging::log;
use node_comm::{
    node_traits::{ConnectedPeer, PeerId},
    rpc_client::NodeRpcError,
};
use rstest::rstest;
use serialization::hex_encoded::HexEncoded;
use test_utils::random::{make_seedable_rng, Seed};
use tokio::sync::mpsc;

use super::*;

struct MockWallet {
    genesis_id: Id<GenBlock>,
    blocks: Vec<Id<Block>>,
    new_tip_tx: mpsc::UnboundedSender<Id<Block>>,
    latest_median_time: BlockTimestamp,
}

impl MockWallet {
    fn new(chain_config: &ChainConfig, new_tip_tx: mpsc::UnboundedSender<Id<Block>>) -> Self {
        Self {
            genesis_id: chain_config.genesis_block_id(),
            blocks: Vec::new(),
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
}

impl SyncingWallet for MockWallet {
    fn best_block(&self) -> WalletResult<(Id<GenBlock>, BlockHeight)> {
        Ok((self.get_best_block_id(), self.get_block_height()))
    }

    fn scan_blocks(
        &mut self,
        common_block_height: BlockHeight,
        blocks: Vec<Block>,
    ) -> WalletResult<()> {
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
            let _ = self.new_tip_tx.send(block.header().block_id());
        }

        log::debug!(
            "new block added to wallet: {}, block height: {}",
            self.get_best_block_id(),
            self.get_block_height()
        );

        Ok(())
    }

    fn update_median_time(&mut self, median_time: BlockTimestamp) -> WalletResult<()> {
        self.latest_median_time = median_time;
        Ok(())
    }

    fn best_block_unsynced_acc(&self) -> Option<(Id<GenBlock>, BlockHeight)> {
        None
    }

    fn scan_blocks_unsynced_acc(
        &mut self,
        _common_block_height: BlockHeight,
        _blocks: Vec<Block>,
    ) -> WalletResult<()> {
        Err(wallet::WalletError::NoUnsyncedAccount)
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

    async fn chainstate_info(&self) -> Result<ChainInfo, Self::Error> {
        Ok(self.tf.lock().unwrap().chainstate.info().unwrap())
    }
    async fn get_best_block_id(&self) -> Result<Id<GenBlock>, Self::Error> {
        unreachable!()
    }
    async fn get_block(&self, block_id: Id<Block>) -> Result<Option<Block>, Self::Error> {
        Ok(self.tf.lock().unwrap().chainstate.get_block(block_id).unwrap())
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

    async fn generate_block(
        &self,
        _input_data: GenerateBlockInputData,
        _transactions_hex: Option<Vec<SignedTransaction>>,
    ) -> Result<Block, Self::Error> {
        unreachable!()
    }
    async fn submit_block(&self, _block: Block) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn submit_transaction(&self, _tx: SignedTransaction) -> Result<(), Self::Error> {
        unreachable!()
    }

    async fn node_shutdown(&self) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn node_version(&self) -> Result<String, Self::Error> {
        unreachable!()
    }

    async fn p2p_connect(&self, _address: String) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn p2p_disconnect(&self, _peer_id: PeerId) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn p2p_get_peer_count(&self) -> Result<usize, Self::Error> {
        unreachable!()
    }
    async fn p2p_get_connected_peers(&self) -> Result<Vec<ConnectedPeer>, Self::Error> {
        unreachable!()
    }
    async fn p2p_add_reserved_node(&self, _address: String) -> Result<(), Self::Error> {
        unreachable!()
    }
    async fn p2p_remove_reserved_node(&self, _address: String) -> Result<(), Self::Error> {
        unreachable!()
    }

    async fn get_all_mempool_transactions(
        &self,
    ) -> Result<Vec<HexEncoded<SignedTransaction>>, Self::Error> {
        Ok(vec![])
    }
}

fn create_chain(node: &MockNode, rng: &mut (impl Rng + CryptoRng), parent: u64, count: usize) {
    let mut tf = node.tf.lock().unwrap();
    let parent_id = tf.chainstate.get_block_id_from_height(&parent.into()).unwrap().unwrap();
    tf.create_chain(&parent_id, count, rng).unwrap();
}

async fn wait_new_tip(node: &MockNode, new_tip_tx: &mut mpsc::UnboundedReceiver<Id<Block>>) {
    let expected_block_id = node.tf.lock().unwrap().best_block_id();
    let wait_fut = async move { while new_tip_tx.recv().await.unwrap() != expected_block_id {} };
    tokio::time::timeout(Duration::from_secs(60), wait_fut).await.unwrap();
}

fn run_sync(chain_config: Arc<ChainConfig>, node: MockNode, mut wallet: MockWallet) {
    tokio::spawn(async move {
        loop {
            let _ = sync_once(&chain_config, &node, &mut wallet).await;
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
    let (new_tip_tx, mut new_tip_rx) = mpsc::unbounded_channel();
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
    let (new_tip_tx, mut new_tip_rx) = mpsc::unbounded_channel();
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
    let (new_tip_tx, mut new_tip_rx) = mpsc::unbounded_channel();
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
