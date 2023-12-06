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

mod utils;

use rstest::rstest;

use common::primitives::BlockHeight;
use test_utils::random::{make_seedable_rng, Seed};
use utils::ACCOUNT0_ARG;
use wallet_rpc_lib::WalletRpcClient;

#[rstest]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn startup_shutdown(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = utils::TestFramework::start(&mut rng).await;

    let wallet = tf.handle();
    assert!(wallet.is_running());

    let rpc_client = tf.rpc_client();
    let genesis_id = tf.wallet_service.chain_config().genesis_block_id();
    let best_block = rpc_client.best_block(Default::default()).await.unwrap();
    assert_eq!(best_block.id, genesis_id);
    assert_eq!(best_block.height, BlockHeight::new(0));

    tf.stop().await;
    assert!(!wallet.is_running());
}

#[rstest]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn send_coins(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tf = utils::TestFramework::start(&mut rng).await;

    let wallet_rpc = tf.rpc_client();

    let best_block = wallet_rpc.best_block(Default::default()).await.unwrap();
    assert_eq!(best_block.height, BlockHeight::new(0));

    let new_addr = wallet_rpc.issue_address(ACCOUNT0_ARG).await.unwrap();
    let balances = wallet_rpc.get_balance(ACCOUNT0_ARG).await.unwrap();
    logging::log::warn!("{new_addr:?}, {balances:?}");

    tf.stop().await;
}
