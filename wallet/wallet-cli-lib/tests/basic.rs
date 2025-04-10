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

mod cli_test_framework;

use randomness::Rng;

use common::{address::Address, chain::PoolId, primitives::H256};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crate::cli_test_framework::CliTestFramework;

#[rstest]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn wallet_cli_basic(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test = CliTestFramework::setup(&mut rng).await;

    let output = test.exec("node-version");
    assert_eq!(output, env!("CARGO_PKG_VERSION"));

    let output = test.exec("node-best-block-height");
    assert_eq!(output, "0");

    test.shutdown().await;
}

#[rstest]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn wallet_cli_file(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test = CliTestFramework::setup(&mut rng).await;

    // Use dir name with spaces to make sure quoting works as expected
    let file_name = test
        .test_root
        .fresh_test_dir("wallet dir")
        .as_ref()
        .join("wallet1")
        .to_str()
        .unwrap()
        .to_owned();

    assert!(test
        .exec(&format!(
            "wallet-create software \"{file_name}\" store-seed-phrase"
        ))
        .starts_with("New wallet created successfully\n"));
    assert_eq!(test.exec("wallet-close"), "Successfully closed the wallet.");

    assert_eq!(
        test.exec(&format!("wallet-open software \"{file_name}\"")),
        "Wallet loaded successfully"
    );
    assert_eq!(test.exec("wallet-close"), "Successfully closed the wallet.");

    test.shutdown().await;
}

#[rstest]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn produce_blocks(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let test = CliTestFramework::setup(&mut rng).await;

    test.create_genesis_wallet();

    assert_eq!(test.exec("account-balance"), "Coins amount: 99960000");
    assert_eq!(test.exec("node-generate-blocks 20"), "Success");

    test.shutdown().await;
}

#[rstest]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn produce_blocks_decommission_genesis_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let test = CliTestFramework::setup(&mut rng).await;

    test.create_genesis_wallet();

    assert_eq!(test.exec("account-balance"), "Coins amount: 99960000");

    // create a new pool
    let address = test.exec("address-new");
    assert!(test
        .exec(&format!(
            "staking-create-pool 40000 {} 0.{} {}",
            rng.gen_range(0..100),
            rng.gen_range(1..100),
            address,
        ),)
        .contains("The transaction was submitted successfully with ID"));
    // create some blocks
    assert_eq!(test.exec("node-generate-blocks 20"), "Success");

    // create a new account and a new pool
    assert_eq!(
        test.exec("account-create"),
        "Success, the new account index is: 1"
    );
    assert_eq!(test.exec("account-select 1"), "Success");
    let acc2_address = test.exec("address-new");
    assert_eq!(test.exec("account-select 0"), "Success");
    assert!(test
        .exec(&format!("address-send {} 50000", acc2_address))
        .contains("The transaction was submitted successfully with ID"));
    // create a block
    assert_eq!(test.exec("node-generate-blocks 1"), "Success");

    assert_eq!(test.exec("account-select 1"), "Success");
    assert!(test
        .exec(&format!(
            "staking-create-pool 40000 {} 0.{} {}",
            rng.gen_range(0..100),
            rng.gen_range(1..100),
            address,
        ),)
        .contains("The transaction was submitted successfully with ID"));
    assert_eq!(test.exec("account-select 0"), "Success");

    // create some blocks
    assert_eq!(test.exec("node-generate-blocks 1"), "Success");

    // create some blocks with the other pool
    assert_eq!(test.exec("account-select 1"), "Success");
    assert_eq!(test.exec("node-generate-blocks 1"), "Success");

    // create the decommission request
    assert_eq!(test.exec("account-select 0"), "Success");
    let address = test.exec("address-new");
    let pool_id: PoolId = H256::zero().into();
    let output = test.exec(&format!(
        "staking-decommission-pool-request {} {address}",
        Address::new(&test.chain_config, pool_id).unwrap(),
    ));
    let req = output.lines().nth(2).unwrap();

    assert_eq!(test.exec("wallet-close"), "Successfully closed the wallet.");

    test.create_genesis_cold_wallet();
    let output = test.exec(&format!("account-sign-raw-transaction {req}"));
    let signed_tx = output.lines().nth(2).unwrap();
    assert_eq!(test.exec("wallet-close"), "Successfully closed the wallet.");

    // submit the tx
    test.create_genesis_wallet();
    assert_eq!(test.exec("wallet-sync"), "Success");
    assert!(test
        .exec(&format!("node-submit-transaction {signed_tx}"))
        .contains("The transaction was submitted successfully with ID"));

    // stake with the other acc
    assert_eq!(test.exec("account-select 1"), "Success");
    assert_eq!(test.exec("node-generate-blocks 10"), "Success");

    // stake with the first acc
    assert_eq!(test.exec("account-select 0"), "Success");
    assert!(test.exec("account-balance").starts_with("Coins amount: 99869999"));
    assert!(test.exec("account-balance locked").starts_with("Coins amount: 44444"));
    assert_eq!(test.exec("node-generate-blocks 2"), "Success");

    test.shutdown().await;
}
