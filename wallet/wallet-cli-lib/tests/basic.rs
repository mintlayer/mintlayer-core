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
        .exec(&format!("wallet-create \"{file_name}\" store-seed-phrase"))
        .starts_with("New wallet created successfully\n"));
    assert_eq!(test.exec("wallet-close"), "Successfully closed the wallet.");

    assert_eq!(
        test.exec(&format!("wallet-open \"{file_name}\"")),
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

    assert_eq!(test.exec("address-balance"), "Coins amount: 99960000");
    assert_eq!(test.exec("node-generate-blocks 20"), "Success");

    test.shutdown().await;
}
