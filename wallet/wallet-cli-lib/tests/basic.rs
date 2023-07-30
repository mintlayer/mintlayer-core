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

use crate::cli_test_framework::{CliTestFramework, MNEMONIC};

#[rstest]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn wallet_cli_basic(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let test = CliTestFramework::setup(&mut rng).await;

    let output = test.run(&["nodeversion"]).await;
    assert_eq!(output, vec!["0.1.0"]);

    let output = test.run(&["bestblockheight"]).await;
    assert_eq!(output, vec!["0"]);

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

    // Start the wallet, create it, then close it, then shutdown
    let output = test.run(&[&format!("createwallet \"{file_name}\""), "closewallet"]).await;
    assert_eq!(output.len(), 2, "Unexpected output: {:?}", output);
    assert!(output[0].starts_with("New wallet created successfully\n"));
    assert_eq!(output[1], "Successfully closed the wallet.");

    // Start the wallet, open it, then close it, then shutdown
    let output = test.run(&[&format!("openwallet \"{file_name}\""), "closewallet"]).await;
    assert_eq!(output.len(), 2, "Unexpected output: {:?}", output);
    assert_eq!(output[0], "Wallet loaded successfully");
    assert_eq!(output[1], "Successfully closed the wallet.");

    test.shutdown().await;
}

#[rstest]
#[case(test_utils::random::Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn produce_blocks(#[case] seed: Seed) {
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

    // Create wallet
    let cmd1 = format!("createwallet \"{}\" \"{}\"", file_name, MNEMONIC);
    let output = test.run(&[&cmd1, "getbalance", "generateblocks 20"]).await;
    assert_eq!(output.len(), 3, "Unexpected output: {:?}", output);
    assert_eq!(output[0], "New wallet created successfully");
    assert_eq!(output[1], "Coins amount: 99960000");
    assert_eq!(output[2], "Success");

    test.shutdown().await;
}
