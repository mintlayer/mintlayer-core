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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staking_locked_wallet(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let test = CliTestFramework::setup(&mut rng).await;

    test.create_genesis_wallet();

    // It is not possible to start staking when the wallet is locked
    assert_eq!(
        test.exec("wallet-encrypt-private-keys Password123"),
        "Successfully encrypted the private keys of the wallet."
    );
    assert_eq!(
        test.exec("wallet-lock-private-keys"),
        "Success. The wallet is now locked."
    );
    assert_eq!(
        test.exec("staking-start"),
        "Wallet controller error: Wallet is locked"
    );

    // It is possible to start staking after the wallet is unlocked
    assert_eq!(
        test.exec("wallet-unlock-private-keys Password123"),
        "Success. The wallet is now unlocked."
    );
    assert_eq!(test.exec("staking-start"), "Staking started successfully");

    // It is not possible to lock the wallet while staking is running
    assert_eq!(
        test.exec("wallet-lock-private-keys"),
        "Wallet controller error: Cannot lock wallet because staking is running"
    );

    // It is possible to lock the wallet after staking is stopped
    assert_eq!(test.exec("staking-stop"), "Success");
    assert_eq!(
        test.exec("wallet-lock-private-keys"),
        "Success. The wallet is now locked."
    );

    test.shutdown().await;
}
