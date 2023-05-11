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

use super::*;
use common::chain::config::create_regtest;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[test]
fn wallet_creation_in_memory() {
    let chain_config = Arc::new(create_regtest());
    let db = open_or_create_wallet_in_memory().unwrap();

    match Wallet::load_wallet(chain_config.clone(), db.clone()) {
        Ok(_) => panic!("Wallet loading should fail"),
        Err(err) => assert_eq!(err, WalletError::WalletNotInitialized),
    }

    let wallet = Wallet::new_wallet(chain_config.clone(), db.clone(), MNEMONIC, None);
    assert!(wallet.is_ok());
    drop(wallet);

    let wallet = Wallet::load_wallet(chain_config, db);
    assert!(wallet.is_ok());
}
