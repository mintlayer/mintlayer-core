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
use crate::key_chain::{MasterKeyChain, LOOKAHEAD_SIZE};
use common::chain::config::create_mainnet;
use crypto::key::secp256k1::Secp256k1PublicKey;
use rstest::rstest;
use wallet_storage::{DefaultBackend, Store, TransactionRwUnlocked, Transactional};
use wallet_types::{account_info::DEFAULT_ACCOUNT_INDEX, seed_phrase::StoreSeedPhrase};

// TODO: More tests

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

#[rstest]
#[case("03bf6f8d52dade77f95e9c6c9488fd8492a99c09ff23095caffb2e6409d1746ade")]
#[case("035df5d551bac1d61a5473615a70eb17b2f4ccbf7e354166639428941e4dbbcd81")]
#[case("030d1d07a8e45110d14f4e2c8623e8db556c11a90c0aac6be9a88f2464e446ee95")]
fn check_mine_methods(#[case] public: &str) {
    let chain_config = Arc::new(create_mainnet());
    let db = Arc::new(Store::new(DefaultBackend::new_in_memory()).unwrap());
    let mut db_tx = db.transaction_rw_unlocked(None).unwrap();

    let master_key_chain = MasterKeyChain::new_from_mnemonic(
        chain_config,
        &mut db_tx,
        MNEMONIC,
        None,
        StoreSeedPhrase::DoNotStore,
    )
    .unwrap();
    let mut key_chain = master_key_chain
        .create_account_key_chain(&mut db_tx, DEFAULT_ACCOUNT_INDEX, LOOKAHEAD_SIZE)
        .unwrap();
    key_chain.top_up_all(&mut db_tx).unwrap();
    db_tx.commit().unwrap();

    // This public key should belong to the key chain
    let pk: PublicKey =
        Secp256k1PublicKey::from_bytes(&hex::decode(public).unwrap()).unwrap().into();
    let pkh = PublicKeyHash::from(&pk);
    let pk_destination = Destination::PublicKey(pk.clone());
    let addr_destination = Destination::PublicKeyHash(pkh);

    assert!(key_chain.is_public_key_mine(&pk));
    assert!(key_chain.is_public_key_hash_mine(&pkh));
    assert!(key_chain.is_destination_mine(&addr_destination));
    assert!(key_chain.is_destination_mine(&pk_destination));
    assert!(key_chain.has_private_key_for_destination(&addr_destination));
    assert!(key_chain.has_private_key_for_destination(&pk_destination));
}
