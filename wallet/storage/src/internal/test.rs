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
use crate::DefaultBackend;
use common::chain::tokens::OutputValue;
use common::chain::{Destination, OutPoint, OutPointSourceId, TxOutput};
use common::primitives::{Amount, Id, H256};
use crypto::key::extended::{ExtendedKeyKind, ExtendedPrivateKey};
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

#[test]
fn storage_get_default_version_in_tx() {
    utils::concurrency::model(|| {
        let mut store = Store::new(DefaultBackend::new_in_memory()).unwrap();
        store.set_storage_version(1).unwrap();
        let vtx = store.transaction_ro().unwrap().get_storage_version().unwrap();
        let vst = store.get_storage_version().unwrap();
        assert_eq!(vtx, 1, "Default storage version wrong");
        assert_eq!(vtx, vst, "Transaction and non-transaction inconsistency");
    })
}

#[cfg(not(loom))]
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn read_write_utxo_in_db_transaction(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut db_interface = Store::new(DefaultBackend::new_in_memory()).unwrap();

    // generate an account id
    let account_id = AccountId::new_from_xpub(
        &ExtendedPrivateKey::new_from_rng(&mut rng, ExtendedKeyKind::Secp256k1Schnorr).1,
    );

    // generate a utxo and outpoint
    let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let output = TxOutput::Transfer(
        OutputValue::Coin(Amount::from_atoms(rng.gen_range(0..(u128::MAX - 1)))),
        Destination::PublicKey(pub_key),
    );
    let utxo = Utxo::new_for_mempool(output);
    let outpoint = OutPoint::new(
        OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng))),
        0,
    );

    let account_outpoint_id = AccountOutPointId::new(account_id, outpoint);

    assert!(db_interface.set_utxo(&account_outpoint_id, utxo.clone()).is_ok());
    assert_eq!(db_interface.get_utxo(&account_outpoint_id), Ok(Some(utxo)));
    assert!(db_interface.del_utxo(&account_outpoint_id).is_ok());
    assert_eq!(db_interface.get_utxo(&account_outpoint_id), Ok(None));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn compare_encrypt_and_decrypt_root_key(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut store = Store::new(DefaultBackend::new_in_memory()).unwrap();
        let (xpriv_key, xpub_key) =
            ExtendedPrivateKey::new_from_rng(&mut rng, ExtendedKeyKind::Secp256k1Schnorr);
        let key_id = RootKeyId::from(xpub_key);
        let key_content = RootKeyContent::from(xpriv_key);
        store.set_root_key(&key_id, &key_content).unwrap();

        // check it was writen correctly
        assert_eq!(store.get_root_key(&key_id).unwrap().unwrap(), key_content);

        // now encrypt the keys with a new password

        let new_password = gen_random_password(&mut rng);
        store.encrypt_private_keys(&new_password).unwrap();

        // check it can decrypt it correctly
        assert_eq!(store.get_root_key(&key_id).unwrap().unwrap(), key_content);

        // after locking the store can't operate on the root keys
        store.lock_private_keys();

        let error = store.get_root_key(&key_id);
        assert_eq!(error, Err(crate::Error::WalletLocked()));
        let error = store.get_all_root_keys();
        assert_eq!(error, Err(crate::Error::WalletLocked()));
        let error = store.set_root_key(&key_id, &key_content);
        assert_eq!(error, Err(crate::Error::WalletLocked()));
        let error = store.del_root_key(&key_id);
        assert_eq!(error, Err(crate::Error::WalletLocked()));

        // fail to unlock with the wrong password
        let mut wrong_password = gen_random_password(&mut rng);
        while wrong_password == new_password {
            wrong_password = gen_random_password(&mut rng);
        }
        assert_ne!(new_password, wrong_password);

        let error = store.unlock_private_keys(&wrong_password);
        assert_eq!(error, Err(crate::Error::WalletInvalidPassword()));

        // after unlocking with the right key we can get the root keys again
        store.unlock_private_keys(&new_password).unwrap();

        // check it can decrypt it correctly
        assert_eq!(store.get_root_key(&key_id).unwrap().unwrap(), key_content);
    })
}

fn gen_random_password(rng: &mut (impl Rng + CryptoRng)) -> Option<String> {
    let new_password: String = (0..rng.gen_range(0..100)).map(|_| rng.gen::<char>()).collect();
    if new_password.is_empty() {
        Some(new_password)
    } else {
        None
    }
}
