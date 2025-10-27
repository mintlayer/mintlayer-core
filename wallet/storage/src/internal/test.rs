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
use crate::{
    DefaultBackend, TransactionRwLocked, TransactionRwUnlocked, WalletStorageReadLocked,
    WalletStorageReadUnlocked, WalletStorageWriteLocked, WalletStorageWriteUnlocked,
};

use crypto::key::extended::{ExtendedKeyKind, ExtendedPrivateKey};
use crypto::vrf::ExtendedVRFPrivateKey;
use randomness::{CryptoRng, Rng};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};
use wallet_types::keys::RootKeys;

fn gen_random_password(rng: &mut (impl Rng + CryptoRng)) -> String {
    (0..rng.gen_range(1..100)).map(|_| rng.gen::<char>()).collect()
}

#[test]
fn storage_get_default_version_in_tx() {
    utils::concurrency::model(|| {
        let mut store = Store::new(DefaultBackend::new_in_memory()).unwrap();

        let mut db_tx = store.transaction_rw(None).unwrap();
        db_tx.set_storage_version(1).unwrap();
        db_tx.commit().unwrap();

        let vtx = store.transaction_ro().unwrap().get_storage_version().unwrap();
        assert_eq!(vtx, 1, "Default storage version wrong");
    })
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn compare_encrypt_and_decrypt_root_key(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut store = Store::new(DefaultBackend::new_in_memory()).unwrap();
        let (xpriv_key, _xpub_key) =
            ExtendedPrivateKey::new_from_rng(&mut rng, ExtendedKeyKind::Secp256k1Schnorr);
        let seed_bytes: Vec<u8> = (0..64).map(|_| rng.gen::<u8>()).collect();
        let vrf_key = ExtendedVRFPrivateKey::new_master(
            seed_bytes.as_slice(),
            crypto::vrf::VRFKeyKind::Schnorrkel,
        )
        .unwrap();
        let key_content = RootKeys {
            root_key: xpriv_key,
            root_vrf_key: vrf_key,
        };
        {
            let mut db_tx = store.transaction_rw_unlocked(None).unwrap();
            db_tx.set_root_key(&key_content).unwrap();
            db_tx.commit().unwrap();
        }

        {
            let db_tx = store.transaction_ro_unlocked().unwrap();
            // check it was written correctly
            assert_eq!(db_tx.get_root_key().unwrap().unwrap(), key_content);
        }

        // now encrypt the keys with a new password

        let new_password = gen_random_password(&mut rng);
        store.encrypt_private_keys(&Some(new_password.clone())).unwrap();

        {
            let db_tx = store.transaction_ro_unlocked().unwrap();
            // check it can decrypt it correctly
            assert_eq!(db_tx.get_root_key().unwrap().unwrap(), key_content);
        }

        // after locking the store can't operate on the root keys
        store.lock_private_keys().unwrap();
        {
            let error = store.transaction_ro_unlocked();
            assert_eq!(error.err(), Some(crate::Error::WalletLocked));
        }
        {
            let error = store.transaction_rw_unlocked(None);
            assert_eq!(error.err(), Some(crate::Error::WalletLocked));
        }

        // fail to unlock with the wrong password
        let mut wrong_password = gen_random_password(&mut rng);
        while wrong_password == new_password {
            wrong_password = gen_random_password(&mut rng);
        }
        assert_ne!(new_password, wrong_password);

        let error = store.unlock_private_keys(&wrong_password);
        assert_eq!(error, Err(crate::Error::WalletInvalidPassword));

        // after unlocking with the right key we can get the root keys again
        store.unlock_private_keys(&new_password).unwrap();
        {
            let db_tx = store.transaction_ro_unlocked().unwrap();

            // check it can decrypt it correctly
            assert_eq!(db_tx.get_root_key().unwrap().unwrap(), key_content);
        }
    })
}
