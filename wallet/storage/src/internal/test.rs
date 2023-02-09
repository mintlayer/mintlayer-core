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
use common::chain::tokens::OutputValue;
use common::chain::{Destination, OutPointSourceId, OutputPurpose, TxOutput};
use common::primitives::{Amount, Id, H256};
use crypto::key::{KeyKind, PrivateKey};
use crypto::random::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

impl Store<storage_sqlite::Sqlite> {
    /// Create a default storage (mostly for testing, may want to remove this later)
    pub fn new_in_memory() -> crate::Result<Self> {
        Self::new(storage_sqlite::Sqlite::new_in_memory())
    }
}

type TestStore = Store<storage_sqlite::Sqlite>;

#[test]
fn test_storage_get_default_version_in_tx() {
    utils::concurrency::model(|| {
        let store = TestStore::new_in_memory().unwrap();
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
fn utxo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut db_interface = TestStore::new_in_memory().unwrap();

    // generate a utxo and outpoint
    let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let output = TxOutput::new(
        OutputValue::Coin(Amount::from_atoms(rng.gen_range(0..(u128::MAX - 1)))),
        OutputPurpose::Transfer(Destination::PublicKey(pub_key)),
    );
    let utxo = Utxo::new_for_mempool(output, false);
    let outpoint = OutPoint::new(
        OutPointSourceId::Transaction(Id::new(H256::random_using(&mut rng))),
        0,
    );

    assert!(db_interface.set_utxo(&outpoint, utxo.clone()).is_ok());
    assert_eq!(db_interface.get_utxo(&outpoint), Ok(Some(utxo)));
    assert!(db_interface.del_utxo(&outpoint).is_ok());
    assert_eq!(db_interface.get_utxo(&outpoint), Ok(None));
}
