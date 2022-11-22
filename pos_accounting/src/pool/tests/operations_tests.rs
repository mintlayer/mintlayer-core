// Copyright (c) 2022 RBB S.r.l
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

use std::collections::BTreeMap;

use common::{
    chain::{OutPoint, OutPointSourceId},
    primitives::{Amount, Id, H256},
};
use crypto::key::{KeyKind, PrivateKey};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crate::{
    pool::{
        delta::PoSAccountingDelta, pool_data::PoolData, storage::PoSAccountingDBMut,
        view::FlushablePoSAccountingView,
    },
    storage::in_memory::InMemoryPoSAccounting,
    PoSAccountingData, PoSAccountingOperations,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_decomission_pool_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);

    let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    );
    let pledge_amount = Amount::from_atoms(100);
    let (pool_id, _) = db.create_pool(&outpoint, pledge_amount, pub_key.clone()).unwrap();

    let mut delta1 = PoSAccountingDelta::from_borrowed_parent(&db);
    let undo = delta1.decommission_pool(pool_id).unwrap();

    let mut delta2 = PoSAccountingDelta::from_borrowed_parent(&delta1);
    delta2.undo(undo).unwrap();

    delta1.batch_write_delta(delta2.consume()).unwrap();
    db.batch_write_delta(delta1.consume()).unwrap();

    let expected_data = PoSAccountingData {
        pool_data: BTreeMap::from([(pool_id, PoolData::new(pub_key, pledge_amount))]),
        pool_balances: BTreeMap::from([(pool_id, pledge_amount)]),
        pool_delegation_shares: Default::default(),
        delegation_balances: Default::default(),
        delegation_data: Default::default(),
    };
    assert_eq!(storage.dump(), expected_data);
}
