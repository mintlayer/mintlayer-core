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

use accounting::{
    DataDelta, DataDeltaUndo, DeltaAmountCollection, DeltaDataCollection, DeltaMapElement,
};
use common::primitives::{signed_amount::SignedAmount, Amount, H256};
use crypto::key::{KeyKind, PrivateKey};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crate::{
    pool::{
        delegation::DelegationData,
        delta::{data::PoSAccountingDeltaData, PoSAccountingDelta},
        pool_data::PoolData,
        storage::PoSAccountingDBMut,
    },
    storage::in_memory::InMemoryPoSAccounting,
    DelegationId, PoolId,
};

fn new_pool_id(v: u64) -> PoolId {
    PoolId::new(H256::from_low_u64_be(v))
}

fn new_delegation_id(v: u64) -> DelegationId {
    DelegationId::new(H256::from_low_u64_be(v))
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn merge_deltas_check_undo_check(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);

    let (_, pub_key1) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
    let data1 = PoSAccountingDeltaData {
        pool_data: DeltaDataCollection::from_iter(
            [(
                new_pool_id(1),
                DataDelta::Create(PoolData::new(pub_key1.clone(), Amount::from_atoms(100))),
            )]
            .into_iter(),
        ),
        pool_balances: DeltaAmountCollection::from_iter(
            [
                (new_pool_id(3), SignedAmount::from_atoms(300)),
                (new_pool_id(4), SignedAmount::from_atoms(400)),
            ]
            .into_iter(),
        ),
        pool_delegation_shares: DeltaAmountCollection::from_iter(
            [(
                (new_pool_id(5), new_delegation_id(6)),
                SignedAmount::from_atoms(100),
            )]
            .into_iter(),
        ),
        delegation_balances: DeltaAmountCollection::from_iter(
            [
                (new_delegation_id(5), SignedAmount::from_atoms(500)),
                (new_delegation_id(6), SignedAmount::from_atoms(600)),
            ]
            .into_iter(),
        ),
        delegation_data: DeltaDataCollection::from_iter(
            [(
                new_delegation_id(1),
                DataDelta::Create(DelegationData::new(new_pool_id(1), pub_key1.clone())),
            )]
            .into_iter(),
        ),
    };
    let mut delta1 = PoSAccountingDelta::from_data(&db, data1);

    let (_, pub_key2) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
    let data2 = PoSAccountingDeltaData {
        pool_data: DeltaDataCollection::from_iter(
            [
                (
                    new_pool_id(1),
                    DataDelta::Modify(
                        PoolData::new(pub_key1.clone(), Amount::from_atoms(100)),
                        PoolData::new(pub_key1.clone(), Amount::from_atoms(300)),
                    ),
                ),
                (
                    new_pool_id(10),
                    DataDelta::Create(PoolData::new(pub_key2.clone(), Amount::from_atoms(100))),
                ),
            ]
            .into_iter(),
        ),
        pool_balances: DeltaAmountCollection::from_iter(
            [
                (new_pool_id(3), SignedAmount::from_atoms(-300)),
                (new_pool_id(4), SignedAmount::from_atoms(50)),
            ]
            .into_iter(),
        ),
        pool_delegation_shares: DeltaAmountCollection::from_iter(
            [(
                (new_pool_id(5), new_delegation_id(6)),
                SignedAmount::from_atoms(50),
            )]
            .into_iter(),
        ),
        delegation_balances: DeltaAmountCollection::from_iter(
            [
                (new_delegation_id(8), SignedAmount::from_atoms(200)),
                (new_delegation_id(9), SignedAmount::from_atoms(300)),
            ]
            .into_iter(),
        ),
        delegation_data: DeltaDataCollection::from_iter(
            [(
                new_delegation_id(1),
                DataDelta::Delete(DelegationData::new(new_pool_id(1), pub_key1.clone())),
            )]
            .into_iter(),
        ),
    };
    let delta2 = PoSAccountingDelta::from_data(&db, data2);
    let delta2_origin_data = delta2.data().clone();

    let expected_data_after_merge = PoSAccountingDeltaData {
        pool_data: DeltaDataCollection::from_iter(
            [
                (
                    new_pool_id(1),
                    DataDelta::Create(PoolData::new(pub_key1.clone(), Amount::from_atoms(300))),
                ),
                (
                    new_pool_id(10),
                    DataDelta::Create(PoolData::new(pub_key2, Amount::from_atoms(100))),
                ),
            ]
            .into_iter(),
        ),
        pool_balances: DeltaAmountCollection::from_iter(
            [(new_pool_id(4), SignedAmount::from_atoms(450))].into_iter(),
        ),
        pool_delegation_shares: DeltaAmountCollection::from_iter(
            [(
                (new_pool_id(5), new_delegation_id(6)),
                SignedAmount::from_atoms(150),
            )]
            .into_iter(),
        ),
        delegation_balances: DeltaAmountCollection::from_iter(
            [
                (new_delegation_id(5), SignedAmount::from_atoms(500)),
                (new_delegation_id(6), SignedAmount::from_atoms(600)),
                (new_delegation_id(8), SignedAmount::from_atoms(200)),
                (new_delegation_id(9), SignedAmount::from_atoms(300)),
            ]
            .into_iter(),
        ),
        delegation_data: DeltaDataCollection::new(),
    };

    let undo_data = delta1.merge_with_delta(delta2.consume()).unwrap();
    assert_eq!(delta1.data(), &expected_data_after_merge);

    let expected_data_after_undo = PoSAccountingDeltaData {
        pool_data: DeltaDataCollection::from_iter(
            [(
                new_pool_id(1),
                DeltaMapElement::Delta(DataDelta::Create(PoolData::new(
                    pub_key1.clone(),
                    Amount::from_atoms(100),
                ))),
            )]
            .into_iter(),
        ),
        pool_balances: DeltaAmountCollection::from_iter(
            [
                (new_pool_id(3), SignedAmount::from_atoms(300)),
                (new_pool_id(4), SignedAmount::from_atoms(400)),
            ]
            .into_iter(),
        ),
        pool_delegation_shares: DeltaAmountCollection::from_iter(
            [(
                (new_pool_id(5), new_delegation_id(6)),
                SignedAmount::from_atoms(100),
            )]
            .into_iter(),
        ),
        delegation_balances: DeltaAmountCollection::from_iter(
            [
                (new_delegation_id(5), SignedAmount::from_atoms(500)),
                (new_delegation_id(6), SignedAmount::from_atoms(600)),
            ]
            .into_iter(),
        ),
        delegation_data: DeltaDataCollection::from_iter(
            [(
                new_delegation_id(1),
                DeltaMapElement::DeltaUndo(DataDeltaUndo::Create(DelegationData::new(
                    new_pool_id(1),
                    pub_key1,
                ))),
            )]
            .into_iter(),
        ),
    };

    delta1.undo_delta_merge(delta2_origin_data, undo_data).unwrap();
    assert_eq!(delta1.data(), &expected_data_after_undo);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn merge_store_with_delta_check_undo_check(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let (_, pub_key1) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
    let (_, pub_key2) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);

    let mut storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(
            new_pool_id(1),
            PoolData::new(pub_key1.clone(), Amount::from_atoms(100)),
        )]),
        BTreeMap::from([
            (new_pool_id(3), Amount::from_atoms(300)),
            (new_pool_id(4), Amount::from_atoms(400)),
        ]),
        BTreeMap::from([(
            (new_pool_id(5), new_delegation_id(6)),
            Amount::from_atoms(100),
        )]),
        BTreeMap::from([
            (new_delegation_id(5), Amount::from_atoms(500)),
            (new_delegation_id(6), Amount::from_atoms(600)),
        ]),
        BTreeMap::from([(
            new_delegation_id(1),
            DelegationData::new(new_pool_id(1), pub_key1.clone()),
        )]),
    );
    let original_storage = storage.clone();

    let (delta_origin, undo_data) = {
        let mut db = PoSAccountingDBMut::new_empty(&mut storage);

        let delta_data = PoSAccountingDeltaData {
            pool_data: DeltaDataCollection::from_iter(
                [
                    (
                        new_pool_id(1),
                        DataDelta::Modify(
                            PoolData::new(pub_key1.clone(), Amount::from_atoms(100)),
                            PoolData::new(pub_key1.clone(), Amount::from_atoms(300)),
                        ),
                    ),
                    (
                        new_pool_id(10),
                        DataDelta::Create(PoolData::new(pub_key2.clone(), Amount::from_atoms(100))),
                    ),
                ]
                .into_iter(),
            ),
            pool_balances: DeltaAmountCollection::from_iter(
                [
                    (new_pool_id(3), SignedAmount::from_atoms(-300)),
                    (new_pool_id(4), SignedAmount::from_atoms(50)),
                ]
                .into_iter(),
            ),
            pool_delegation_shares: DeltaAmountCollection::from_iter(
                [(
                    (new_pool_id(5), new_delegation_id(6)),
                    SignedAmount::from_atoms(50),
                )]
                .into_iter(),
            ),
            delegation_balances: DeltaAmountCollection::from_iter(
                [
                    (new_delegation_id(8), SignedAmount::from_atoms(200)),
                    (new_delegation_id(9), SignedAmount::from_atoms(300)),
                ]
                .into_iter(),
            ),
            delegation_data: DeltaDataCollection::from_iter(
                [(
                    new_delegation_id(1),
                    DataDelta::Delete(DelegationData::new(new_pool_id(1), pub_key1.clone())),
                )]
                .into_iter(),
            ),
        };
        let delta = PoSAccountingDelta::from_data(&db, delta_data);
        let delta_origin = delta.data().clone();

        let undo_data = db.merge_with_delta(delta.consume()).unwrap();
        (delta_origin, undo_data)
    };

    let expected_storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([
            (
                new_pool_id(1),
                PoolData::new(pub_key1, Amount::from_atoms(300)),
            ),
            (
                new_pool_id(10),
                PoolData::new(pub_key2, Amount::from_atoms(100)),
            ),
        ]),
        BTreeMap::from([(new_pool_id(4), Amount::from_atoms(450))]),
        BTreeMap::from([(
            (new_pool_id(5), new_delegation_id(6)),
            Amount::from_atoms(150),
        )]),
        BTreeMap::from([
            (new_delegation_id(5), Amount::from_atoms(500)),
            (new_delegation_id(6), Amount::from_atoms(600)),
            (new_delegation_id(8), Amount::from_atoms(200)),
            (new_delegation_id(9), Amount::from_atoms(300)),
        ]),
        BTreeMap::from_iter([]),
    );

    assert_eq!(storage, expected_storage);

    let mut db = PoSAccountingDBMut::new_empty(&mut storage);
    db.undo_merge_with_delta(delta_origin, undo_data).unwrap();
    assert_eq!(storage, original_storage);
}

// TODO: increase test coverage (consider using proptest)
