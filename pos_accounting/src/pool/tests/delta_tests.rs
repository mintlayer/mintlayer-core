use std::collections::BTreeMap;

use accounting::{DataDelta, DeltaAmountCollection, DeltaDataCollection};
use common::primitives::{signed_amount::SignedAmount, Amount, H256};
use crypto::key::{KeyKind, PrivateKey};

use crate::{
    pool::{
        delegation::DelegationData,
        delta::{data::PoSAccountingDeltaData, PoSAccountingDelta},
        pool_data::PoolData,
        storage::PoSAccountingDBMut,
    },
    storage::in_memory::InMemoryPoSAccounting,
};

#[test]
fn check_merge_deltas() {
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);

    let (_, pub_key1) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let data1 = PoSAccountingDeltaData {
        pool_data: DeltaDataCollection::from_iter(
            [(
                H256::from_low_u64_be(1),
                DataDelta::Create(Box::new(PoolData::new(
                    pub_key1.clone(),
                    Amount::from_atoms(100),
                ))),
            )]
            .into_iter(),
        ),
        pool_balances: DeltaAmountCollection::from_iter(
            [
                (H256::from_low_u64_be(3), SignedAmount::from_atoms(100)),
                (H256::from_low_u64_be(4), SignedAmount::from_atoms(100)),
            ]
            .into_iter(),
        ),
        pool_delegation_shares: DeltaAmountCollection::from_iter(
            [(
                (H256::from_low_u64_be(5), H256::from_low_u64_be(6)),
                SignedAmount::from_atoms(100),
            )]
            .into_iter(),
        ),
        delegation_balances: DeltaAmountCollection::from_iter(
            [
                (H256::from_low_u64_be(5), SignedAmount::from_atoms(100)),
                (H256::from_low_u64_be(6), SignedAmount::from_atoms(100)),
            ]
            .into_iter(),
        ),
        delegation_data: DeltaDataCollection::from_iter(
            [(
                H256::from_low_u64_be(1),
                DataDelta::Create(Box::new(DelegationData::new(
                    H256::from_low_u64_be(1),
                    pub_key1.clone(),
                ))),
            )]
            .into_iter(),
        ),
    };
    let mut delta1 = PoSAccountingDelta::from_data(&db, data1);
    let delta1_origin_data = delta1.data().clone();

    let (_, pub_key2) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let data2 = PoSAccountingDeltaData {
        pool_data: DeltaDataCollection::from_iter(
            [
                (
                    H256::from_low_u64_be(1),
                    DataDelta::Modify(Box::new(PoolData::new(
                        pub_key1.clone(),
                        Amount::from_atoms(300),
                    ))),
                ),
                (
                    H256::from_low_u64_be(10),
                    DataDelta::Create(Box::new(PoolData::new(
                        pub_key2.clone(),
                        Amount::from_atoms(100),
                    ))),
                ),
            ]
            .into_iter(),
        ),
        pool_balances: DeltaAmountCollection::from_iter(
            [
                (H256::from_low_u64_be(3), SignedAmount::from_atoms(50)),
                (H256::from_low_u64_be(4), SignedAmount::from_atoms(-50)),
            ]
            .into_iter(),
        ),
        pool_delegation_shares: DeltaAmountCollection::from_iter(
            [(
                (H256::from_low_u64_be(5), H256::from_low_u64_be(6)),
                SignedAmount::from_atoms(50),
            )]
            .into_iter(),
        ),
        delegation_balances: DeltaAmountCollection::from_iter(
            [
                (H256::from_low_u64_be(8), SignedAmount::from_atoms(100)),
                (H256::from_low_u64_be(9), SignedAmount::from_atoms(100)),
            ]
            .into_iter(),
        ),
        delegation_data: DeltaDataCollection::from_iter(
            [(H256::from_low_u64_be(1), DataDelta::Delete)].into_iter(),
        ),
    };
    let delta2 = PoSAccountingDelta::from_data(&db, data2);

    let expected_data = PoSAccountingDeltaData {
        pool_data: DeltaDataCollection::from_iter(
            [
                (
                    H256::from_low_u64_be(1),
                    DataDelta::Create(Box::new(PoolData::new(
                        pub_key1.clone(),
                        Amount::from_atoms(300),
                    ))),
                ),
                (
                    H256::from_low_u64_be(10),
                    DataDelta::Create(Box::new(PoolData::new(
                        pub_key2.clone(),
                        Amount::from_atoms(100),
                    ))),
                ),
            ]
            .into_iter(),
        ),
        pool_balances: DeltaAmountCollection::from_iter(
            [
                (H256::from_low_u64_be(3), SignedAmount::from_atoms(150)),
                (H256::from_low_u64_be(4), SignedAmount::from_atoms(50)),
            ]
            .into_iter(),
        ),
        pool_delegation_shares: DeltaAmountCollection::from_iter(
            [(
                (H256::from_low_u64_be(5), H256::from_low_u64_be(6)),
                SignedAmount::from_atoms(150),
            )]
            .into_iter(),
        ),
        delegation_balances: DeltaAmountCollection::from_iter(
            [
                (H256::from_low_u64_be(5), SignedAmount::from_atoms(100)),
                (H256::from_low_u64_be(6), SignedAmount::from_atoms(100)),
                (H256::from_low_u64_be(8), SignedAmount::from_atoms(100)),
                (H256::from_low_u64_be(9), SignedAmount::from_atoms(100)),
            ]
            .into_iter(),
        ),
        delegation_data: DeltaDataCollection::from_iter([]),
    };

    let undo_data = delta1.merge_with_delta(delta2.consume()).unwrap();
    assert_eq!(delta1.data(), &expected_data);

    delta1.undo_delta_merge(undo_data).unwrap();
    assert_eq!(delta1.data(), &delta1_origin_data);
}

#[test]
fn check_merge_values_with_deltas() {
    let (_, pub_key1) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let (_, pub_key2) = PrivateKey::new(KeyKind::RistrettoSchnorr);

    let mut storage = InMemoryPoSAccounting {
        pool_data: BTreeMap::from([(
            H256::from_low_u64_be(1),
            PoolData::new(pub_key1.clone(), Amount::from_atoms(100)),
        )]),
        pool_balances: BTreeMap::from([
            (H256::from_low_u64_be(3), Amount::from_atoms(100)),
            (H256::from_low_u64_be(4), Amount::from_atoms(100)),
        ]),
        pool_delegation_shares: BTreeMap::from([(
            (H256::from_low_u64_be(5), H256::from_low_u64_be(6)),
            Amount::from_atoms(100),
        )]),
        delegation_balances: BTreeMap::from([
            (H256::from_low_u64_be(5), Amount::from_atoms(100)),
            (H256::from_low_u64_be(6), Amount::from_atoms(100)),
        ]),
        delegation_data: BTreeMap::from([(
            H256::from_low_u64_be(1),
            DelegationData::new(H256::from_low_u64_be(1), pub_key1.clone()),
        )]),
    };
    let original_storage = storage.clone();

    let undo_data = {
        let mut db = PoSAccountingDBMut::new_empty(&mut storage);

        let delta_data = PoSAccountingDeltaData {
            pool_data: DeltaDataCollection::from_iter(
                [
                    (
                        H256::from_low_u64_be(1),
                        DataDelta::Modify(Box::new(PoolData::new(
                            pub_key1.clone(),
                            Amount::from_atoms(300),
                        ))),
                    ),
                    (
                        H256::from_low_u64_be(10),
                        DataDelta::Create(Box::new(PoolData::new(
                            pub_key2.clone(),
                            Amount::from_atoms(100),
                        ))),
                    ),
                ]
                .into_iter(),
            ),
            pool_balances: DeltaAmountCollection::from_iter(
                [
                    (H256::from_low_u64_be(3), SignedAmount::from_atoms(50)),
                    (H256::from_low_u64_be(4), SignedAmount::from_atoms(-50)),
                ]
                .into_iter(),
            ),
            pool_delegation_shares: DeltaAmountCollection::from_iter(
                [(
                    (H256::from_low_u64_be(5), H256::from_low_u64_be(6)),
                    SignedAmount::from_atoms(50),
                )]
                .into_iter(),
            ),
            delegation_balances: DeltaAmountCollection::from_iter(
                [
                    (H256::from_low_u64_be(8), SignedAmount::from_atoms(100)),
                    (H256::from_low_u64_be(9), SignedAmount::from_atoms(100)),
                ]
                .into_iter(),
            ),
            delegation_data: DeltaDataCollection::from_iter(
                [(H256::from_low_u64_be(1), DataDelta::Delete)].into_iter(),
            ),
        };
        let delta = PoSAccountingDelta::from_data(&db, delta_data);

        db.merge_with_delta(delta.consume()).unwrap()
    };

    let expected_storage = InMemoryPoSAccounting {
        pool_data: BTreeMap::from([
            (
                H256::from_low_u64_be(1),
                PoolData::new(pub_key1.clone(), Amount::from_atoms(300)),
            ),
            (
                H256::from_low_u64_be(10),
                PoolData::new(pub_key2.clone(), Amount::from_atoms(100)),
            ),
        ]),
        pool_balances: BTreeMap::from([
            (H256::from_low_u64_be(3), Amount::from_atoms(150)),
            (H256::from_low_u64_be(4), Amount::from_atoms(50)),
        ]),
        pool_delegation_shares: BTreeMap::from([(
            (H256::from_low_u64_be(5), H256::from_low_u64_be(6)),
            Amount::from_atoms(150),
        )]),
        delegation_balances: BTreeMap::from([
            (H256::from_low_u64_be(5), Amount::from_atoms(100)),
            (H256::from_low_u64_be(6), Amount::from_atoms(100)),
            (H256::from_low_u64_be(8), Amount::from_atoms(100)),
            (H256::from_low_u64_be(9), Amount::from_atoms(100)),
        ]),
        delegation_data: BTreeMap::from_iter([]),
    };

    assert_eq!(storage, expected_storage);

    let mut db = PoSAccountingDBMut::new_empty(&mut storage);
    db.undo_merge_with_delta(undo_data).unwrap();
    assert_eq!(storage, original_storage);
}

// TODO: increase test coverage (consider using proptest)
