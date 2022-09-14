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
fn check_merge_delta() {
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
    let delta2_origin_data = delta2.data().clone();

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

    delta1.undo_delta_merge(delta2_origin_data, undo_data).unwrap();
    assert_eq!(delta1.data(), &delta1_origin_data);
}

// TODO: increase test coverage (consider using proptest)
