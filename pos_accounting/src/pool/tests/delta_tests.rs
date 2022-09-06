use common::{
    chain::{OutPoint, OutPointSourceId},
    primitives::{signed_amount::SignedAmount, Amount, Id, H256},
};
use crypto::key::{KeyKind, PrivateKey};

use crate::{
    pool::{
        delegation::DelegationData,
        delta::{
            data::PoSAccountingDeltaData,
            delta_amount_collection::DeltaAmountCollection,
            delta_data_collection::{DataDelta, DeltaDataCollection},
            PoSAccountingDelta,
        },
        operations::{PoSAccountingOperatorWrite, PoSAccountingUndo},
        pool_data::PoolData,
        storage::PoSAccountingDBMut,
        view::PoSAccountingView,
    },
    storage::in_memory::InMemoryPoSAccounting,
};

#[test]
fn check_merge_delta() {
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);

    let (_, pub_key1) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let data1 = PoSAccountingDeltaData {
        pool_data: DeltaDataCollection::from_data([(
            H256::from_low_u64_be(1),
            DataDelta::Create(Box::new(PoolData::new(
                pub_key1.clone(),
                Amount::from_atoms(100),
            ))),
        )]),
        pool_balances: DeltaAmountCollection::from_data([
            (H256::from_low_u64_be(3), SignedAmount::from_atoms(100)),
            (H256::from_low_u64_be(4), SignedAmount::from_atoms(100)),
        ]),
        pool_delegation_shares: DeltaAmountCollection::from_data([(
            (H256::from_low_u64_be(5), H256::from_low_u64_be(6)),
            SignedAmount::from_atoms(100),
        )]),
        delegation_balances: DeltaAmountCollection::from_data([
            (H256::from_low_u64_be(5), SignedAmount::from_atoms(100)),
            (H256::from_low_u64_be(6), SignedAmount::from_atoms(100)),
        ]),
        delegation_data: DeltaDataCollection::from_data([(
            H256::from_low_u64_be(1),
            DataDelta::Create(Box::new(DelegationData::new(
                H256::from_low_u64_be(1),
                pub_key1.clone(),
            ))),
        )]),
    };
    let mut delta1 = PoSAccountingDelta::from_data(&db, data1);
    let delta1_origin_data = delta1.data().clone();

    let (_, pub_key2) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let data2 = PoSAccountingDeltaData {
        pool_data: DeltaDataCollection::from_data([
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
        ]),
        pool_balances: DeltaAmountCollection::from_data([
            (H256::from_low_u64_be(3), SignedAmount::from_atoms(50)),
            (H256::from_low_u64_be(4), SignedAmount::from_atoms(-50)),
        ]),
        pool_delegation_shares: DeltaAmountCollection::from_data([(
            (H256::from_low_u64_be(5), H256::from_low_u64_be(6)),
            SignedAmount::from_atoms(50),
        )]),
        delegation_balances: DeltaAmountCollection::from_data([
            (H256::from_low_u64_be(8), SignedAmount::from_atoms(100)),
            (H256::from_low_u64_be(9), SignedAmount::from_atoms(100)),
        ]),
        delegation_data: DeltaDataCollection::from_data([(
            H256::from_low_u64_be(1),
            DataDelta::Delete,
        )]),
    };
    let delta2 = PoSAccountingDelta::from_data(&db, data2);
    let delta2_origin_data = delta2.data().clone();

    let expected_data = PoSAccountingDeltaData {
        pool_data: DeltaDataCollection::from_data([
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
        ]),
        pool_balances: DeltaAmountCollection::from_data([
            (H256::from_low_u64_be(3), SignedAmount::from_atoms(150)),
            (H256::from_low_u64_be(4), SignedAmount::from_atoms(50)),
        ]),
        pool_delegation_shares: DeltaAmountCollection::from_data([(
            (H256::from_low_u64_be(5), H256::from_low_u64_be(6)),
            SignedAmount::from_atoms(150),
        )]),
        delegation_balances: DeltaAmountCollection::from_data([
            (H256::from_low_u64_be(5), SignedAmount::from_atoms(100)),
            (H256::from_low_u64_be(6), SignedAmount::from_atoms(100)),
            (H256::from_low_u64_be(8), SignedAmount::from_atoms(100)),
            (H256::from_low_u64_be(9), SignedAmount::from_atoms(100)),
        ]),
        delegation_data: DeltaDataCollection::from_data([]),
    };

    let undo_data = delta1.merge_with_delta(delta2.consume()).unwrap();
    assert_eq!(delta1.data(), &expected_data);

    delta1.undo_delta_merge(delta2_origin_data, undo_data).unwrap();
    assert_eq!(delta1.data(), &delta1_origin_data);
}

#[test]
fn check_create_pool() {
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);

    let mut delta = PoSAccountingDelta::new(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(OutPointSourceId::BlockReward(Id::new(H256::random())), 0);
    let (pool_id, undo) = delta.create_pool(&outpoint, pledged_amount, pub_key.clone()).unwrap();

    assert_eq!(
        delta
            .get_pool_balance(pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        pledged_amount
    );
    assert_eq!(
        delta
            .get_pool_data(pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert!(delta.data().delegation_balances.data().is_empty());
    assert!(delta.data().delegation_data.data().is_empty());
    assert!(delta.data().pool_delegation_shares.data().is_empty());

    match undo {
        PoSAccountingUndo::CreatePool(u) => delta.undo_create_pool(u).unwrap(),
        _ => unreachable!(),
    }
    assert!(delta.is_empty());
}

#[test]
fn check_decommission_pool() {
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);

    let mut delta = PoSAccountingDelta::new(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(OutPointSourceId::BlockReward(Id::new(H256::random())), 0);
    let (pool_id, _) = delta.create_pool(&outpoint, pledged_amount, pub_key.clone()).unwrap();

    let undo = delta.decommission_pool(pool_id).unwrap();

    assert!(delta.is_empty());

    match undo {
        PoSAccountingUndo::DecommissionPool(u) => delta.undo_decommission_pool(u).unwrap(),
        _ => unreachable!(),
    }

    assert_eq!(
        delta
            .get_pool_balance(pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        pledged_amount
    );
    assert_eq!(
        delta
            .get_pool_data(pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert!(delta.data().delegation_balances.data().is_empty());
    assert!(delta.data().delegation_data.data().is_empty());
    assert!(delta.data().pool_delegation_shares.data().is_empty());
}

#[test]
fn check_delegation_id() {
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);

    let mut delta = PoSAccountingDelta::new(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(OutPointSourceId::BlockReward(Id::new(H256::random())), 0);
    let (pool_id, _) = delta.create_pool(&outpoint, pledged_amount, pub_key.clone()).unwrap();

    let (_, del_pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let del_outpoint = OutPoint::new(OutPointSourceId::BlockReward(Id::new(H256::random())), 0);
    let (delegation_id, undo) =
        delta.create_delegation_id(pool_id, del_pub_key.clone(), &del_outpoint).unwrap();

    assert_eq!(
        delta
            .get_delegation_data(delegation_id)
            .expect("get_delegation_data ok")
            .expect("get_delegation_data some"),
        DelegationData::new(pool_id, del_pub_key)
    );

    match undo {
        PoSAccountingUndo::CreateDelegationId(u) => delta.undo_create_delegation_id(u).unwrap(),
        _ => unreachable!(),
    }

    assert!(delta
        .get_delegation_data(delegation_id)
        .expect("get_delegation_data ok")
        .is_none());
}
