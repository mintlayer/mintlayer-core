use accounting::{DataDelta, DeltaAmountCollection, DeltaDataCollection};
use common::{
    chain::{OutPoint, OutPointSourceId},
    primitives::{signed_amount::SignedAmount, Amount, Id, H256},
};
use crypto::key::{KeyKind, PrivateKey, PublicKey};

use crate::{
    error::Error,
    pool::{
        delegation::DelegationData,
        delta::{data::PoSAccountingDeltaData, PoSAccountingDelta},
        operations::{PoSAccountingOperatorRead, PoSAccountingOperatorWrite, PoSAccountingUndo},
        pool_data::PoolData,
        storage::PoSAccountingDBMut,
        view::PoSAccountingView,
    },
    storage::in_memory::InMemoryPoSAccounting,
};

fn create_pool(
    delta: &mut PoSAccountingDelta,
    pledged_amount: Amount,
) -> Result<(H256, PublicKey, PoSAccountingUndo), Error> {
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(OutPointSourceId::BlockReward(Id::new(H256::random())), 0);
    delta
        .create_pool(&outpoint, pledged_amount, pub_key.clone())
        .map(|(id, undo)| (id, pub_key, undo))
}

fn create_delegation_id(
    delta: &mut PoSAccountingDelta,
    target_pool: H256,
) -> Result<(H256, PublicKey, PoSAccountingUndo), Error> {
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(OutPointSourceId::BlockReward(Id::new(H256::random())), 0);
    delta
        .create_delegation_id(target_pool, pub_key.clone(), &outpoint)
        .map(|(id, undo)| (id, pub_key, undo))
}

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

#[test]
fn check_create_pool() {
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, undo) = create_pool(&mut delta, pledged_amount).unwrap();

    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_balance(&delta, pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        pledged_amount
    );
    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_data(&delta, pool_id)
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
    assert!(delta.data().is_empty());
}

#[test]
fn check_decommission_pool() {
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(&mut delta, pledged_amount).unwrap();

    let undo = delta.decommission_pool(pool_id).unwrap();

    assert!(delta.data().is_empty());

    match undo {
        PoSAccountingUndo::DecommissionPool(u) => delta.undo_decommission_pool(u).unwrap(),
        _ => unreachable!(),
    }

    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_balance(&delta, pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        pledged_amount
    );
    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_data(&delta, pool_id)
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
    let (pool_id, pub_key, _) = create_pool(&mut delta, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, undo) = create_delegation_id(&mut delta, pool_id).unwrap();

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

    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_balance(&delta, pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        pledged_amount
    );
    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_data(&delta, pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert!(delta.data().delegation_balances.data().is_empty());
    assert!(delta.data().delegation_data.data().is_empty());
    assert!(delta.data().pool_delegation_shares.data().is_empty());
}

#[test]
fn check_delegate_staking() {
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(&mut delta, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, _) = create_delegation_id(&mut delta, pool_id).unwrap();

    let delegated_amount = Amount::from_atoms(300);
    let undo = delta.delegate_staking(delegation_id, delegated_amount).unwrap();

    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_delegation_balance(&delta, delegation_id)
            .expect("get_delegation_balance ok")
            .expect("get_delegation_balance some"),
        delegated_amount
    );
    assert_eq!(
        delta
            .get_delegation_share(pool_id, delegation_id)
            .expect("get_delegation_share ok")
            .expect("get_delegation_share some"),
        delegated_amount
    );
    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_balance(&delta, pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        (pledged_amount + delegated_amount).unwrap()
    );

    match undo {
        PoSAccountingUndo::DelegateStaking(u) => delta.undo_delegate_staking(u).unwrap(),
        _ => unreachable!(),
    }

    assert_eq!(
        delta
            .get_delegation_data(delegation_id)
            .expect("get_delegation_data ok")
            .expect("get_delegation_data some"),
        DelegationData::new(pool_id, del_pub_key)
    );
    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_balance(&delta, pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        pledged_amount
    );
    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_data(&delta, pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert!(delta.data().delegation_balances.data().is_empty());
    assert!(delta.data().pool_delegation_shares.data().is_empty());
}

#[test]
fn check_spend_share() {
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(&mut delta, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, _) = create_delegation_id(&mut delta, pool_id).unwrap();

    let delegated_amount = Amount::from_atoms(300);
    delta.delegate_staking(delegation_id, delegated_amount).unwrap();

    let spent_amount = Amount::from_atoms(50);
    delta.spend_share_from_delegation_id(delegation_id, spent_amount).unwrap();

    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_delegation_balance(&delta, delegation_id)
            .expect("get_delegation_balance ok")
            .expect("get_delegation_balance some"),
        (delegated_amount - spent_amount).unwrap()
    );
    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_balance(&delta, pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        ((pledged_amount + delegated_amount).unwrap() - spent_amount).unwrap()
    );
    // TODO: disambiguate function call
    assert_eq!(
        PoSAccountingView::get_pool_data(&delta, pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert_eq!(
        delta
            .get_delegation_data(delegation_id)
            .expect("get_delegation_data ok")
            .expect("get_delegation_data some"),
        DelegationData::new(pool_id, del_pub_key)
    );
    assert_eq!(
        delta
            .get_delegation_share(pool_id, delegation_id)
            .expect("get_delegation_share ok")
            .expect("get_delegation_share some"),
        (delegated_amount - spent_amount).unwrap()
    );
}

// TODO: increase test coverage (consider using proptest)
