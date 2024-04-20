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

use common::{chain::Destination, primitives::Amount};
use randomness::{CryptoRng, Rng, RngCore};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use super::{
    create_delegation_id, create_pool, create_storage_with_pool,
    create_storage_with_pool_and_delegation,
};
use crate::{
    pool::{
        delegation::DelegationData,
        delta::PoSAccountingDelta,
        operations::PoSAccountingOperations,
        storage::PoSAccountingDB,
        view::{FlushablePoSAccountingView, PoSAccountingView},
    },
    storage::in_memory::InMemoryPoSAccounting,
    PoSAccountingUndo,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_storage_undo_no_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);

    create_pool_check_undo_check(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_delta_undo_no_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    create_pool_check_undo_check(&mut rng, &mut delta);
}

fn create_pool_check_undo_check(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations<PoSAccountingUndo> + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, undo) = create_pool(rng, op, pledged_amount).unwrap();

    assert_eq!(
        op.get_pool_balance(pool_id).expect("ok").expect("some"),
        pledged_amount
    );
    assert_eq!(
        op.get_pool_data(pool_id).expect("ok").expect("some"),
        pool_data
    );
    assert_eq!(op.get_pool_delegations_shares(pool_id).unwrap(), None);

    op.undo(undo).unwrap();

    assert_eq!(op.get_pool_balance(pool_id).unwrap(), None);
    assert_eq!(op.get_pool_data(pool_id).unwrap(), None);
    assert_eq!(op.get_pool_delegations_shares(pool_id).unwrap(), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_flush_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, delta_undo) =
        create_pool(&mut rng, &mut delta, pledged_amount).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();

    let expected_storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, pool_data)]),
        BTreeMap::from([(pool_id, pledged_amount)]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);

    {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut new_delta = PoSAccountingDelta::new(&db);
        new_delta.undo(delta_undo).unwrap();

        db.batch_write_delta(new_delta.consume()).unwrap();

        assert_eq!(storage, InMemoryPoSAccounting::new());
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_undo_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (_, _, delta_undo) = create_pool(&mut rng, &mut delta, pledged_amount).unwrap();

    delta.undo(delta_undo).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();
    assert_eq!(storage, InMemoryPoSAccounting::new());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_pool_storage_undo_no_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);

    decommission_pool_check_undo_check(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_pool_delta_undo_no_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    decommission_pool_check_undo_check(&mut rng, &mut delta);
}

fn decommission_pool_check_undo_check(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations<PoSAccountingUndo> + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, _) = create_pool(rng, op, pledged_amount).unwrap();

    let undo = op.decommission_pool(pool_id).unwrap();

    assert_eq!(op.get_pool_balance(pool_id).expect("ok"), None);
    assert_eq!(op.get_pool_data(pool_id).expect("ok"), None);
    assert_eq!(op.get_pool_delegations_shares(pool_id).expect("ok"), None);

    op.undo(undo).unwrap();

    assert_eq!(
        op.get_pool_balance(pool_id).expect("ok").expect("some"),
        pledged_amount
    );
    assert_eq!(
        op.get_pool_data(pool_id).expect("ok").expect("some"),
        pool_data
    );
    assert_eq!(op.get_pool_delegations_shares(pool_id).expect("ok"), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_pool_flush_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, mut storage) = create_storage_with_pool(&mut rng, pledged_amount);

    let delta_undo = {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        let delta_undo = delta.decommission_pool(pool_id).unwrap();

        db.batch_write_delta(delta.consume()).unwrap();

        assert_eq!(storage, InMemoryPoSAccounting::new());
        delta_undo
    };

    {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut new_delta = PoSAccountingDelta::new(&db);
        new_delta.undo(delta_undo).unwrap();

        db.batch_write_delta(new_delta.consume()).unwrap();

        let expected_storage = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, pledged_amount)]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(storage, expected_storage);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_pool_undo_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, _) = create_pool(&mut rng, &mut db, pledged_amount).unwrap();

    let mut delta = PoSAccountingDelta::new(&db);
    let delta_undo = delta.decommission_pool(pool_id).unwrap();
    delta.undo(delta_undo).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();

    let expected_storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, pool_data)]),
        BTreeMap::from([(pool_id, pledged_amount)]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_id_storage_undo_no_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);

    check_delegation_id(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_id_delta_undo_no_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    check_delegation_id(&mut rng, &mut delta);
}

fn check_delegation_id(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations<PoSAccountingUndo> + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, _) = create_pool(rng, op, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, undo) = create_delegation_id(rng, op, pool_id).unwrap();

    assert_eq!(
        op.get_delegation_data(delegation_id).expect("ok").expect("some"),
        DelegationData::new(pool_id, del_pub_key)
    );
    assert_eq!(op.get_delegation_balance(delegation_id).expect("ok"), None);
    assert_eq!(
        op.get_pool_delegation_share(pool_id, delegation_id).expect("ok"),
        None
    );

    op.undo(undo).unwrap();

    assert_eq!(op.get_delegation_data(delegation_id).expect("ok"), None);

    assert_eq!(
        op.get_pool_balance(pool_id).expect("ok").expect("some"),
        pledged_amount
    );
    assert_eq!(
        op.get_pool_data(pool_id).expect("ok").expect("some"),
        pool_data
    );
    assert_eq!(op.get_delegation_balance(delegation_id).expect("ok"), None);
    assert_eq!(
        op.get_pool_delegation_share(pool_id, delegation_id).expect("ok"),
        None
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_id_flush_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, mut storage) = create_storage_with_pool(&mut rng, pledged_amount);

    let delta_undo = {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        let (delegation_id, del_pub_key, delta_undo) =
            create_delegation_id(&mut rng, &mut delta, pool_id).unwrap();

        db.batch_write_delta(delta.consume()).unwrap();

        let expected_storage = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data.clone())]),
            BTreeMap::from([(pool_id, pledged_amount)]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::from([(delegation_id, DelegationData::new(pool_id, del_pub_key))]),
        );
        assert_eq!(storage, expected_storage);
        delta_undo
    };

    {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut new_delta = PoSAccountingDelta::new(&db);
        new_delta.undo(delta_undo).unwrap();

        db.batch_write_delta(new_delta.consume()).unwrap();

        let expected_storage = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, pledged_amount)]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(storage, expected_storage);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_id_undo_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, _) = create_pool(&mut rng, &mut db, pledged_amount).unwrap();

    let mut delta = PoSAccountingDelta::new(&db);
    let (_, _, delta_undo) = create_delegation_id(&mut rng, &mut delta, pool_id).unwrap();

    delta.undo(delta_undo).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();

    let expected_storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, pool_data)]),
        BTreeMap::from([(pool_id, pledged_amount)]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_staking_storage_undo_no_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);

    check_delegate_staking(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_staking_delta_undo_no_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    check_delegate_staking(&mut rng, &mut delta);
}

fn check_delegate_staking(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations<PoSAccountingUndo> + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, _) = create_pool(rng, op, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, _) = create_delegation_id(rng, op, pool_id).unwrap();

    let delegated_amount = Amount::from_atoms(300);
    let undo = op.delegate_staking(delegation_id, delegated_amount).unwrap();

    assert_eq!(
        op.get_delegation_balance(delegation_id).expect("ok").expect("some"),
        delegated_amount
    );
    assert_eq!(
        op.get_pool_delegation_share(pool_id, delegation_id).expect("ok").expect("some"),
        delegated_amount
    );
    assert_eq!(
        op.get_pool_balance(pool_id).expect("ok").expect("some"),
        (pledged_amount + delegated_amount).unwrap()
    );

    op.undo(undo).unwrap();

    assert_eq!(
        op.get_delegation_data(delegation_id).expect("ok").expect("some"),
        DelegationData::new(pool_id, del_pub_key)
    );
    assert_eq!(
        op.get_pool_balance(pool_id).expect("ok").expect("some"),
        pledged_amount
    );
    assert_eq!(
        op.get_pool_data(pool_id).expect("ok").expect("some"),
        pool_data
    );
    assert_eq!(op.get_delegation_balance(delegation_id).expect("ok"), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_staking_delta_flush_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledged_amount = Amount::from_atoms(100);
    let delegated_amount = Amount::from_atoms(0);
    let (pool_id, pool_data, delegation_id, del_pub_key, mut storage) =
        create_storage_with_pool_and_delegation(&mut rng, pledged_amount, delegated_amount);

    let delta_undo = {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        let delegated_amount = Amount::from_atoms(300);
        let delta_undo = delta.delegate_staking(delegation_id, delegated_amount).unwrap();

        db.batch_write_delta(delta.consume()).unwrap();

        let expected_storage = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data.clone())]),
            BTreeMap::from([(pool_id, (pledged_amount + delegated_amount).unwrap())]),
            BTreeMap::from([((pool_id, delegation_id), delegated_amount)]),
            BTreeMap::from([(delegation_id, delegated_amount)]),
            BTreeMap::from([(
                delegation_id,
                DelegationData::new(pool_id, del_pub_key.clone()),
            )]),
        );
        assert_eq!(storage, expected_storage);
        delta_undo
    };

    {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut new_delta = PoSAccountingDelta::new(&db);
        new_delta.undo(delta_undo).unwrap();

        db.batch_write_delta(new_delta.consume()).unwrap();

        let expected_storage = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, pledged_amount)]),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::from([(delegation_id, DelegationData::new(pool_id, del_pub_key))]),
        );
        assert_eq!(storage, expected_storage);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_staking_delta_undo_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, _) = create_pool(&mut rng, &mut db, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, _) = create_delegation_id(&mut rng, &mut db, pool_id).unwrap();

    let mut delta = PoSAccountingDelta::new(&db);
    let delegated_amount = Amount::from_atoms(300);
    let delta_undo = delta.delegate_staking(delegation_id, delegated_amount).unwrap();
    delta.undo(delta_undo).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();

    let expected_storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, pool_data)]),
        BTreeMap::from([(pool_id, pledged_amount)]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::from([(delegation_id, DelegationData::new(pool_id, del_pub_key))]),
    );
    assert_eq!(storage, expected_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_share_storage_undo_no_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);

    check_delegate_staking(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_share_delta_undo_no_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    check_spend_share(&mut rng, &mut delta);
}

fn check_spend_share(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations<PoSAccountingUndo> + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, _) = create_pool(rng, op, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, _) = create_delegation_id(rng, op, pool_id).unwrap();

    let delegated_amount = Amount::from_atoms(300);
    let _ = op.delegate_staking(delegation_id, delegated_amount).unwrap();

    let spent_amount = Amount::from_atoms(50);
    let undo = op.spend_share_from_delegation_id(delegation_id, spent_amount).unwrap();

    assert_eq!(
        op.get_delegation_balance(delegation_id).expect("ok").expect("some"),
        (delegated_amount - spent_amount).unwrap()
    );
    assert_eq!(
        op.get_pool_balance(pool_id).expect("ok").expect("some"),
        ((pledged_amount + delegated_amount).unwrap() - spent_amount).unwrap()
    );
    assert_eq!(
        op.get_pool_data(pool_id).expect("ok").expect("some"),
        pool_data
    );
    assert_eq!(
        op.get_delegation_data(delegation_id).expect("ok").expect("some"),
        DelegationData::new(pool_id, del_pub_key.clone())
    );
    assert_eq!(
        op.get_pool_delegation_share(pool_id, delegation_id).expect("ok").expect("some"),
        (delegated_amount - spent_amount).unwrap()
    );

    op.undo(undo).unwrap();

    assert_eq!(
        op.get_delegation_balance(delegation_id).expect("ok").expect("some"),
        delegated_amount
    );
    assert_eq!(
        op.get_pool_balance(pool_id).expect("ok").expect("some"),
        (pledged_amount + delegated_amount).unwrap()
    );
    assert_eq!(
        op.get_pool_data(pool_id).expect("ok").expect("some"),
        pool_data
    );
    assert_eq!(
        op.get_delegation_data(delegation_id).expect("ok").expect("some"),
        DelegationData::new(pool_id, del_pub_key)
    );
    assert_eq!(
        op.get_pool_delegation_share(pool_id, delegation_id).expect("ok").expect("some"),
        delegated_amount
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_share_delta_flush_undo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledged_amount = Amount::from_atoms(100);
    let delegated_amount = Amount::from_atoms(300);
    let (pool_id, pool_data, delegation_id, del_pub_key, mut storage) =
        create_storage_with_pool_and_delegation(&mut rng, pledged_amount, delegated_amount);

    let delta_undo = {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        let spent_amount = Amount::from_atoms(50);
        let delta_undo = delta.spend_share_from_delegation_id(delegation_id, spent_amount).unwrap();

        db.batch_write_delta(delta.consume()).unwrap();

        let expected_storage = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data.clone())]),
            BTreeMap::from([(
                pool_id,
                ((pledged_amount + delegated_amount).unwrap() - spent_amount).unwrap(),
            )]),
            BTreeMap::from([(
                (pool_id, delegation_id),
                (delegated_amount - spent_amount).unwrap(),
            )]),
            BTreeMap::from([(delegation_id, (delegated_amount - spent_amount).unwrap())]),
            BTreeMap::from([(
                delegation_id,
                DelegationData::new(pool_id, del_pub_key.clone()),
            )]),
        );
        assert_eq!(storage, expected_storage);
        delta_undo
    };

    {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut new_delta = PoSAccountingDelta::new(&db);
        new_delta.undo(delta_undo).unwrap();

        db.batch_write_delta(new_delta.consume()).unwrap();

        let expected_storage = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
            BTreeMap::from([(pool_id, (pledged_amount + delegated_amount).unwrap())]),
            BTreeMap::from([((pool_id, delegation_id), delegated_amount)]),
            BTreeMap::from([(delegation_id, delegated_amount)]),
            BTreeMap::from([(delegation_id, DelegationData::new(pool_id, del_pub_key))]),
        );
        assert_eq!(storage, expected_storage);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_share_delta_undo_flush(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledged_amount = Amount::from_atoms(100);
    let delegated_amount = Amount::from_atoms(300);
    let (pool_id, pool_data, delegation_id, del_pub_key, mut storage) =
        create_storage_with_pool_and_delegation(&mut rng, pledged_amount, delegated_amount);

    let mut db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);
    let spent_amount = Amount::from_atoms(50);
    let delta_undo = delta.spend_share_from_delegation_id(delegation_id, spent_amount).unwrap();
    delta.undo(delta_undo).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();

    let expected_storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, pool_data)]),
        BTreeMap::from([(pool_id, (pledged_amount + delegated_amount).unwrap())]),
        BTreeMap::from([((pool_id, delegation_id), delegated_amount)]),
        BTreeMap::from([(delegation_id, delegated_amount)]),
        BTreeMap::from([(delegation_id, DelegationData::new(pool_id, del_pub_key))]),
    );
    assert_eq!(storage, expected_storage);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delete_delegation_id_delta_check_undo_check(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pool_id = super::new_pool_id(rng.next_u64());
    let delegation_id = super::new_delegation_id(rng.next_u64());

    let mut storage = InMemoryPoSAccounting::from_values(
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::from([(
            delegation_id,
            DelegationData::new(pool_id, Destination::AnyoneCanSpend),
        )]),
    );
    let original_storage = storage.clone();

    let delta_undo = {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        let delta_undo = delta.delete_delegation_id(delegation_id).unwrap();

        db.batch_write_delta(delta.consume()).unwrap();

        let expected_storage = InMemoryPoSAccounting::new();
        assert_eq!(storage, expected_storage);
        delta_undo
    };

    {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut new_delta = PoSAccountingDelta::new(&db);
        new_delta.undo(delta_undo).unwrap();

        db.batch_write_delta(new_delta.consume()).unwrap();

        assert_eq!(storage, original_storage);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delete_delegation_id_db_check_undo_check(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pool_id = super::new_pool_id(rng.next_u64());
    let delegation_id = super::new_delegation_id(rng.next_u64());

    let mut storage = InMemoryPoSAccounting::from_values(
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::from([(
            delegation_id,
            DelegationData::new(pool_id, Destination::AnyoneCanSpend),
        )]),
    );
    let original_storage = storage.clone();

    let mut db = PoSAccountingDB::new(&mut storage);
    let undo = db.delete_delegation_id(delegation_id).unwrap();

    let expected_storage = InMemoryPoSAccounting::new();
    assert_eq!(storage, expected_storage);

    {
        let mut db = PoSAccountingDB::new(&mut storage);
        db.undo(undo).unwrap();

        assert_eq!(storage, original_storage);
    }
}
