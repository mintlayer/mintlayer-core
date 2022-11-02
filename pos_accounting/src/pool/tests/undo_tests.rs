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

use common::{
    chain::{OutPoint, OutPointSourceId},
    primitives::{Amount, Id, H256},
};
use crypto::{
    key::{KeyKind, PrivateKey, PublicKey},
    random::Rng,
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crate::{
    error::Error,
    pool::{
        delegation::DelegationData,
        delta::PoSAccountingDelta,
        operations::{PoSAccountingOperatorWrite, PoSAccountingUndo},
        pool_data::PoolData,
        storage::PoSAccountingDBMut,
        view::PoSAccountingView,
    },
    storage::in_memory::InMemoryPoSAccounting,
    DelegationId, PoolId,
};

fn create_pool(
    rng: &mut impl Rng,
    op: &mut impl PoSAccountingOperatorWrite,
    pledged_amount: Amount,
) -> Result<(PoolId, PublicKey, PoSAccountingUndo), Error> {
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(rng))),
        0,
    );
    op.create_pool(&outpoint, pledged_amount, pub_key.clone())
        .map(|(id, undo)| (id, pub_key, undo))
}

fn create_delegation_id(
    rng: &mut impl Rng,
    op: &mut impl PoSAccountingOperatorWrite,
    target_pool: PoolId,
) -> Result<(DelegationId, PublicKey, PoSAccountingUndo), Error> {
    let (_, pub_key) = PrivateKey::new(KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(rng))),
        0,
    );
    op.create_delegation_id(target_pool, pub_key.clone(), &outpoint)
        .map(|(id, undo)| (id, pub_key, undo))
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_create_pool_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new_empty(&mut storage);

    check_create_pool(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_create_pool_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    check_create_pool(&mut rng, &mut delta);
}

fn check_create_pool(
    rng: &mut impl Rng,
    op: &mut (impl PoSAccountingOperatorWrite + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, undo) = create_pool(rng, op, pledged_amount).unwrap();

    assert_eq!(
        op.get_pool_balance(pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        pledged_amount
    );
    assert_eq!(
        op.get_pool_data(pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert!(op
        .get_pool_delegations_shares(pool_id)
        .expect("get_pool_delegations_shares ok")
        .is_none());

    op.undo(undo).unwrap();

    assert!(op.get_pool_balance(pool_id).expect("get_pool_balance ok").is_none());
    assert!(op.get_pool_data(pool_id).expect("get_pool_data ok").is_none());
    assert!(op
        .get_pool_delegations_shares(pool_id)
        .expect("get_pool_delegations_shares ok")
        .is_none());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_decommission_pool_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new_empty(&mut storage);

    check_decommission_pool(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_decommission_pool_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    check_decommission_pool(&mut rng, &mut delta);
}

fn check_decommission_pool(
    rng: &mut impl Rng,
    op: &mut (impl PoSAccountingOperatorWrite + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(rng, op, pledged_amount).unwrap();

    let undo = op.decommission_pool(pool_id).unwrap();

    assert!(op.get_pool_balance(pool_id).expect("get_pool_balance ok").is_none());
    assert!(op.get_pool_data(pool_id).expect("get_pool_data ok").is_none());
    assert!(op
        .get_pool_delegations_shares(pool_id)
        .expect("get_pool_delegations_shares ok")
        .is_none());

    op.undo(undo).unwrap();

    assert_eq!(
        op.get_pool_balance(pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        pledged_amount
    );
    assert_eq!(
        op.get_pool_data(pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert!(op
        .get_pool_delegations_shares(pool_id)
        .expect("get_pool_delegations_shares ok")
        .is_none());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_delegation_id_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new_empty(&mut storage);

    check_delegation_id(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_delegation_id_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    check_delegation_id(&mut rng, &mut delta);
}

fn check_delegation_id(
    rng: &mut impl Rng,
    op: &mut (impl PoSAccountingOperatorWrite + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(rng, op, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, undo) = create_delegation_id(rng, op, pool_id).unwrap();

    assert_eq!(
        op.get_delegation_data(delegation_id)
            .expect("get_delegation_data ok")
            .expect("get_delegation_data some"),
        DelegationData::new(pool_id, del_pub_key)
    );
    assert!(op
        .get_delegation_balance(delegation_id)
        .expect("get_delegation_balance ok")
        .is_none());
    assert!(op
        .get_pool_delegation_share(pool_id, delegation_id)
        .expect("get_pool_delegation_share ok")
        .is_none());

    op.undo(undo).unwrap();

    assert!(op.get_delegation_data(delegation_id).expect("get_delegation_data ok").is_none());

    assert_eq!(
        op.get_pool_balance(pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        pledged_amount
    );
    assert_eq!(
        op.get_pool_data(pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert!(op
        .get_delegation_balance(delegation_id)
        .expect("get_delegation_balance ok")
        .is_none());
    assert!(op
        .get_pool_delegation_share(pool_id, delegation_id)
        .expect("get_pool_delegation_share ok")
        .is_none());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_delegate_staking_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new_empty(&mut storage);

    check_delegate_staking(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_delegate_staking_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    check_delegate_staking(&mut rng, &mut delta);
}

fn check_delegate_staking(
    rng: &mut impl Rng,
    op: &mut (impl PoSAccountingOperatorWrite + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(rng, op, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, _) = create_delegation_id(rng, op, pool_id).unwrap();

    let delegated_amount = Amount::from_atoms(300);
    let undo = op.delegate_staking(delegation_id, delegated_amount).unwrap();

    assert_eq!(
        op.get_delegation_balance(delegation_id)
            .expect("get_delegation_balance ok")
            .expect("get_delegation_balance some"),
        delegated_amount
    );
    assert_eq!(
        op.get_pool_delegation_share(pool_id, delegation_id)
            .expect("get_delegation_share ok")
            .expect("get_delegation_share some"),
        delegated_amount
    );
    assert_eq!(
        op.get_pool_balance(pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        (pledged_amount + delegated_amount).unwrap()
    );

    op.undo(undo).unwrap();

    assert_eq!(
        op.get_delegation_data(delegation_id)
            .expect("get_delegation_data ok")
            .expect("get_delegation_data some"),
        DelegationData::new(pool_id, del_pub_key)
    );
    assert_eq!(
        op.get_pool_balance(pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        pledged_amount
    );
    assert_eq!(
        op.get_pool_data(pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert!(op
        .get_delegation_balance(delegation_id)
        .expect("get_delegation_balance ok")
        .is_none());
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_spend_share_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new_empty(&mut storage);

    check_delegate_staking(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn check_spend_share_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new_empty(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    check_spend_share(&mut rng, &mut delta);
}

fn check_spend_share(
    rng: &mut impl Rng,
    op: &mut (impl PoSAccountingOperatorWrite + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(rng, op, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, _) = create_delegation_id(rng, op, pool_id).unwrap();

    let delegated_amount = Amount::from_atoms(300);
    op.delegate_staking(delegation_id, delegated_amount).unwrap();

    let spent_amount = Amount::from_atoms(50);
    let undo = op.spend_share_from_delegation_id(delegation_id, spent_amount).unwrap();

    assert_eq!(
        op.get_delegation_balance(delegation_id)
            .expect("get_delegation_balance ok")
            .expect("get_delegation_balance some"),
        (delegated_amount - spent_amount).unwrap()
    );
    assert_eq!(
        op.get_pool_balance(pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        ((pledged_amount + delegated_amount).unwrap() - spent_amount).unwrap()
    );
    assert_eq!(
        op.get_pool_data(pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key.clone(), pledged_amount)
    );
    assert_eq!(
        op.get_delegation_data(delegation_id)
            .expect("get_delegation_data ok")
            .expect("get_delegation_data some"),
        DelegationData::new(pool_id, del_pub_key.clone())
    );
    assert_eq!(
        op.get_pool_delegation_share(pool_id, delegation_id)
            .expect("get_delegation_share ok")
            .expect("get_delegation_share some"),
        (delegated_amount - spent_amount).unwrap()
    );

    op.undo(undo).unwrap();

    assert_eq!(
        op.get_delegation_balance(delegation_id)
            .expect("get_delegation_balance ok")
            .expect("get_delegation_balance some"),
        delegated_amount
    );
    assert_eq!(
        op.get_pool_balance(pool_id)
            .expect("get_pool_balance ok")
            .expect("get_pool_balance some"),
        (pledged_amount + delegated_amount).unwrap()
    );
    assert_eq!(
        op.get_pool_data(pool_id)
            .expect("get_pool_data ok")
            .expect("get_pool_data some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert_eq!(
        op.get_delegation_data(delegation_id)
            .expect("get_delegation_data ok")
            .expect("get_delegation_data some"),
        DelegationData::new(pool_id, del_pub_key)
    );
    assert_eq!(
        op.get_pool_delegation_share(pool_id, delegation_id)
            .expect("get_delegation_share ok")
            .expect("get_delegation_share some"),
        delegated_amount
    );
}

// TODO: increase test coverage (consider using proptest)
