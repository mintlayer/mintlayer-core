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
    random::{CryptoRng, Rng},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crate::{
    error::Error,
    pool::{
        delegation::DelegationData,
        delta::PoSAccountingDelta,
        operations::{PoSAccountingOperations, PoSAccountingUndo},
        pool_data::PoolData,
        storage::PoSAccountingDBMut,
        view::{FlushablePoSAccountingView, PoSAccountingView},
    },
    storage::in_memory::InMemoryPoSAccounting,
    DelegationId, PoolId,
};

fn create_pool(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut impl PoSAccountingOperations,
    pledged_amount: Amount,
) -> Result<(PoolId, PublicKey, PoSAccountingUndo), Error> {
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(rng))),
        0,
    );
    op.create_pool(&outpoint, pledged_amount, pub_key.clone())
        .map(|(id, undo)| (id, pub_key, undo))
}

fn create_delegation_id(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut impl PoSAccountingOperations,
    target_pool: PoolId,
) -> Result<(DelegationId, PublicKey, PoSAccountingUndo), Error> {
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::RistrettoSchnorr);
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
fn undo_create_pool_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);

    create_pool_check_undo_check(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_create_pool_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new(&mut storage);
    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

    create_pool_check_undo_check(&mut rng, &mut delta);
}

fn create_pool_check_undo_check(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, undo) = create_pool(rng, op, pledged_amount).unwrap();

    assert_eq!(
        op.get_pool_balance(pool_id).expect("ok").expect("some"),
        pledged_amount
    );
    assert_eq!(
        op.get_pool_data(pool_id).expect("ok").expect("some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert_eq!(op.get_pool_delegations_shares(pool_id).unwrap(), None);

    op.undo(undo).unwrap();

    assert_eq!(op.get_pool_balance(pool_id).unwrap(), None);
    assert_eq!(op.get_pool_data(pool_id).unwrap(), None);
    assert_eq!(op.get_pool_delegations_shares(pool_id).unwrap(), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), true)]
#[case(Seed::from_entropy(), false)]
fn undo_create_pool_delta_with_flush(#[case] seed: Seed, #[case] flush_after_undo: bool) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);
    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, undo) = create_pool(&mut rng, &mut delta, pledged_amount).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();

    let mut new_delta = PoSAccountingDelta::from_borrowed_parent(&db);

    assert_eq!(
        new_delta.get_pool_balance(pool_id).expect("ok").expect("some"),
        pledged_amount
    );
    assert_eq!(
        new_delta.get_pool_data(pool_id).expect("ok").expect("some"),
        PoolData::new(pub_key, pledged_amount)
    );
    assert_eq!(
        new_delta.get_pool_delegations_shares(pool_id).unwrap(),
        None
    );

    new_delta.undo(undo).unwrap();

    if flush_after_undo {
        db.batch_write_delta(new_delta.consume()).unwrap();

        assert_eq!(db.get_pool_balance(pool_id).unwrap(), None);
        assert_eq!(db.get_pool_data(pool_id).unwrap(), None);
        assert_eq!(db.get_pool_delegations_shares(pool_id).unwrap(), None);
    } else {
        assert_eq!(
            new_delta.get_pool_balance(pool_id).unwrap(),
            Some(Amount::ZERO)
        );
        assert_eq!(new_delta.get_pool_data(pool_id).unwrap(), None);
        assert_eq!(
            new_delta.get_pool_delegations_shares(pool_id).unwrap(),
            None
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_decommission_pool_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);

    decommission_pool_check_undo_check(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_decommission_pool_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new(&mut storage);
    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

    decommission_pool_check_undo_check(&mut rng, &mut delta);
}

fn decommission_pool_check_undo_check(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(rng, op, pledged_amount).unwrap();

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
        PoolData::new(pub_key, pledged_amount)
    );
    assert_eq!(op.get_pool_delegations_shares(pool_id).expect("ok"), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), true)]
#[case(Seed::from_entropy(), false)]
fn undo_decommission_pool_delta_with_flush(#[case] seed: Seed, #[case] flush_after_undo: bool) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);
    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(&mut rng, &mut delta, pledged_amount).unwrap();

    let undo = delta.decommission_pool(pool_id).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();

    let mut new_delta = PoSAccountingDelta::from_borrowed_parent(&db);

    assert_eq!(new_delta.get_pool_balance(pool_id).expect("ok"), None);
    assert_eq!(new_delta.get_pool_data(pool_id).expect("ok"), None);
    assert_eq!(
        new_delta.get_pool_delegations_shares(pool_id).expect("ok"),
        None
    );

    new_delta.undo(undo).unwrap();

    let check_after_undo = |v: &dyn PoSAccountingView| {
        assert_eq!(
            v.get_pool_balance(pool_id).expect("ok").expect("some"),
            pledged_amount
        );
        assert_eq!(
            v.get_pool_data(pool_id).expect("ok").expect("some"),
            PoolData::new(pub_key, pledged_amount)
        );
        assert_eq!(v.get_pool_delegations_shares(pool_id).expect("ok"), None);
    };

    if flush_after_undo {
        db.batch_write_delta(new_delta.consume()).unwrap();
        check_after_undo(&db);
    } else {
        check_after_undo(&new_delta);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_create_delegation_id_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);

    check_delegation_id(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_create_delegation_id_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new(&mut storage);
    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

    check_delegation_id(&mut rng, &mut delta);
}

fn check_delegation_id(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(rng, op, pledged_amount).unwrap();
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
        PoolData::new(pub_key, pledged_amount)
    );
    assert_eq!(op.get_delegation_balance(delegation_id).expect("ok"), None);
    assert_eq!(
        op.get_pool_delegation_share(pool_id, delegation_id).expect("ok"),
        None
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), true)]
#[case(Seed::from_entropy(), false)]
fn undo_create_delegation_id_delta_with_flush(#[case] seed: Seed, #[case] flush_after_undo: bool) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);
    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(&mut rng, &mut delta, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, undo) =
        create_delegation_id(&mut rng, &mut delta, pool_id).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();

    let mut new_delta = PoSAccountingDelta::from_borrowed_parent(&db);

    assert_eq!(
        new_delta.get_delegation_data(delegation_id).expect("ok").expect("some"),
        DelegationData::new(pool_id, del_pub_key)
    );
    assert_eq!(
        new_delta.get_delegation_balance(delegation_id).expect("ok"),
        None
    );
    assert_eq!(
        new_delta.get_pool_delegation_share(pool_id, delegation_id).expect("ok"),
        None
    );

    new_delta.undo(undo).unwrap();

    let check_after_undo = |v: &dyn PoSAccountingView| {
        assert_eq!(v.get_delegation_data(delegation_id).expect("ok"), None);
        assert_eq!(
            v.get_pool_balance(pool_id).expect("ok").expect("some"),
            pledged_amount
        );
        assert_eq!(
            v.get_pool_data(pool_id).expect("ok").expect("some"),
            PoolData::new(pub_key, pledged_amount)
        );
        assert_eq!(v.get_delegation_balance(delegation_id).expect("ok"), None);
        assert_eq!(
            v.get_pool_delegation_share(pool_id, delegation_id).expect("ok"),
            None
        );
    };

    if flush_after_undo {
        db.batch_write_delta(new_delta.consume()).unwrap();
        check_after_undo(&db);
    } else {
        check_after_undo(&new_delta);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_delegate_staking_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);

    check_delegate_staking(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_delegate_staking_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new(&mut storage);
    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

    check_delegate_staking(&mut rng, &mut delta);
}

fn check_delegate_staking(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(rng, op, pledged_amount).unwrap();
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
        PoolData::new(pub_key, pledged_amount)
    );
    assert_eq!(op.get_delegation_balance(delegation_id).expect("ok"), None);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), true)]
#[case(Seed::from_entropy(), false)]
fn undo_delegate_staking_delta_with_flush(#[case] seed: Seed, #[case] flush_after_undo: bool) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);
    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(&mut rng, &mut delta, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, _) =
        create_delegation_id(&mut rng, &mut delta, pool_id).unwrap();
    let delegated_amount = Amount::from_atoms(300);
    let undo = delta.delegate_staking(delegation_id, delegated_amount).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();

    let mut new_delta = PoSAccountingDelta::from_borrowed_parent(&db);

    assert_eq!(
        new_delta.get_delegation_balance(delegation_id).expect("ok").expect("some"),
        delegated_amount
    );
    assert_eq!(
        new_delta
            .get_pool_delegation_share(pool_id, delegation_id)
            .expect("ok")
            .expect("some"),
        delegated_amount
    );
    assert_eq!(
        new_delta.get_pool_balance(pool_id).expect("ok").expect("some"),
        (pledged_amount + delegated_amount).unwrap()
    );

    new_delta.undo(undo).unwrap();

    if flush_after_undo {
        db.batch_write_delta(new_delta.consume()).unwrap();

        assert_eq!(
            db.get_delegation_data(delegation_id).expect("ok").expect("some"),
            DelegationData::new(pool_id, del_pub_key)
        );
        assert_eq!(
            db.get_pool_balance(pool_id).expect("ok").expect("some"),
            pledged_amount
        );
        assert_eq!(
            db.get_pool_data(pool_id).expect("ok").expect("some"),
            PoolData::new(pub_key, pledged_amount)
        );
        assert_eq!(db.get_delegation_balance(delegation_id).expect("ok"), None);
    } else {
        assert_eq!(
            new_delta.get_delegation_data(delegation_id).expect("ok").expect("some"),
            DelegationData::new(pool_id, del_pub_key)
        );
        assert_eq!(
            new_delta.get_pool_balance(pool_id).expect("ok").expect("some"),
            pledged_amount
        );
        assert_eq!(
            new_delta.get_pool_data(pool_id).expect("ok").expect("some"),
            PoolData::new(pub_key, pledged_amount)
        );
        assert_eq!(
            new_delta.get_delegation_balance(delegation_id).expect("ok"),
            Some(Amount::ZERO)
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_spend_share_storage(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);

    check_delegate_staking(&mut rng, &mut db);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn undo_spend_share_delta(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDBMut::new(&mut storage);
    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

    check_spend_share(&mut rng, &mut delta);
}

fn check_spend_share(
    rng: &mut (impl Rng + CryptoRng),
    op: &mut (impl PoSAccountingOperations + PoSAccountingView),
) {
    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(rng, op, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, _) = create_delegation_id(rng, op, pool_id).unwrap();

    let delegated_amount = Amount::from_atoms(300);
    op.delegate_staking(delegation_id, delegated_amount).unwrap();

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
        PoolData::new(pub_key.clone(), pledged_amount)
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
        PoolData::new(pub_key, pledged_amount)
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
#[case(Seed::from_entropy(), true)]
#[case(Seed::from_entropy(), false)]
fn undo_spend_share_delta_with_flush(#[case] seed: Seed, #[case] flush_after_undo: bool) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);
    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

    let pledged_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, _) = create_pool(&mut rng, &mut delta, pledged_amount).unwrap();
    let (delegation_id, del_pub_key, _) =
        create_delegation_id(&mut rng, &mut delta, pool_id).unwrap();
    let delegated_amount = Amount::from_atoms(300);
    delta.delegate_staking(delegation_id, delegated_amount).unwrap();

    let spent_amount = Amount::from_atoms(50);
    let undo = delta.spend_share_from_delegation_id(delegation_id, spent_amount).unwrap();

    db.batch_write_delta(delta.consume()).unwrap();

    let mut new_delta = PoSAccountingDelta::from_borrowed_parent(&db);

    assert_eq!(
        new_delta.get_delegation_balance(delegation_id).expect("ok").expect("some"),
        (delegated_amount - spent_amount).unwrap()
    );
    assert_eq!(
        new_delta.get_pool_balance(pool_id).expect("ok").expect("some"),
        ((pledged_amount + delegated_amount).unwrap() - spent_amount).unwrap()
    );
    assert_eq!(
        new_delta.get_pool_data(pool_id).expect("ok").expect("some"),
        PoolData::new(pub_key.clone(), pledged_amount)
    );
    assert_eq!(
        new_delta.get_delegation_data(delegation_id).expect("ok").expect("some"),
        DelegationData::new(pool_id, del_pub_key.clone())
    );
    assert_eq!(
        new_delta
            .get_pool_delegation_share(pool_id, delegation_id)
            .expect("ok")
            .expect("some"),
        (delegated_amount - spent_amount).unwrap()
    );

    new_delta.undo(undo).unwrap();

    let check_after_undo = |v: &dyn PoSAccountingView| {
        assert_eq!(
            v.get_delegation_balance(delegation_id).expect("ok").expect("some"),
            delegated_amount
        );
        assert_eq!(
            v.get_pool_balance(pool_id).expect("ok").expect("some"),
            (pledged_amount + delegated_amount).unwrap()
        );
        assert_eq!(
            v.get_pool_data(pool_id).expect("ok").expect("some"),
            PoolData::new(pub_key, pledged_amount)
        );
        assert_eq!(
            v.get_delegation_data(delegation_id).expect("ok").expect("some"),
            DelegationData::new(pool_id, del_pub_key)
        );
        assert_eq!(
            v.get_pool_delegation_share(pool_id, delegation_id).expect("ok").expect("some"),
            delegated_amount
        );
    };

    if flush_after_undo {
        db.batch_write_delta(new_delta.consume()).unwrap();

        check_after_undo(&db);
    } else {
        check_after_undo(&new_delta);
    }
}

// TODO: increase test coverage (consider using proptest)
