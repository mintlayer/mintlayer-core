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
use crypto::{
    key::{KeyKind, PrivateKey, PublicKey},
    random::{CryptoRng, Rng, RngCore},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use super::{new_delegation_id, new_pool_id};

use crate::{
    pool::{
        delta::PoSAccountingDelta, pool_data::PoolData, storage::PoSAccountingDBMut,
        view::FlushablePoSAccountingView,
    },
    storage::in_memory::InMemoryPoSAccounting,
    DelegationData, DelegationId, Error, PoSAccountingOperations, PoolId,
};

fn create_storage_with_pool(
    rng: &mut (impl Rng + CryptoRng),
    pledged_amount: Amount,
) -> (PoolId, PublicKey, InMemoryPoSAccounting) {
    let pool_id = new_pool_id(rng.next_u64());
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::RistrettoSchnorr);

    let storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, PoolData::new(pub_key.clone(), pledged_amount))]),
        BTreeMap::from([(pool_id, pledged_amount)]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    (pool_id, pub_key, storage)
}

fn create_storage_with_pool_and_delegation(
    rng: &mut (impl Rng + CryptoRng),
    pledged_amount: Amount,
    delegated_amount: Amount,
) -> (
    PoolId,
    PublicKey,
    DelegationId,
    PublicKey,
    InMemoryPoSAccounting,
) {
    let pool_id = new_pool_id(rng.next_u64());
    let delegation_id = new_delegation_id(rng.next_u64());
    let (_, pub_key_pool) = PrivateKey::new_from_rng(rng, KeyKind::RistrettoSchnorr);
    let (_, pub_key_del) = PrivateKey::new_from_rng(rng, KeyKind::RistrettoSchnorr);

    let storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, PoolData::new(pub_key_pool.clone(), pledged_amount))]),
        BTreeMap::from([(pool_id, (pledged_amount + delegated_amount).unwrap())]),
        BTreeMap::from([((pool_id, delegation_id), delegated_amount)]),
        BTreeMap::from([(delegation_id, delegated_amount)]),
        BTreeMap::from([(
            delegation_id,
            DelegationData::new(pool_id, pub_key_del.clone()),
        )]),
    );
    (pool_id, pub_key_pool, delegation_id, pub_key_del, storage)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();

    let pledge_amount = Amount::from_atoms(100);
    let outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    );
    let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);

    let mut db = PoSAccountingDBMut::new(&mut storage);
    let _ = db.create_pool(&outpoint, pledge_amount, pub_key.clone()).unwrap();

    // using db
    {
        let mut db = PoSAccountingDBMut::new(&mut storage);
        assert_eq!(
            db.create_pool(&outpoint, pledge_amount, pub_key.clone()).unwrap_err(),
            Error::InvariantErrorPoolBalanceAlreadyExists
        );
    }

    // using delta
    {
        let db = PoSAccountingDBMut::new(&mut storage);
        let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);
        assert_eq!(
            delta.create_pool(&outpoint, pledge_amount, pub_key).unwrap_err(),
            Error::InvariantErrorPoolBalanceAlreadyExists
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decomission_unknown_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let pool_id = new_pool_id(rng.next_u64());

    // using db
    {
        let mut db = PoSAccountingDBMut::new(&mut storage);
        assert_eq!(
            db.decommission_pool(pool_id).unwrap_err(),
            Error::AttemptedDecommissionNonexistingPoolData
        );
    }

    // using delta
    {
        let db = PoSAccountingDBMut::new(&mut storage);
        let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);
        assert_eq!(
            delta.decommission_pool(pool_id).unwrap_err(),
            Error::AttemptedDecommissionNonexistingPoolData
        );
    }
}

// Create pool in db -> decomission pool in delta -> undo in delta -> merge -> merge
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_decomission_pool_undo_merge(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledge_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, mut storage) = create_storage_with_pool(&mut rng, pledge_amount);

    let mut db = PoSAccountingDBMut::new(&mut storage);
    let mut delta1 = PoSAccountingDelta::from_borrowed_parent(&db);
    let undo = delta1.decommission_pool(pool_id).unwrap();

    let mut delta2 = PoSAccountingDelta::from_borrowed_parent(&delta1);
    delta2.undo(undo).unwrap();

    delta1.batch_write_delta(delta2.consume()).unwrap();
    db.batch_write_delta(delta1.consume()).unwrap();

    let expected_storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, PoolData::new(pub_key, pledge_amount))]),
        BTreeMap::from([(pool_id, pledge_amount)]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);
}

// Create pool in db -> decomission pool in delta -> merge -> undo in delta -> merge
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_decomission_pool_merge_undo_merge(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledge_amount = Amount::from_atoms(100);
    let (pool_id, pub_key, mut storage) = create_storage_with_pool(&mut rng, pledge_amount);

    let mut db = PoSAccountingDBMut::new(&mut storage);
    let mut delta1 = PoSAccountingDelta::from_borrowed_parent(&db);
    let undo = delta1.decommission_pool(pool_id).unwrap();

    db.batch_write_delta(delta1.consume()).unwrap();

    {
        let mut db = PoSAccountingDBMut::new(&mut storage);
        let mut delta2 = PoSAccountingDelta::from_borrowed_parent(&db);
        delta2.undo(undo).unwrap();

        db.batch_write_delta(delta2.consume()).unwrap();

        let expected_storage = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, PoolData::new(pub_key, pledge_amount))]),
            BTreeMap::from([(pool_id, pledge_amount)]),
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
fn create_pool_undo_decomission_pool_merge(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDBMut::new(&mut storage);

    let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    );
    let pledge_amount = Amount::from_atoms(100);
    let (pool_id, undo) = db.create_pool(&outpoint, pledge_amount, pub_key).unwrap();
    db.undo(undo).unwrap();

    let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);
    assert_eq!(
        delta.decommission_pool(pool_id).unwrap_err(),
        Error::AttemptedDecommissionNonexistingPoolData
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledge_amount = Amount::from_atoms(100);
    let (pool_id, _, mut storage) = create_storage_with_pool(&mut rng, pledge_amount);

    let outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    );
    let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);

    let mut db = PoSAccountingDBMut::new(&mut storage);
    let _ = db.create_delegation_id(pool_id, pub_key.clone(), &outpoint).unwrap();

    // using db
    {
        let mut db = PoSAccountingDBMut::new(&mut storage);
        assert_eq!(
            db.create_delegation_id(pool_id, pub_key.clone(), &outpoint).unwrap_err(),
            Error::InvariantErrorDelegationCreationFailedIdAlreadyExists
        );
    }

    // using delta
    {
        let db = PoSAccountingDBMut::new(&mut storage);
        let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);
        assert_eq!(
            delta.create_delegation_id(pool_id, pub_key, &outpoint).unwrap_err(),
            Error::InvariantErrorDelegationCreationFailedIdAlreadyExists
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_id_unknown_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();

    let (_, pub_key) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
    let outpoint = OutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    );
    let pool_id = new_pool_id(rng.next_u64());

    {
        let mut db = PoSAccountingDBMut::new(&mut storage);
        assert_eq!(
            db.create_delegation_id(pool_id, pub_key.clone(), &outpoint).unwrap_err(),
            Error::DelegationCreationFailedPoolDoesNotExist
        );
    }

    {
        let db = PoSAccountingDBMut::new(&mut storage);
        let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);
        assert_eq!(
            delta.create_delegation_id(pool_id, pub_key, &outpoint).unwrap_err(),
            Error::DelegationCreationFailedPoolDoesNotExist
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_staking_unknown_id(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();

    let delegation_id = new_delegation_id(rng.next_u64());
    let delegated_amount = Amount::from_atoms(100);

    {
        let mut db = PoSAccountingDBMut::new(&mut storage);
        assert_eq!(
            db.delegate_staking(delegation_id, delegated_amount).unwrap_err(),
            Error::DelegateToNonexistingId
        );
    }

    {
        let db = PoSAccountingDBMut::new(&mut storage);
        let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);
        assert_eq!(
            delta.delegate_staking(delegation_id, delegated_amount).unwrap_err(),
            Error::DelegateToNonexistingId
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_share_unknown_id(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();

    let delegation_id = new_delegation_id(rng.next_u64());
    let delegated_amount = Amount::from_atoms(100);

    {
        let mut db = PoSAccountingDBMut::new(&mut storage);
        assert_eq!(
            db.spend_share_from_delegation_id(delegation_id, delegated_amount).unwrap_err(),
            Error::InvariantErrorDelegationUndoFailedDataNotFound
        );
    }

    {
        let db = PoSAccountingDBMut::new(&mut storage);
        let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);
        assert_eq!(
            delta
                .spend_share_from_delegation_id(delegation_id, delegated_amount)
                .unwrap_err(),
            Error::InvariantErrorDelegationUndoFailedDataNotFound
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_more_than_delegated(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledge_amount = Amount::from_atoms(100);
    let delegated_amount = Amount::from_atoms(200);
    let (_, _, delegation_id, _, mut storage) =
        create_storage_with_pool_and_delegation(&mut rng, pledge_amount, delegated_amount);

    let amount_to_spend = Amount::from_atoms(250);
    {
        let mut db = PoSAccountingDBMut::new(&mut storage);
        assert_eq!(
            db.spend_share_from_delegation_id(delegation_id, amount_to_spend).unwrap_err(),
            Error::DelegationSharesSubtractionError
        );
    }

    {
        let mut db = PoSAccountingDBMut::new(&mut storage);
        let mut delta = PoSAccountingDelta::from_borrowed_parent(&db);

        let _ = delta.spend_share_from_delegation_id(delegation_id, amount_to_spend).unwrap();

        assert_eq!(
            db.batch_write_delta(delta.consume()).unwrap_err(),
            Error::AccountingError(accounting::Error::ArithmeticErrorSumToUnsignedFailed)
        );
    }
}
