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
    chain::{OutPointSourceId, UtxoOutPoint},
    primitives::{Amount, Id, H256},
};
use crypto::random::RngCore;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use super::{
    create_pool, create_pool_data, create_storage_with_pool,
    create_storage_with_pool_and_delegation, new_delegation_id, new_pool_id,
    new_pub_key_destination,
};

use crate::{
    pool::{delta::PoSAccountingDelta, storage::PoSAccountingDB, view::FlushablePoSAccountingView},
    storage::in_memory::InMemoryPoSAccounting,
    Error, PoSAccountingOperations,
};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_twice(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();

    let pledge_amount = Amount::from_atoms(100);
    let outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    );
    let destination = new_pub_key_destination(&mut rng);
    let pool_data = create_pool_data(&mut rng, destination, pledge_amount);
    let pool_id = crate::make_pool_id(&outpoint);

    let mut db = PoSAccountingDB::new(&mut storage);
    let _ = db.create_pool(pool_id, pool_data.clone()).unwrap();

    // using db
    {
        let mut db = PoSAccountingDB::new(&mut storage);
        assert_eq!(
            db.create_pool(pool_id, pool_data.clone()).unwrap_err(),
            Error::InvariantErrorPoolBalanceAlreadyExists
        );
    }

    // using delta
    {
        let db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        assert_eq!(
            delta.create_pool(pool_id, pool_data).unwrap_err(),
            Error::InvariantErrorPoolBalanceAlreadyExists
        );
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_unknown_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let pool_id = new_pool_id(rng.next_u64());

    // using db
    {
        let mut db = PoSAccountingDB::new(&mut storage);
        assert_eq!(
            db.decommission_pool(pool_id).unwrap_err(),
            Error::AttemptedDecommissionNonexistingPoolData
        );
    }

    // using delta
    {
        let db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        assert_eq!(
            delta.decommission_pool(pool_id).unwrap_err(),
            Error::AttemptedDecommissionNonexistingPoolData
        );
    }
}

// Create pool in db -> decommission pool in delta -> undo in delta -> merge -> merge
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_decommission_pool_undo_merge(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledge_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, mut storage) = create_storage_with_pool(&mut rng, pledge_amount);

    let mut db = PoSAccountingDB::new(&mut storage);
    let mut delta1 = PoSAccountingDelta::new(&db);
    let undo = delta1.decommission_pool(pool_id).unwrap();

    let mut delta2 = PoSAccountingDelta::new(&delta1);
    delta2.undo(undo).unwrap();

    delta1.batch_write_delta(delta2.consume()).unwrap();
    db.batch_write_delta(delta1.consume()).unwrap();

    let expected_storage = InMemoryPoSAccounting::from_values(
        BTreeMap::from([(pool_id, pool_data)]),
        BTreeMap::from([(pool_id, pledge_amount)]),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    );
    assert_eq!(storage, expected_storage);
}

// Create pool in db -> decommission pool in delta -> merge -> undo in delta -> merge
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_pool_decommission_pool_merge_undo_merge(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledge_amount = Amount::from_atoms(100);
    let (pool_id, pool_data, mut storage) = create_storage_with_pool(&mut rng, pledge_amount);

    let mut db = PoSAccountingDB::new(&mut storage);
    let mut delta1 = PoSAccountingDelta::new(&db);
    let undo = delta1.decommission_pool(pool_id).unwrap();

    db.batch_write_delta(delta1.consume()).unwrap();

    {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut delta2 = PoSAccountingDelta::new(&db);
        delta2.undo(undo).unwrap();

        db.batch_write_delta(delta2.consume()).unwrap();

        let expected_storage = InMemoryPoSAccounting::from_values(
            BTreeMap::from([(pool_id, pool_data)]),
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
fn create_pool_undo_decommission_pool_merge(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);

    let pledge_amount = Amount::from_atoms(100);
    let (pool_id, _, undo) = create_pool(&mut rng, &mut db, pledge_amount).unwrap();
    db.undo(undo).unwrap();

    let mut delta = PoSAccountingDelta::new(&db);
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

    let outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    );
    let destination = new_pub_key_destination(&mut rng);

    let mut db = PoSAccountingDB::new(&mut storage);
    let _ = db.create_delegation_id(pool_id, destination.clone(), &outpoint).unwrap();

    // using db
    {
        let mut db = PoSAccountingDB::new(&mut storage);
        assert_eq!(
            db.create_delegation_id(pool_id, destination.clone(), &outpoint).unwrap_err(),
            Error::InvariantErrorDelegationCreationFailedIdAlreadyExists
        );
    }

    // using delta
    {
        let db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        assert_eq!(
            delta.create_delegation_id(pool_id, destination, &outpoint).unwrap_err(),
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

    let destination = new_pub_key_destination(&mut rng);
    let outpoint = UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    );
    let pool_id = new_pool_id(rng.next_u64());

    {
        let mut db = PoSAccountingDB::new(&mut storage);
        assert_eq!(
            db.create_delegation_id(pool_id, destination.clone(), &outpoint).unwrap_err(),
            Error::DelegationCreationFailedPoolDoesNotExist
        );
    }

    {
        let db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        assert_eq!(
            delta.create_delegation_id(pool_id, destination, &outpoint).unwrap_err(),
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
        let mut db = PoSAccountingDB::new(&mut storage);
        assert_eq!(
            db.delegate_staking(delegation_id, delegated_amount).unwrap_err(),
            Error::DelegateToNonexistingId
        );
    }

    {
        let db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
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
        let mut db = PoSAccountingDB::new(&mut storage);
        assert_eq!(
            db.spend_share_from_delegation_id(delegation_id, delegated_amount).unwrap_err(),
            Error::InvariantErrorDelegationUndoFailedDataNotFound(delegation_id)
        );
    }

    {
        let db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);
        assert_eq!(
            delta
                .spend_share_from_delegation_id(delegation_id, delegated_amount)
                .unwrap_err(),
            Error::InvariantErrorDelegationUndoFailedDataNotFound(delegation_id)
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
        let mut db = PoSAccountingDB::new(&mut storage);
        assert_eq!(
            db.spend_share_from_delegation_id(delegation_id, amount_to_spend).unwrap_err(),
            Error::DelegationSharesSubtractionError
        );
    }

    {
        let mut db = PoSAccountingDB::new(&mut storage);
        let mut delta = PoSAccountingDelta::new(&db);

        let _ = delta.spend_share_from_delegation_id(delegation_id, amount_to_spend).unwrap();

        assert_eq!(
            db.batch_write_delta(delta.consume()).unwrap_err(),
            Error::AccountingError(accounting::Error::ArithmeticErrorSumToUnsignedFailed)
        );
    }
}

// Try deleting delegation via PoSAccountingDelta while the delegation balance is non-zero
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delta_delete_delegation_existing_balance(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledge_amount = Amount::from_atoms(100);
    let delegated_amount = Amount::from_atoms(200);
    let (pool_id, _, delegation_id, _, mut storage) =
        create_storage_with_pool_and_delegation(&mut rng, pledge_amount, delegated_amount);

    let mut db = PoSAccountingDB::new(&mut storage);
    let _ = db.decommission_pool(pool_id).unwrap();

    {
        let mut delta = PoSAccountingDelta::new(&db);

        assert_eq!(
            delta.delete_delegation_id(delegation_id).unwrap_err(),
            Error::DelegationDeletionFailedBalanceNonZero
        );
    }

    // Spend entire delegation and try again
    let _ = db.spend_share_from_delegation_id(delegation_id, delegated_amount).unwrap();
    let mut delta = PoSAccountingDelta::new(&db);

    let _ = delta.delete_delegation_id(delegation_id).unwrap();
    db.batch_write_delta(delta.consume()).unwrap();

    assert!(storage.all_delegation_data().is_empty());
    assert!(storage.all_delegation_balances().is_empty());
}

// Try deleting delegation via PoSAccountingDb while the delegation balance is non-zero
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn db_delete_delegation_existing_balance(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledge_amount = Amount::from_atoms(100);
    let delegated_amount = Amount::from_atoms(200);
    let (pool_id, _, delegation_id, _, mut storage) =
        create_storage_with_pool_and_delegation(&mut rng, pledge_amount, delegated_amount);

    let mut db = PoSAccountingDB::new(&mut storage);
    let _ = db.decommission_pool(pool_id).unwrap();

    assert_eq!(
        db.delete_delegation_id(delegation_id).unwrap_err(),
        Error::DelegationDeletionFailedBalanceNonZero
    );

    // Spend entire delegation and try again
    let _ = db.spend_share_from_delegation_id(delegation_id, delegated_amount).unwrap();
    let _ = db.delete_delegation_id(delegation_id).unwrap();

    assert!(storage.all_delegation_data().is_empty());
    assert!(storage.all_delegation_balances().is_empty());
}

// Try deleting delegation via PoAccountingDelta while the pool still exist
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delta_delete_delegation_existing_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledge_amount = Amount::from_atoms(100);
    let delegated_amount = Amount::from_atoms(200);
    let (pool_id, _, delegation_id, _, mut storage) =
        create_storage_with_pool_and_delegation(&mut rng, pledge_amount, delegated_amount);

    let mut db = PoSAccountingDB::new(&mut storage);
    let _ = db.spend_share_from_delegation_id(delegation_id, delegated_amount).unwrap();

    {
        let mut delta = PoSAccountingDelta::new(&db);

        assert_eq!(
            delta.delete_delegation_id(delegation_id).unwrap_err(),
            Error::DelegationDeletionFailedPoolStillExists
        );
    }

    // decommission the pool and try again
    let _ = db.decommission_pool(pool_id).unwrap();

    let mut delta = PoSAccountingDelta::new(&db);

    let _ = delta.delete_delegation_id(delegation_id).unwrap();
    db.batch_write_delta(delta.consume()).unwrap();

    assert!(storage.all_delegation_data().is_empty());
    assert!(storage.all_delegation_balances().is_empty());
}

// Try deleting delegation via PoAccountingDB while the pool still exist
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn db_delete_delegation_existing_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let pledge_amount = Amount::from_atoms(100);
    let delegated_amount = Amount::from_atoms(200);
    let (pool_id, _, delegation_id, _, mut storage) =
        create_storage_with_pool_and_delegation(&mut rng, pledge_amount, delegated_amount);

    let _ = PoSAccountingDB::new(&mut storage)
        .spend_share_from_delegation_id(delegation_id, delegated_amount)
        .unwrap();

    let mut db = PoSAccountingDB::new(&mut storage);
    assert_eq!(
        db.delete_delegation_id(delegation_id).unwrap_err(),
        Error::DelegationDeletionFailedPoolStillExists
    );

    // decommission the pool and try again
    let _ = db.decommission_pool(pool_id).unwrap();

    let _ = db.delete_delegation_id(delegation_id).unwrap();

    assert!(storage.all_delegation_data().is_empty());
    assert!(storage.all_delegation_balances().is_empty());
}
