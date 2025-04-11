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
    chain::{DelegationId, PoolId},
    primitives::Amount,
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use super::{
    create_pool, create_pool_data, create_storage_with_pool,
    create_storage_with_pool_and_delegation, new_pub_key_destination,
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

    let pledge_amount = Amount::from_atoms(100);
    let destination = new_pub_key_destination(&mut rng);
    let pool_data = create_pool_data(&mut rng, destination, pledge_amount);
    let pool_id = PoolId::random_using(&mut rng);

    let mut storage = InMemoryPoSAccounting::new();
    let mut db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&mut db);
    let _ = delta.create_pool(pool_id, pool_data.clone()).unwrap();

    // before flush
    assert_eq!(
        delta.create_pool(pool_id, pool_data.clone()).unwrap_err(),
        Error::InvariantErrorPoolDataAlreadyExists
    );

    let consumed = delta.consume();
    db.batch_write_delta(consumed).unwrap();

    // after flush
    let mut delta = PoSAccountingDelta::new(&mut db);
    assert_eq!(
        delta.create_pool(pool_id, pool_data).unwrap_err(),
        Error::InvariantErrorPoolDataAlreadyExists
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn decommission_unknown_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let storage = InMemoryPoSAccounting::new();
    let pool_id = PoolId::random_using(&mut rng);

    let db = PoSAccountingDB::new(&storage);
    let mut delta = PoSAccountingDelta::new(&db);
    assert_eq!(
        delta.decommission_pool(pool_id).unwrap_err(),
        Error::AttemptedDecommissionNonexistingPoolData
    );
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
    let storage = InMemoryPoSAccounting::new();
    let db = PoSAccountingDB::new(&storage);
    let mut delta = PoSAccountingDelta::new(&db);

    let pledge_amount = Amount::from_atoms(100);
    let (pool_id, _, undo) = create_pool(&mut rng, &mut delta, pledge_amount).unwrap();
    delta.undo(undo).unwrap();

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

    let delegation_id = DelegationId::random_using(&mut rng);
    let destination = new_pub_key_destination(&mut rng);

    let mut db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&mut db);
    let _ = delta.create_delegation_id(pool_id, delegation_id, destination.clone()).unwrap();

    // before flush
    assert_eq!(
        delta
            .create_delegation_id(pool_id, delegation_id, destination.clone(),)
            .unwrap_err(),
        Error::InvariantErrorDelegationCreationFailedIdAlreadyExists
    );

    let consumed = delta.consume();
    db.batch_write_delta(consumed).unwrap();

    // after flush
    let mut delta = PoSAccountingDelta::new(&mut db);
    assert_eq!(
        delta.create_delegation_id(pool_id, delegation_id, destination).unwrap_err(),
        Error::InvariantErrorDelegationCreationFailedIdAlreadyExists
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_delegation_id_unknown_pool(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let storage = InMemoryPoSAccounting::new();

    let destination = new_pub_key_destination(&mut rng);
    let pool_id = PoolId::random_using(&mut rng);
    let delegation_id = DelegationId::random_using(&mut rng);

    let db = PoSAccountingDB::new(&storage);
    let mut delta = PoSAccountingDelta::new(&db);
    assert_eq!(
        delta.create_delegation_id(pool_id, delegation_id, destination).unwrap_err(),
        Error::DelegationCreationFailedPoolDoesNotExist
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn delegate_staking_unknown_id(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let storage = InMemoryPoSAccounting::new();

    let delegation_id = DelegationId::random_using(&mut rng);
    let delegated_amount = Amount::from_atoms(100);

    let db = PoSAccountingDB::new(&storage);
    let mut delta = PoSAccountingDelta::new(&db);
    assert_eq!(
        delta.delegate_staking(delegation_id, delegated_amount).unwrap_err(),
        Error::DelegateToNonexistingId
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn spend_share_unknown_id(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let storage = InMemoryPoSAccounting::new();

    let delegation_id = DelegationId::random_using(&mut rng);
    let delegated_amount = Amount::from_atoms(100);

    let db = PoSAccountingDB::new(&storage);
    let mut delta = PoSAccountingDelta::new(&db);
    assert_eq!(
        delta
            .spend_share_from_delegation_id(delegation_id, delegated_amount)
            .unwrap_err(),
        Error::SpendingShareOfNonexistingDelegation(delegation_id)
    );
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

    let mut db = PoSAccountingDB::new(&mut storage);
    let mut delta = PoSAccountingDelta::new(&db);

    let _ = delta.spend_share_from_delegation_id(delegation_id, amount_to_spend).unwrap();

    assert_eq!(
        db.batch_write_delta(delta.consume()).unwrap_err(),
        Error::AccountingError(accounting::Error::ArithmeticErrorSumToUnsignedFailed)
    );
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
    {
        let mut delta = PoSAccountingDelta::new(&db);
        let _ = delta.decommission_pool(pool_id).unwrap();
        db.batch_write_delta(delta.consume()).unwrap();
    }

    {
        let mut delta = PoSAccountingDelta::new(&db);

        assert_eq!(
            delta.delete_delegation_id(delegation_id).unwrap_err(),
            Error::DelegationDeletionFailedBalanceNonZero
        );
    }

    // Spend entire delegation and try again
    let mut delta = PoSAccountingDelta::new(&db);
    let _ = delta.spend_share_from_delegation_id(delegation_id, delegated_amount).unwrap();

    let _ = delta.delete_delegation_id(delegation_id).unwrap();
    db.batch_write_delta(delta.consume()).unwrap();

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
    let mut delta = PoSAccountingDelta::new(&mut db);
    let _ = delta.spend_share_from_delegation_id(delegation_id, delegated_amount).unwrap();

    assert_eq!(
        delta.delete_delegation_id(delegation_id).unwrap_err(),
        Error::DelegationDeletionFailedPoolStillExists
    );

    // decommission the pool and try again
    let _ = delta.decommission_pool(pool_id).unwrap();

    let _ = delta.delete_delegation_id(delegation_id).unwrap();
    let consumed = delta.consume();
    db.batch_write_delta(consumed).unwrap();

    assert!(storage.all_delegation_data().is_empty());
    assert!(storage.all_delegation_balances().is_empty());
}
