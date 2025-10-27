// Copyright (c) 2021-2025 RBB S.r.l
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

use storage::error::Fatal;
use storage_backend_test_suite::prelude::{desc, MAPID};
use storage_core::{
    backend::{BackendImpl as _, ReadOps as _, TxRw as _, WriteOps as _},
    Backend as _,
};
use test_utils::assert_matches_return_val;

use crate::Sqlite;

// Force tx creation to produce an error and check the error.
// This checks for a regression where an error during tx creation would cause a deadlock:
// 1) Inside `start_transaction` the drop order was first db tx, then the mutex lock.
// 2) So, when `DbTx::drop` tried to lock the same mutex, it would deadlock.
// Due to an explicit `drop` call, this was only reproducible on an erroneous execution path.
#[test]
fn test_error_on_tx_opening() {
    let db = Sqlite::new_in_memory();
    let opened_db = db.open(desc(1)).unwrap();

    {
        let conn_lock = opened_db.connection.lock().unwrap();
        conn_lock.connection.execute("BEGIN TRANSACTION", ()).unwrap();
    }

    let res = opened_db.transaction_ro();
    // Note: can't use unwrap_err or assert_matches_return_val on res directly because the tx
    // doesn't implement Debug.
    let err_str = match res {
        Ok(_) => panic!("Got Ok while expecting an error"),
        Err(err) => {
            assert_matches_return_val!(err, storage::Error::Fatal(Fatal::InternalError(err)), err)
        }
    };
    assert!(err_str.contains("cannot start a transaction within a transaction"));
}

// Check that multiple ro txs can co-exist in the same thread.
// Note that this test can't be moved to backend-test-suite, because e.g. LMDB doesn't support
// this (though it does support having multiple ro txs in different threads, for which we have
// separate tests).
#[test]
fn multiple_ro_txs() {
    let db = Sqlite::new_in_memory();
    let mut opened_db = db.open(desc(1)).unwrap();

    // Create an rw transaction, modify storage and commit
    let mut dbtx = opened_db.transaction_rw(None).unwrap();
    dbtx.put(MAPID.0, b"hello".to_vec(), b"world".to_vec()).unwrap();
    dbtx.commit().unwrap();

    // Create 2 ro transactions, check the modification.
    let dbtx1 = opened_db.transaction_ro().unwrap();
    let dbtx2 = opened_db.transaction_ro().unwrap();
    assert_eq!(
        dbtx1.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        b"world"
    );
    assert_eq!(
        dbtx2.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        b"world"
    );
    drop(dbtx1);
    drop(dbtx2);
}

// Open a db, commit something, close the db and open again.
// This checks for a regression where `DbTx::commit_transaction` would call `forget` on self
// to avoid a seemingly unnecessary `drop`, which would lead to the underlying collection
// object being leaked, so the db wouldn't be properly closed.
#[test]
fn db_reopen_after_commit() {
    let temp_file = tempfile::NamedTempFile::new().unwrap();

    // Open a db, create an rw transaction, modify the storage and commit.
    {
        let db = Sqlite::new(&temp_file);
        let mut opened_db = db.open(desc(1)).unwrap();

        let mut dbtx = opened_db.transaction_rw(None).unwrap();

        dbtx.put(MAPID.0, b"hello".to_vec(), b"world".to_vec()).unwrap();
        dbtx.commit().unwrap();
    }

    // Open the same db, check the previously written data.
    {
        let db = Sqlite::new(&temp_file);
        let opened_db = db.open(desc(1)).unwrap();

        let dbtx = opened_db.transaction_ro().unwrap();
        assert_eq!(
            dbtx.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
            b"world"
        );
    }
}

#[test]
fn db_open_in_memory_unnamed() {
    // Create an unnamed in-memory db
    let mut db1 = Sqlite::new_in_memory().open(desc(1)).unwrap();

    // Modify db1.
    {
        let mut dbtx = db1.transaction_rw(None).unwrap();

        dbtx.put(MAPID.0, b"hello".to_vec(), b"world".to_vec()).unwrap();
        dbtx.commit().unwrap();

        // Sanity check - the data is there
        let dbtx = db1.transaction_ro().unwrap();
        assert_eq!(
            dbtx.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
            b"world"
        );
    }

    // Create an unnamed in-memory db again
    let db2 = Sqlite::new_in_memory().open(desc(1)).unwrap();

    // Check that the modification from above is not there.
    {
        let dbtx = db2.transaction_ro().unwrap();
        assert!(dbtx.get(MAPID.0, b"hello").unwrap().is_none());
    }

    // Both objects co-existed all this time
    drop(db1);
    drop(db2);
}

#[test]
fn db_open_in_memory_named() {
    // Create an in-memory db named "foo".
    let mut db_foo1 = Sqlite::new_named_in_memory("foo").open(desc(1)).unwrap();

    // Modify db_foo1.
    {
        let mut dbtx = db_foo1.transaction_rw(None).unwrap();

        dbtx.put(MAPID.0, b"hello".to_vec(), b"foo".to_vec()).unwrap();
        dbtx.commit().unwrap();

        // Sanity check - the data is there
        let dbtx = db_foo1.transaction_ro().unwrap();
        assert_eq!(
            dbtx.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
            b"foo"
        );
    }

    // Create an in-memory db named "bar".
    let mut db_bar1 = Sqlite::new_named_in_memory("bar").open(desc(1)).unwrap();

    // Modify db_bar1 (using different data than in db_foo1).
    {
        let mut dbtx = db_bar1.transaction_rw(None).unwrap();

        dbtx.put(MAPID.0, b"hello".to_vec(), b"bar".to_vec()).unwrap();
        dbtx.commit().unwrap();

        // Sanity check - the data is there
        let dbtx = db_bar1.transaction_ro().unwrap();
        assert_eq!(
            dbtx.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
            b"bar"
        );
    }

    // Create/open an in-memory db named "foo" again.
    let db_foo2 = Sqlite::new_named_in_memory("foo").open(desc(1)).unwrap();

    // Check db_foo2 - the data is there
    {
        let dbtx = db_foo2.transaction_ro().unwrap();
        assert_eq!(
            dbtx.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
            b"foo"
        );
    }

    // Create/open an in-memory db named "bar" again.
    let db_bar2 = Sqlite::new_named_in_memory("bar").open(desc(1)).unwrap();

    // Check db_foo2 - the data is there
    {
        let dbtx = db_bar2.transaction_ro().unwrap();
        assert_eq!(
            dbtx.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
            b"bar"
        );
    }

    // All objects co-existed all this time
    drop(db_foo1);
    drop(db_foo2);
    drop(db_bar1);
    drop(db_bar2);

    // Create an in-memory db named "foo" yet again, after all previous connections have been dropped.
    let db_foo3 = Sqlite::new_named_in_memory("foo").open(desc(1)).unwrap();

    // Check db_foo3 - the data is not there
    {
        let dbtx = db_foo3.transaction_ro().unwrap();
        assert!(dbtx.get(MAPID.0, b"hello").unwrap().is_none());
    }
}
