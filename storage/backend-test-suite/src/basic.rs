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

//! Some basic tests

use crate::prelude::*;

fn put_and_commit<B: Backend>(backend: B) {
    let store = backend.open(desc(1)).expect("db open to succeed");

    // Create a transaction, modify storage and abort transaction
    let mut dbtx = store.transaction_rw();
    dbtx.put(IDX.0, b"hello".to_vec(), b"world".to_vec()).unwrap();
    dbtx.commit().expect("commit to succeed");

    // Check the modification did not happen
    let dbtx = store.transaction_ro();
    assert_eq!(dbtx.get(IDX.0, b"hello"), Ok(Some(b"world".as_ref())));
    drop(dbtx);
}

fn put_and_abort<B: Backend>(backend: B) {
    let store = backend.open(desc(1)).expect("db open to succeed");

    // Create a transaction, modify storage and abort transaction
    let mut dbtx = store.transaction_rw();
    dbtx.put(IDX.0, b"hello".to_vec(), b"world".to_vec()).unwrap();
    drop(dbtx);

    // Check the modification did not happen
    let dbtx = store.transaction_ro();
    assert_eq!(dbtx.get(IDX.0, b"hello"), Ok(None));
    drop(dbtx);
}

fn put_two_under_different_keys<B: Backend>(backend: B) {
    let store = backend.open(desc(1)).expect("db open to succeed");

    // Create a transaction, modify storage and commit
    let mut dbtx = store.transaction_rw();
    dbtx.put(IDX.0, b"a".to_vec(), b"0".to_vec()).unwrap();
    dbtx.put(IDX.0, b"b".to_vec(), b"1".to_vec()).unwrap();
    dbtx.commit().expect("commit to succeed");

    // Check the values are in place
    let dbtx = store.transaction_ro();
    assert_eq!(dbtx.get(IDX.0, b"a"), Ok(Some(b"0".as_ref())));
    assert_eq!(dbtx.get(IDX.0, b"b"), Ok(Some(b"1".as_ref())));
    drop(dbtx);

    // Create a transaction, modify storage and abort
    let mut dbtx = store.transaction_rw();
    dbtx.put(IDX.0, b"a".to_vec(), b"00".to_vec()).unwrap();
    dbtx.put(IDX.0, b"b".to_vec(), b"11".to_vec()).unwrap();
    drop(dbtx);

    // Check the modification did not happen
    let dbtx = store.transaction_ro();
    assert_eq!(dbtx.get(IDX.0, b"a"), Ok(Some(b"0".as_ref())));
    assert_eq!(dbtx.get(IDX.0, b"b"), Ok(Some(b"1".as_ref())));
    drop(dbtx);
}

fn put_twice_then_commit_read_last<B: Backend>(backend: B) {
    let store = backend.open(desc(1)).expect("db open to succeed");

    let mut dbtx = store.transaction_rw();
    dbtx.put(IDX.0, b"hello".to_vec(), b"a".to_vec()).unwrap();
    assert_eq!(dbtx.get(IDX.0, b"hello"), Ok(Some(b"a".as_ref())),);
    dbtx.put(IDX.0, b"hello".to_vec(), b"b".to_vec()).unwrap();
    assert_eq!(dbtx.get(IDX.0, b"hello"), Ok(Some(b"b".as_ref())),);
    dbtx.commit().expect("commit to succeed");

    let dbtx = store.transaction_ro();
    assert_eq!(dbtx.get(IDX.0, b"hello"), Ok(Some(b"b".as_ref())),);
}

tests![
    put_and_abort,
    put_and_commit,
    put_twice_then_commit_read_last,
    put_two_under_different_keys,
];
