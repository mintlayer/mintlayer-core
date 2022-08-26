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

use super::*;
use storage_core::{
    backend::{Backend, ReadOps, TransactionalRo, TransactionalRw, TxRw, WriteOps},
    info,
};

fn generic_commit<B: Backend>(backend: B) {
    let dbinfo: DbDesc = [info::MapDesc::new("foo")].into_iter().collect();
    let store = backend.open(dbinfo).expect("db open to succeed");
    let idx = info::DbIndex::new(0);

    {
        // Create a transaction, modify storage and abort transaction
        let mut dbtx = store.transaction_rw();
        dbtx.put(idx, b"hello".to_vec(), b"world".to_vec()).unwrap();
        dbtx.commit().expect("commit to succeed");
    }

    {
        // Check the modification did not happen
        let dbtx = store.transaction_ro();
        assert_eq!(dbtx.get(idx, b"hello"), Ok(Some(b"world".as_ref())));
    }
}

fn generic_abort<B: Backend>(backend: B) {
    let dbinfo: DbDesc = [info::MapDesc::new("foo")].into_iter().collect();
    let store = backend.open(dbinfo).expect("db open to succeed");
    let idx = info::DbIndex::new(0);

    {
        // Create a transaction, modify storage and abort transaction
        let mut dbtx = store.transaction_rw();
        dbtx.put(idx, b"hello".to_vec(), b"world".to_vec()).unwrap();
    }

    {
        // Check the modification did not happen
        let dbtx = store.transaction_ro();
        assert_eq!(dbtx.get(idx, b"hello"), Ok(None));
    }
}

#[test]
fn commit() {
    common::concurrency::model(|| generic_commit(InMemory::new()))
}

#[test]
fn abort() {
    common::concurrency::model(|| generic_abort(InMemory::new()))
}
