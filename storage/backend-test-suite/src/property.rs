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

//! Randomized property-based tests

use crate::prelude::*;
use proptest::prelude::Strategy;

/// Proptest generators
mod gen {
    pub use proptest::prelude::*;
    use storage_core::{Data, DbIndex};

    pub fn idx(num_dbs: usize) -> impl Strategy<Value = DbIndex> {
        (0..num_dbs).prop_map(DbIndex::new)
    }

    pub fn entries(
        num_dbs: usize,
        num_entries: impl Into<proptest::collection::SizeRange>,
    ) -> impl Strategy<Value = std::collections::BTreeMap<(DbIndex, Data), Data>> {
        proptest::collection::btree_map((idx(num_dbs), any::<Data>()), any::<Data>(), num_entries)
    }
}

fn overwrite_and_abort<B: Backend + ThreadSafe + Clone>(backend: B) {
    using_proptest(
        file!(),
        backend,
        (gen::any::<Data>(), gen::any::<Data>(), gen::any::<Data>())
            .prop_filter("not equal", |(_, a, b)| a != b),
        |backend, (key, val0, val1)| {
            let store = backend.open(desc(1)).expect("db open to succeed");

            // Check the store returns None for given key initially
            let dbtx = store.transaction_ro();
            assert_eq!(dbtx.get(IDX.0, key.as_ref()), Ok(None));
            drop(dbtx);

            // Create a transaction, put the value in the storage and commit
            let mut dbtx = store.transaction_rw();
            dbtx.put(IDX.0, key.clone(), val0.clone()).unwrap();
            dbtx.commit().expect("commit to succeed");

            // Check the values are in place
            let dbtx = store.transaction_ro();
            assert_eq!(dbtx.get(IDX.0, key.as_ref()), Ok(Some(val0.as_ref())));
            drop(dbtx);

            // Create a transaction, modify storage and abort
            let mut dbtx = store.transaction_rw();
            dbtx.put(IDX.0, key.clone(), val1.clone()).unwrap();
            drop(dbtx);

            // Check the store still contains the original value
            let dbtx = store.transaction_ro();
            assert_eq!(dbtx.get(IDX.0, key.as_ref()), Ok(Some(val0.as_ref())));
            drop(dbtx);

            // Create a transaction, overwrite the value and commit
            let mut dbtx = store.transaction_rw();
            dbtx.put(IDX.0, key.clone(), val1.clone()).unwrap();
            dbtx.commit().expect("commit to succeed");

            // Check the key now stores the new value
            let dbtx = store.transaction_ro();
            assert_eq!(dbtx.get(IDX.0, key.as_ref()), Ok(Some(val1.as_ref())));
            drop(dbtx);
        },
    )
}

fn add_and_delete<B: Backend + ThreadSafe + Clone>(backend: B) {
    const NUM_DBS: usize = 5;
    using_proptest(
        file!(),
        backend,
        gen::entries(NUM_DBS, 0usize..20),
        |backend, entries| {
            let store = backend.open(desc(NUM_DBS)).expect("db open to succeed");

            // Add all entries to the database
            let mut dbtx = store.transaction_rw();
            for ((db, key), val) in &entries {
                dbtx.put(*db, key.clone(), val.clone()).unwrap();
            }
            dbtx.commit().unwrap();

            // check all entries have been added
            let dbtx = store.transaction_ro();
            for ((db, key), val) in &entries {
                assert_eq!(dbtx.get(*db, key).unwrap(), Some(val.as_ref()));
            }
            drop(dbtx);

            // remove all entries
            let mut dbtx = store.transaction_rw();
            for (db, key) in entries.keys() {
                dbtx.del(*db, key).unwrap();
            }
            dbtx.commit().unwrap();

            // Check entries no longer present
            let dbtx = store.transaction_ro();
            for (db, key) in entries.keys() {
                assert_eq!(dbtx.get(*db, key).unwrap(), None);
            }
            drop(dbtx);
        },
    )
}

fn add_and_delete_some<B: Backend + ThreadSafe + Clone>(backend: B) {
    const NUM_DBS: usize = 5;
    using_proptest(
        file!(),
        backend,
        (
            gen::entries(NUM_DBS, 0usize..20),
            gen::entries(NUM_DBS, 0usize..20),
            proptest::collection::vec((gen::idx(NUM_DBS), gen::any::<Data>()), 0usize..10),
        ),
        |backend, (entries1, entries2, extra_keys)| {
            let store = backend.open(desc(NUM_DBS)).expect("db open to succeed");

            // Add all entries to the database
            let mut dbtx = store.transaction_rw();
            for ((db, key), val) in entries1.iter().chain(entries2.iter()) {
                dbtx.put(*db, key.clone(), val.clone()).unwrap();
            }
            dbtx.commit().unwrap();

            // check all entries have been added
            let dbtx = store.transaction_ro();
            for ent @ (db, key) in entries1.keys().chain(entries2.keys()).chain(extra_keys.iter()) {
                let expected = entries2.get(ent).or_else(|| entries1.get(ent)).map(AsRef::as_ref);
                assert_eq!(dbtx.get(*db, key).unwrap(), expected);
            }
            drop(dbtx);

            // remove entries from the second set
            let mut dbtx = store.transaction_rw();
            for (db, key) in entries2.keys() {
                dbtx.del(*db, key).unwrap();
            }
            dbtx.commit().unwrap();

            let dbtx = store.transaction_ro();

            // Check entries from the second set are absent
            for (db, key) in entries2.keys() {
                assert_eq!(dbtx.get(*db, key).unwrap(), None);
            }

            // Check entries from the first set have correct value, unless deleted
            for ((db, key), val) in entries1.iter().filter(|e| !entries2.contains_key(e.0)) {
                assert_eq!(dbtx.get(*db, key).unwrap(), Some(val.as_ref()));
            }
        },
    )
}

tests![overwrite_and_abort, add_and_delete, add_and_delete_some];
