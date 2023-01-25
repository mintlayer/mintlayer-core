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
    use super::WriteAction;
    pub use proptest::prelude::*;
    use storage_core::{Data, DbIndex};

    pub fn idx(num_dbs: usize) -> impl Strategy<Value = DbIndex> {
        (0..num_dbs).prop_map(DbIndex::new)
    }

    pub fn entries(
        num_dbs: usize,
        num_entries: impl Into<proptest::collection::SizeRange>,
    ) -> impl Strategy<Value = std::collections::BTreeMap<(DbIndex, Data), Data>> {
        proptest::collection::btree_map((idx(num_dbs), big_key()), any::<Data>(), num_entries)
    }

    // Generate key from a set of keys with given cardinality. Lower cardinality encourages
    // generation of conflicting keys, causing value overwrites and deletions to be more likely.
    pub fn key(key_cardinality: u32) -> impl Strategy<Value = Data> {
        (0..key_cardinality).prop_map(|x| format!("{x:x}").into())
    }

    // Potentially big arbitrary key
    pub fn big_key() -> impl Strategy<Value = Data> {
        proptest::collection::vec(any::<u8>(), 1..512)
    }

    pub fn action(key_cardinality: u32) -> impl Strategy<Value = WriteAction> {
        prop_oneof![
            (key(key_cardinality), any::<Data>()).prop_map(|(k, v)| WriteAction::Put(k, v)),
            key(key_cardinality).prop_map(WriteAction::Del),
        ]
    }

    pub fn actions(
        key_cardinality: u32,
        count: impl Into<proptest::collection::SizeRange>,
    ) -> impl Strategy<Value = Vec<WriteAction>> {
        proptest::collection::vec(action(key_cardinality), count)
    }
}

fn overwrite_and_abort<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    using_proptest(
        file!(),
        backend_fn,
        (gen::key(100), gen::any::<Data>(), gen::any::<Data>())
            .prop_filter("not equal", |(_, a, b)| a != b),
        |backend, (key, val0, val1)| {
            let store = backend.open(desc(1)).expect("db open to succeed");

            // Check the store returns None for given key initially
            let dbtx = store.transaction_ro().unwrap();
            assert_eq!(dbtx.get(IDX.0, key.as_ref()), Ok(None));
            drop(dbtx);

            // Create a transaction, put the value in the storage and commit
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.put(IDX.0, key.clone(), val0.clone()).unwrap();
            dbtx.commit().expect("commit to succeed");

            // Check the values are in place
            let dbtx = store.transaction_ro().unwrap();
            assert_eq!(
                dbtx.get(IDX.0, key.as_ref()).unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
                val0.as_ref() as &[u8]
            );
            drop(dbtx);

            // Create a transaction, modify storage and abort
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.put(IDX.0, key.clone(), val1.clone()).unwrap();
            drop(dbtx);

            // Check the store still contains the original value
            let dbtx = store.transaction_ro().unwrap();
            assert_eq!(
                dbtx.get(IDX.0, key.as_ref()).unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
                val0.as_ref() as &[u8]
            );
            drop(dbtx);

            // Create a transaction, overwrite the value and commit
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.put(IDX.0, key.clone(), val1.clone()).unwrap();
            dbtx.commit().expect("commit to succeed");

            // Check the key now stores the new value
            let dbtx = store.transaction_ro().unwrap();
            assert_eq!(
                dbtx.get(IDX.0, key.as_ref()).unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
                val1.as_ref() as &[u8]
            );
            drop(dbtx);
        },
    )
}

fn add_and_delete<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    const NUM_DBS: usize = 5;
    using_proptest(
        file!(),
        backend_fn,
        gen::entries(NUM_DBS, 0usize..20),
        |backend, entries| {
            let store = backend.open(desc(NUM_DBS)).expect("db open to succeed");

            // Add all entries to the database
            let mut dbtx = store.transaction_rw().unwrap();
            for ((db, key), val) in &entries {
                dbtx.put(*db, key.clone(), val.clone()).unwrap();
            }
            dbtx.commit().unwrap();

            // check all entries have been added
            let dbtx = store.transaction_ro().unwrap();
            for ((db, key), val) in &entries {
                assert_eq!(
                    dbtx.get(*db, key).unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
                    val.as_ref() as &[u8]
                );
            }
            drop(dbtx);

            // remove all entries
            let mut dbtx = store.transaction_rw().unwrap();
            for (db, key) in entries.keys() {
                dbtx.del(*db, &key).unwrap();
            }
            dbtx.commit().unwrap();

            // Check entries no longer present
            let dbtx = store.transaction_ro().unwrap();
            for (db, key) in entries.keys() {
                assert_eq!(dbtx.get(*db, &key), Ok(None));
            }
            drop(dbtx);
        },
    )
}

fn last_write_wins<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    using_proptest(
        file!(),
        backend_fn,
        (
            gen::key(1000),
            gen::prop::collection::vec(gen::any::<Data>(), 0..100),
        ),
        |backend, (key, vals)| {
            let store = backend.open(desc(1)).expect("db open to succeed");
            let last = vals.last().cloned();

            // Add all entries to the database
            let mut dbtx = store.transaction_rw().unwrap();
            for val in vals.into_iter() {
                dbtx.put(IDX.0, key.clone(), val).unwrap();
            }
            dbtx.commit().unwrap();

            let dbtx = store.transaction_ro().unwrap();
            assert_eq!(
                dbtx.get(IDX.0, key.as_ref()).unwrap().as_ref().map(|v| v.as_ref()),
                last.as_deref()
            );
        },
    )
}

fn add_and_delete_some<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    const NUM_DBS: usize = 5;
    using_proptest(
        file!(),
        backend_fn,
        (
            gen::entries(NUM_DBS, 0usize..20),
            gen::entries(NUM_DBS, 0usize..20),
            proptest::collection::vec((gen::idx(NUM_DBS), gen::big_key()), 0usize..10),
        ),
        |backend, (entries1, entries2, extra_keys)| {
            let store = backend.open(desc(NUM_DBS)).expect("db open to succeed");

            // Add all entries to the database
            let mut dbtx = store.transaction_rw().unwrap();
            for ((db, key), val) in entries1.iter().chain(entries2.iter()) {
                dbtx.put(*db, key.clone(), val.clone()).unwrap();
            }
            dbtx.commit().unwrap();

            // check all entries have been added
            let dbtx = store.transaction_ro().unwrap();
            for ent @ (db, key) in entries1.keys().chain(entries2.keys()).chain(extra_keys.iter()) {
                let expected = entries2.get(ent).or_else(|| entries1.get(ent)).map(AsRef::as_ref);
                assert_eq!(
                    dbtx.get(*db, &key).unwrap().as_ref().map(|v| v.as_ref()),
                    expected
                );
            }
            drop(dbtx);

            // remove entries from the second set
            let mut dbtx = store.transaction_rw().unwrap();
            for (db, key) in entries2.keys() {
                dbtx.del(*db, &key).unwrap();
            }
            dbtx.commit().unwrap();

            let dbtx = store.transaction_ro().unwrap();

            // Check entries from the second set are absent
            for (db, key) in entries2.keys() {
                assert_eq!(dbtx.get(*db, &key), Ok(None));
            }

            // Check entries from the first set have correct value, unless deleted
            for ((db, key), val) in entries1.iter().filter(|e| !entries2.contains_key(e.0)) {
                assert_eq!(
                    dbtx.get(*db, key).unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
                    val.as_ref() as &[u8]
                );
            }
        },
    )
}

fn add_modify_abort_modify_commit<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    using_proptest(
        file!(),
        backend_fn,
        (
            gen::actions(100, 0..20),
            gen::actions(100, 0..20),
            gen::actions(100, 0..20),
        ),
        |backend, (to_prepopulate, to_abort, to_commit)| {
            let model = Model::from_actions(to_prepopulate.clone());
            let store = backend.open(desc(1)).expect("db open to succeed");

            // Pre-populate the db with initial data, check the contents against the model
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.0, to_prepopulate.into_iter());
            dbtx.commit().unwrap();
            assert_eq!(model, Model::from_db(&store, IDX.0));

            // Apply another set of changes but abort the transaction
            let tx_model = {
                let mut tx_model = model.clone();
                tx_model.extend(to_abort.clone().into_iter());
                tx_model
            };
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.0, to_abort.into_iter());
            assert_eq!(tx_model, Model::from_tx(&dbtx, IDX.0));
            drop(dbtx);
            assert_eq!(model, Model::from_db(&store, IDX.0));

            // Apply a different set of operations, commit, check they have been performed
            let model = {
                let mut model = model;
                model.extend(to_commit.clone().into_iter());
                model
            };
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.0, to_commit.into_iter());
            dbtx.commit().unwrap();
            assert_eq!(model, Model::from_db(&store, IDX.0));
        },
    )
}

fn add_modify_abort_replay_commit<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    using_proptest(
        file!(),
        backend_fn,
        (gen::actions(100, 0..20), gen::actions(100, 0..20)),
        |backend, (initial, actions)| {
            let store = backend.open(desc(1)).expect("db open to succeed");

            // Pre-populate the db with initial data, check the contents against the model
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.0, initial.into_iter());
            dbtx.commit().unwrap();

            let initial_model = Model::from_db(&store, IDX.0);

            // Apply another set of changes but abort the transaction, check nothing changed
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.0, actions.clone().into_iter());
            let modified_model = Model::from_tx(&dbtx, IDX.0);
            drop(dbtx);
            assert_eq!(Model::from_db(&store, IDX.0), initial_model);

            // Apply the same changes again, and check that we get to the same state after commit
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.0, actions.into_iter());
            dbtx.commit().unwrap();
            assert_eq!(modified_model, Model::from_db(&store, IDX.0));
        },
    )
}

fn db_writes_do_not_interfere<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    using_proptest(
        file!(),
        backend_fn,
        (gen::actions(100, 0..20), gen::actions(100, 0..20)),
        |backend, (actions0, actions1)| {
            let store = backend.open(desc(2)).expect("db open to succeed");

            // Apply one set of operations to key-value map 0
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.0, actions0.into_iter());
            dbtx.commit().unwrap();
            let model = Model::from_db(&store, IDX.0);

            // Apply another set of operations to key-value map 1
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.1, actions1.into_iter());
            dbtx.commit().unwrap();

            // The values in key-value map 0 should remain untouched by the second set of changes
            assert_eq!(model, Model::from_db(&store, IDX.0));
        },
    )
}

fn empty_after_abort<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    using_proptest(
        file!(),
        backend_fn,
        (
            gen::actions(100, 0..20),
            gen::prop::collection::vec(gen::key(100), 0..20),
        ),
        |backend, (actions, keys)| {
            let store = backend.open(desc(5)).expect("db open to succeed");

            // Apply one set of operations to key-value map 0
            let model = Model::from_actions(actions.clone());
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.0, actions.into_iter());
            for key in &keys {
                assert_eq!(
                    dbtx.get(IDX.0, key).unwrap().as_ref().map(|v| v.as_ref()),
                    model.get(key)
                );
            }
            drop(dbtx);

            let dbtx = store.transaction_ro().unwrap();
            for key in &keys {
                assert_eq!(dbtx.get(IDX.0, key), Ok(None));
            }
        },
    )
}

fn prefix_iteration<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    using_proptest(
        file!(),
        backend_fn,
        (gen::actions(100, 0..20), gen::actions(100, 0..20)),
        |backend, (actions_a, actions_b)| {
            // Add prefixes to action keys
            fn add_prefix(pfx: u8, mut key: Data) -> Data {
                key.insert(0, pfx);
                key
            }
            let actions_a: Vec<WriteAction> =
                actions_a.into_iter().map(|act| act.map_key(|k| add_prefix(b'a', k))).collect();
            let actions_b: Vec<WriteAction> =
                actions_b.into_iter().map(|act| act.map_key(|k| add_prefix(b'b', k))).collect();

            // Open storage
            let store = backend.open(desc(5)).expect("db open to succeed");

            // Populate the database
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.0, actions_a.iter().chain(actions_b.iter()).cloned());
            dbtx.commit().unwrap();

            // Check iteration over keys prefixed "a"
            let model_a = Model::from_actions(actions_a);
            let dbtx = store.transaction_ro().unwrap();
            let iter_a = dbtx.prefix_iter(IDX.0, vec![b'a']).unwrap();
            assert!(model_a.into_iter().eq(iter_a));
            drop(dbtx);

            // Check iteration over keys prefixed "b"
            let model_b = Model::from_actions(actions_b);
            let dbtx = store.transaction_ro().unwrap();
            let iter_b = dbtx.prefix_iter(IDX.0, vec![b'b']).unwrap();
            assert!(model_b.into_iter().eq(iter_b));
            drop(dbtx);

            // Check there are no entries prefixed "c"
            let dbtx = store.transaction_ro().unwrap();
            assert_eq!(dbtx.prefix_iter(IDX.0, vec![b'c']).unwrap().next(), None);
            drop(dbtx);

            // Take all entries prefixed "a" and remove them
            let mut dbtx = store.transaction_rw().unwrap();
            let keys_a: Vec<_> =
                dbtx.prefix_iter(IDX.0, vec![b'a']).unwrap().map(|(k, _)| k).collect();
            for key in keys_a {
                dbtx.del(IDX.0, &key).unwrap();
            }
            dbtx.commit().unwrap();

            // Check there are no entries prefixed "a"
            let dbtx = store.transaction_ro().unwrap();
            assert_eq!(dbtx.prefix_iter(IDX.0, vec![b'a']).unwrap().next(), None);
            drop(dbtx);
        },
    )
}

fn post_commit_consistency<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    using_proptest(
        file!(),
        backend_fn,
        gen::actions(100, 0..50),
        |backend, actions| {
            // Open storage
            let store = backend.open(desc(1)).expect("db open to succeed");

            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.apply_actions(IDX.0, actions.into_iter());
            let model = Model::from_tx(&dbtx, IDX.0);
            dbtx.commit().unwrap();

            // The state from the transaction just before committing should de the same as the
            // state of the database after the commit.
            assert_eq!(Model::from_db(&store, IDX.0), model);
        },
    )
}

tests![
    add_and_delete,
    add_and_delete_some,
    add_modify_abort_modify_commit,
    add_modify_abort_replay_commit,
    db_writes_do_not_interfere,
    empty_after_abort,
    last_write_wins,
    overwrite_and_abort,
    post_commit_consistency,
    prefix_iteration,
];
