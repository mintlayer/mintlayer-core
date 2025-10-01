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

use crate::prelude::*;

const TEST_KEY: &[u8] = b"foo";

fn setup<B: Backend>(backend: B, init: Vec<u8>) -> B::Impl {
    let mut store = backend.open(desc(1)).expect("db open to succeed");

    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.put(MAPID.0, TEST_KEY.to_vec(), init).unwrap();
    dbtx.commit().unwrap();

    store
}

fn read_initialize_race<B: SharedBackend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
    let store = backend_factory.create().open(desc(1)).expect("db open to succeed");

    let thr0 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw(None).unwrap();
            dbtx.put(MAPID.0, TEST_KEY.to_vec(), vec![2]).unwrap();
            dbtx.commit().unwrap();
        }
    });

    let dbtx = store.transaction_ro().unwrap();
    let expected = [None, Some([2].as_ref())];
    assert!(expected.contains(&dbtx.get(MAPID.0, TEST_KEY).unwrap().as_ref().map(|v| v.as_ref())));
    drop(dbtx);

    thr0.join().unwrap();
}

fn read_write_race<B: SharedBackend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
    let store = setup(backend_factory.create(), vec![0]);

    let thr0 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw(None).unwrap();
            dbtx.put(MAPID.0, TEST_KEY.to_vec(), vec![2]).unwrap();
            dbtx.commit().unwrap();
        }
    });

    let dbtx = store.transaction_ro().unwrap();
    let expected = [[0u8].as_ref(), [2].as_ref()];
    assert!(expected
        .contains(&dbtx.get(MAPID.0, TEST_KEY).unwrap().as_ref().map(|v| v.as_ref()).unwrap()));
    drop(dbtx);

    thr0.join().unwrap();
}

fn commutative_read_modify_write<B: SharedBackend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
    let store = setup(backend_factory.create(), vec![0]);

    let thr0 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw(None).unwrap();
            let v = dbtx.get(MAPID.0, TEST_KEY).unwrap().unwrap();
            let b = v.first().unwrap();
            dbtx.put(MAPID.0, TEST_KEY.to_vec(), vec![b + 5]).unwrap();
            dbtx.commit().unwrap();
        }
    });
    let thr1 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw(None).unwrap();
            let v = dbtx.get(MAPID.0, TEST_KEY).unwrap().unwrap();
            let b = v.first().unwrap();
            dbtx.put(MAPID.0, TEST_KEY.to_vec(), vec![b + 3]).unwrap();
            dbtx.commit().unwrap();
        }
    });

    thr0.join().unwrap();
    thr1.join().unwrap();

    let dbtx = store.transaction_ro().unwrap();
    assert_eq!(
        dbtx.get(MAPID.0, TEST_KEY).unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        [8].as_ref()
    );
}

// Test parallel reading through a normal Backend. A reference to BackendImpl is shared between threads.
// Note that it's disabled for loom, where thread::scope is not available.
#[cfg(not(loom))]
fn threaded_reads_consistent_for_ordinary_backend<B: Backend, F: BackendFactory<B>>(
    backend_factory: Arc<F>,
) {
    let val = [0x77, 0x88, 0x99].as_ref();
    let store = setup(backend_factory.create(), val.to_vec());

    thread::scope(|s| {
        let thr0 = s.spawn({
            || {
                for _ in 0..100 {
                    let tx = store.transaction_ro().unwrap();
                    let obtained_val = tx.get(MAPID.0, TEST_KEY).unwrap().unwrap();
                    assert_eq!(obtained_val, val);
                }
            }
        });
        let thr1 = s.spawn({
            || {
                for _ in 0..100 {
                    let tx = store.transaction_ro().unwrap();
                    let obtained_val = tx.get(MAPID.0, TEST_KEY).unwrap().unwrap();
                    assert_eq!(obtained_val, val);
                }
            }
        });

        thr0.join().unwrap();
        thr1.join().unwrap();
    });
}

// A stub for loom
#[cfg(loom)]
fn threaded_reads_consistent_for_ordinary_backend<B: Backend, F: BackendFactory<B>>(
    _backend_factory: Arc<F>,
) {
}

// Test parallel reading through a SharedBackend. A copy of SharedBackendImpl is shared between threads.
fn threaded_reads_consistent_for_shared_backend<B: SharedBackend, F: BackendFactory<B>>(
    backend_factory: Arc<F>,
) {
    let val = [0x77, 0x88, 0x99].as_ref();
    let store = setup(backend_factory.create(), val.to_vec());

    #[cfg(not(loom))]
    let iter_count = 100;
    // Note: under loom, with only 10 iterations the test takes more than 3 minutes to complete.
    // With 5 iterations, the time is under 2 seconds.
    #[cfg(loom)]
    let iter_count = 5;

    let thr0 = thread::spawn({
        let store = store.clone();
        move || {
            for _ in 0..iter_count {
                let tx = store.transaction_ro().unwrap();
                let obtained_val = tx.get(MAPID.0, TEST_KEY).unwrap().unwrap();
                assert_eq!(obtained_val, val);
            }
        }
    });
    let thr1 = thread::spawn({
        move || {
            for _ in 0..iter_count {
                let tx = store.transaction_ro().unwrap();
                let obtained_val = tx.get(MAPID.0, TEST_KEY).unwrap().unwrap();
                assert_eq!(obtained_val, val);
            }
        }
    });

    thr0.join().unwrap();
    thr1.join().unwrap();
}

fn write_different_keys_and_iterate<B: SharedBackend, F: BackendFactory<B>>(
    backend_factory: Arc<F>,
) {
    let store = backend_factory.create().open(desc(1)).expect("db open to succeed");

    let thr0 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw(None).unwrap();
            dbtx.put(MAPID.0, vec![0x01], vec![0xf1]).unwrap();
            dbtx.commit().unwrap();
        }
    });
    let thr1 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw(None).unwrap();
            dbtx.put(MAPID.0, vec![0x02], vec![0xf2]).unwrap();
            dbtx.commit().unwrap();
        }
    });

    thr0.join().unwrap();
    thr1.join().unwrap();

    let dbtx = store.transaction_ro().unwrap();
    let contents = dbtx.prefix_iter(MAPID.0, vec![]).unwrap();
    let expected = [(vec![0x01], vec![0xf1]), (vec![0x02], vec![0xf2])];
    assert!(contents.eq(expected));
}

shared_backend_tests![
    commutative_read_modify_write,
    read_initialize_race,
    read_write_race,
    threaded_reads_consistent_for_shared_backend,
    write_different_keys_and_iterate,
];

common_tests![threaded_reads_consistent_for_ordinary_backend];
