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
    let store = backend.open(desc(1)).expect("db open to succeed");

    let mut dbtx = store.transaction_rw().unwrap();
    dbtx.put(IDX.0, TEST_KEY.to_vec(), init).unwrap();
    dbtx.commit().unwrap();

    store
}

fn read_initialize_race<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    let store = backend_fn().open(desc(1)).expect("db open to succeed");

    let thr0 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.put(IDX.0, TEST_KEY.to_vec(), vec![2]).unwrap();
            dbtx.commit().unwrap();
        }
    });

    let dbtx = store.transaction_ro().unwrap();
    let expected = [None, Some([2].as_ref())];
    assert!(expected.contains(&dbtx.get(IDX.0, TEST_KEY).unwrap()));
    drop(dbtx);

    thr0.join().unwrap();
}

fn read_write_race<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    let store = setup(backend_fn(), vec![0]);

    let thr0 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.put(IDX.0, TEST_KEY.to_vec(), vec![2]).unwrap();
            dbtx.commit().unwrap();
        }
    });

    let dbtx = store.transaction_ro().unwrap();
    let expected = [[0u8].as_ref(), [2].as_ref()];
    assert!(expected.contains(&dbtx.get(IDX.0, TEST_KEY).unwrap().unwrap()));
    drop(dbtx);

    thr0.join().unwrap();
}

fn commutative_read_modify_write<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    let store = setup(backend_fn(), vec![0]);

    let thr0 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw().unwrap();
            let b = dbtx.get(IDX.0, TEST_KEY).unwrap().unwrap().first().unwrap();
            dbtx.put(IDX.0, TEST_KEY.to_vec(), vec![b + 5]).unwrap();
            dbtx.commit().unwrap();
        }
    });
    let thr1 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw().unwrap();
            let b = dbtx.get(IDX.0, TEST_KEY).unwrap().unwrap().first().unwrap();
            dbtx.put(IDX.0, TEST_KEY.to_vec(), vec![b + 3]).unwrap();
            dbtx.commit().unwrap();
        }
    });

    thr0.join().unwrap();
    thr1.join().unwrap();

    let dbtx = store.transaction_ro().unwrap();
    assert_eq!(dbtx.get(IDX.0, TEST_KEY), Ok(Some([8].as_ref())));
}

fn threaded_reads_consistent<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    let val = [0x77, 0x88, 0x99].as_ref();
    let store = setup(backend_fn(), val.to_vec());

    let thr0 = thread::spawn({
        let store = store.clone();
        move || {
            store
                .transaction_ro()
                .unwrap()
                .get(IDX.0, TEST_KEY)
                .unwrap()
                .unwrap()
                .to_owned()
        }
    });
    let thr1 = thread::spawn({
        move || {
            store
                .transaction_ro()
                .unwrap()
                .get(IDX.0, TEST_KEY)
                .unwrap()
                .unwrap()
                .to_owned()
        }
    });

    assert_eq!(thr0.join().unwrap(), val);
    assert_eq!(thr1.join().unwrap(), val);
}

fn write_different_keys_and_iterate<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
    let store = backend_fn().open(desc(1)).expect("db open to succeed");

    let thr0 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.put(IDX.0, vec![0x01], vec![0xf1]).unwrap();
            dbtx.commit().unwrap();
        }
    });
    let thr1 = thread::spawn({
        let store = store.clone();
        move || {
            let mut dbtx = store.transaction_rw().unwrap();
            dbtx.put(IDX.0, vec![0x02], vec![0xf2]).unwrap();
            dbtx.commit().unwrap();
        }
    });

    thr0.join().unwrap();
    thr1.join().unwrap();

    let dbtx = store.transaction_ro().unwrap();
    let contents = dbtx.prefix_iter(IDX.0, vec![]).unwrap();
    let expected = [(vec![0x01], vec![0xf1]), (vec![0x02], vec![0xf2])];
    assert!(contents.eq(expected));
}

tests![
    commutative_read_modify_write,
    read_initialize_race,
    read_write_race,
    threaded_reads_consistent,
    write_different_keys_and_iterate,
];
