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

fn put_and_commit<B: Backend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
    let mut store = backend_factory.create().open(desc(1)).expect("db open to succeed");

    // Create a transaction, modify the storage and commit
    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.put(MAPID.0, b"hello".to_vec(), b"world".to_vec()).unwrap();
    dbtx.commit().expect("commit to succeed");

    // Check the modification did happen
    let dbtx = store.transaction_ro().unwrap();
    assert_eq!(
        dbtx.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        b"world".as_ref()
    );
    drop(dbtx);
}

fn put_and_abort<B: Backend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
    let mut store = backend_factory.create().open(desc(1)).expect("db open to succeed");

    // Create a transaction, modify storage and abort transaction
    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.put(MAPID.0, b"hello".to_vec(), b"world".to_vec()).unwrap();
    drop(dbtx);

    // Check the modification did not happen
    let dbtx = store.transaction_ro().unwrap();
    assert_eq!(dbtx.get(MAPID.0, b"hello"), Ok(None));
    drop(dbtx);
}

fn put_two_under_different_keys<B: Backend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
    let mut store = backend_factory.create().open(desc(1)).expect("db open to succeed");

    // Create a transaction, modify storage and commit
    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.put(MAPID.0, b"a".to_vec(), b"0".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"b".to_vec(), b"1".to_vec()).unwrap();
    dbtx.commit().expect("commit to succeed");

    // Check the values are in place
    let dbtx = store.transaction_ro().unwrap();
    assert_eq!(
        dbtx.get(MAPID.0, b"a").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        b"0".as_ref()
    );
    assert_eq!(
        dbtx.get(MAPID.0, b"b").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        b"1".as_ref()
    );
    drop(dbtx);

    // Create a transaction, modify storage and abort
    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.put(MAPID.0, b"a".to_vec(), b"00".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"b".to_vec(), b"11".to_vec()).unwrap();
    drop(dbtx);

    // Check the modification did not happen
    let dbtx = store.transaction_ro().unwrap();
    assert_eq!(
        dbtx.get(MAPID.0, b"a").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        b"0".as_ref()
    );
    assert_eq!(
        dbtx.get(MAPID.0, b"b").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        b"1".as_ref()
    );
    drop(dbtx);
}

fn put_twice_then_commit_read_last<B: Backend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
    let mut store = backend_factory.create().open(desc(1)).expect("db open to succeed");

    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.put(MAPID.0, b"hello".to_vec(), b"a".to_vec()).unwrap();
    assert_eq!(
        dbtx.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        b"a".as_ref(),
    );
    dbtx.put(MAPID.0, b"hello".to_vec(), b"b".to_vec()).unwrap();
    assert_eq!(
        dbtx.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        b"b".as_ref(),
    );
    dbtx.commit().expect("commit to succeed");

    let dbtx = store.transaction_ro().unwrap();
    assert_eq!(
        dbtx.get(MAPID.0, b"hello").unwrap().as_ref().map(|v| v.as_ref()).unwrap(),
        b"b".as_ref(),
    );
}

fn put_iterator_count_matches<B: Backend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
    let mut store = backend_factory.create().open(desc(1)).expect("db open to succeed");

    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.put(MAPID.0, vec![0x00], vec![]).unwrap();
    dbtx.put(MAPID.0, vec![0x01], vec![]).unwrap();
    dbtx.put(MAPID.0, vec![0x02], vec![]).unwrap();
    dbtx.put(MAPID.0, vec![0x03], vec![]).unwrap();
    dbtx.commit().expect("commit to succeed");

    let dbtx = store.transaction_ro().unwrap();
    assert_eq!(dbtx.prefix_iter(MAPID.0, vec![]).unwrap().count(), 4);
    assert_eq!(dbtx.greater_equal_iter(MAPID.0, vec![]).unwrap().count(), 4);
}

fn put_and_iterate<B: Backend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
    let mut store = backend_factory.create().open(desc(1)).expect("db open to succeed");

    // Populate the database with some values
    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.put(MAPID.0, b"ac".to_vec(), b"2".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"bf".to_vec(), b"7".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"ab".to_vec(), b"1".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"aca".to_vec(), b"3".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"bz".to_vec(), b"8".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"x".to_vec(), b"9".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"bb".to_vec(), b"6".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"b".to_vec(), b"5".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"acb".to_vec(), b"4".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"aa".to_vec(), b"0".to_vec()).unwrap();
    dbtx.commit().expect("commit to succeed");

    // prefix_iter
    {
        let check = |range: std::ops::Range<usize>, prefix: Data| {
            let dbtx = store.transaction_ro().unwrap();
            let vals: Vec<_> =
                dbtx.prefix_iter(MAPID.0, prefix.clone()).unwrap().map(|x| x.1).collect();
            let expected: Vec<_> = range.map(|x| Data::from(x.to_string())).collect();
            assert_eq!(vals, expected, "prefix={prefix:?}");
            drop(dbtx);
        };

        check(0..10, b"".to_vec());
        check(0..5, b"a".to_vec());
        check(0..1, b"aa".to_vec());
        check(2..5, b"ac".to_vec());
        check(5..9, b"b".to_vec());
        check(9..10, b"x".to_vec());
        check(0..0, b"foo".to_vec());
        check(0..0, b"zzz".to_vec());
    }

    // greater_equal_iter
    {
        let check = |range: std::ops::Range<usize>, prefix: Data| {
            let dbtx = store.transaction_ro().unwrap();
            let vals: Vec<_> =
                dbtx.greater_equal_iter(MAPID.0, prefix.clone()).unwrap().map(|x| x.1).collect();
            let expected: Vec<_> = range.map(|x| Data::from(x.to_string())).collect();
            assert_eq!(vals, expected, "prefix={prefix:?}");
            drop(dbtx);
        };

        check(0..10, b"".to_vec());
        check(0..10, b"a".to_vec());
        check(0..10, b"aa".to_vec());
        check(2..10, b"ac".to_vec());
        check(5..10, b"b".to_vec());
        check(9..10, b"x".to_vec());
        check(9..10, b"foo".to_vec());
        check(0..0, b"zzz".to_vec());
    }
}

fn check_prefix_iter<Tx: ReadOps>(dbtx: &Tx, prefix: Data, expected: &[(&str, &str)]) {
    let entries = dbtx.prefix_iter(MAPID.0, prefix).unwrap();
    let expected = expected
        .iter()
        .map(|(x, y)| (Data::from(x.to_string()), Data::from(y.to_string())));
    assert!(entries.eq(expected));
}

fn check_greater_equal_iter<Tx: ReadOps>(dbtx: &Tx, key: Data, expected: &[(&str, &str)]) {
    let entries = dbtx.greater_equal_iter(MAPID.0, key).unwrap();
    let expected = expected
        .iter()
        .map(|(x, y)| (Data::from(x.to_string()), Data::from(y.to_string())));
    assert!(entries.eq(expected));
}

fn put_and_iterate_delete_some<B: Backend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
    let mut store = backend_factory.create().open(desc(1)).expect("db open to succeed");

    let expected_full_0 =
        [("aa", "0"), ("ab", "1"), ("ac", "2"), ("aca", "3"), ("acb", "4"), ("b", "5")];
    let expected_pfx_aa_0 = [("aa", "0")];
    let expected_pfx_ac_0 = [("ac", "2"), ("aca", "3"), ("acb", "4")];
    let expected_ge_ac_0 = [("ac", "2"), ("aca", "3"), ("acb", "4"), ("b", "5")];

    // Populate the database with some
    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.put(MAPID.0, b"aa".to_vec(), b"0".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"ab".to_vec(), b"1".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"ac".to_vec(), b"2".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"aca".to_vec(), b"3".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"acb".to_vec(), b"4".to_vec()).unwrap();
    dbtx.put(MAPID.0, b"b".to_vec(), b"5".to_vec()).unwrap();
    // Check db contents
    check_prefix_iter(&dbtx, b"".to_vec(), &expected_full_0);
    check_prefix_iter(&dbtx, b"aa".to_vec(), &expected_pfx_aa_0);
    check_prefix_iter(&dbtx, b"ac".to_vec(), &expected_pfx_ac_0);
    check_greater_equal_iter(&dbtx, b"".to_vec(), &expected_full_0);
    check_greater_equal_iter(&dbtx, b"aa".to_vec(), &expected_full_0);
    check_greater_equal_iter(&dbtx, b"ac".to_vec(), &expected_ge_ac_0);
    dbtx.commit().expect("commit to succeed");

    // Check db contents after a commit
    let dbtx = store.transaction_ro().unwrap();
    check_prefix_iter(&dbtx, b"".to_vec(), &expected_full_0);
    check_prefix_iter(&dbtx, b"aa".to_vec(), &expected_pfx_aa_0);
    check_prefix_iter(&dbtx, b"ac".to_vec(), &expected_pfx_ac_0);
    check_greater_equal_iter(&dbtx, b"".to_vec(), &expected_full_0);
    check_greater_equal_iter(&dbtx, b"aa".to_vec(), &expected_full_0);
    check_greater_equal_iter(&dbtx, b"ac".to_vec(), &expected_ge_ac_0);
    drop(dbtx);

    let expected_full_1 = [("aa", "0"), ("ac", "2"), ("acb", "4"), ("b", "5")];
    let expected_pfx_aa_1 = [("aa", "0")];
    let expected_pfx_ac_1 = [("ac", "2"), ("acb", "4")];
    let expected_ge_ac_1 = [("ac", "2"), ("acb", "4"), ("b", "5")];

    // Delete some entries
    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.del(MAPID.0, b"aca").unwrap();
    dbtx.del(MAPID.0, b"ab").unwrap();
    // Check updated contents
    check_prefix_iter(&dbtx, b"".to_vec(), &expected_full_1);
    check_prefix_iter(&dbtx, b"aa".to_vec(), &expected_pfx_aa_1);
    check_prefix_iter(&dbtx, b"ac".to_vec(), &expected_pfx_ac_1);
    check_greater_equal_iter(&dbtx, b"".to_vec(), &expected_full_1);
    check_greater_equal_iter(&dbtx, b"aa".to_vec(), &expected_full_1);
    check_greater_equal_iter(&dbtx, b"ac".to_vec(), &expected_ge_ac_1);
    // Abort the transaction
    drop(dbtx);

    // Check updated contents after a commit
    let dbtx = store.transaction_ro().unwrap();
    check_prefix_iter(&dbtx, b"".to_vec(), &expected_full_0);
    check_prefix_iter(&dbtx, b"aa".to_vec(), &expected_pfx_aa_0);
    check_prefix_iter(&dbtx, b"ac".to_vec(), &expected_pfx_ac_0);
    check_greater_equal_iter(&dbtx, b"".to_vec(), &expected_full_0);
    check_greater_equal_iter(&dbtx, b"aa".to_vec(), &expected_full_0);
    check_greater_equal_iter(&dbtx, b"ac".to_vec(), &expected_ge_ac_0);
    drop(dbtx);

    // Delete the items, this time for real
    let mut dbtx = store.transaction_rw(None).unwrap();
    dbtx.del(MAPID.0, b"aca").unwrap();
    dbtx.del(MAPID.0, b"ab").unwrap();
    // Check updated contents
    check_prefix_iter(&dbtx, b"".to_vec(), &expected_full_1);
    check_prefix_iter(&dbtx, b"aa".to_vec(), &expected_pfx_aa_1);
    check_prefix_iter(&dbtx, b"ac".to_vec(), &expected_pfx_ac_1);
    check_greater_equal_iter(&dbtx, b"".to_vec(), &expected_full_1);
    check_greater_equal_iter(&dbtx, b"aa".to_vec(), &expected_full_1);
    check_greater_equal_iter(&dbtx, b"ac".to_vec(), &expected_ge_ac_1);
    // Abort the transaction
    dbtx.commit().unwrap();

    // Check updated contents after a commit
    let dbtx = store.transaction_ro().unwrap();
    check_prefix_iter(&dbtx, b"".to_vec(), &expected_full_1);
    check_prefix_iter(&dbtx, b"aa".to_vec(), &expected_pfx_aa_1);
    check_prefix_iter(&dbtx, b"ac".to_vec(), &expected_pfx_ac_1);
    check_greater_equal_iter(&dbtx, b"".to_vec(), &expected_full_1);
    check_greater_equal_iter(&dbtx, b"aa".to_vec(), &expected_full_1);
    check_greater_equal_iter(&dbtx, b"ac".to_vec(), &expected_ge_ac_1);
    drop(dbtx);
}

common_tests![
    put_and_abort,
    put_and_commit,
    put_and_iterate_delete_some,
    put_and_iterate,
    put_iterator_count_matches,
    put_twice_then_commit_read_last,
    put_two_under_different_keys,
];
