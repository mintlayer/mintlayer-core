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

use storage_core::Data;

use utils::sorted::Sorted;

use super::*;

decl_schema! {
    Schema {
        Map1: Map<Data, Data>,
    }
}

#[test]
fn empty_ro() {
    utils::concurrency::model(|| {
        let store = Storage::<_, Schema>::new(storage_inmemory::InMemory::new()).unwrap();
        let tx = store.transaction_ro().unwrap();
        assert_eq!(tx.get::<Map1, _>().get(&b"foo".to_vec()), Ok(None));
    });
}

#[test]
fn empty_rw() {
    utils::concurrency::model(|| {
        let store = Storage::<_, Schema>::new(storage_inmemory::InMemory::new()).unwrap();
        let tx = store.transaction_rw(None).unwrap();
        assert_eq!(tx.get::<Map1, _>().get(&b"foo".to_vec()), Ok(None));
    });
}

decl_schema! {
    // Schema with a compound key
    Compound {
        Map2: Map<(String, u16), u64>,
    }
}

#[test]
fn iteration() {
    utils::concurrency::model(|| {
        let store = Storage::<_, Compound>::new(storage_inmemory::InMemory::new()).unwrap();

        let test_values = [
            ((String::from("foo"), 12), 0),
            ((String::from("foo"), 1), 1),
            ((String::from("foo"), 2), 2),
            ((String::from("bar"), 42), 3),
            ((String::from("bar"), 43), 4),
            ((String::from("hello"), 1337), 6),
        ];

        // prefix iteration
        {
            // Populate the database
            let mut dbtx = store.transaction_rw(None).unwrap();
            let mut map = dbtx.get_mut::<Map2, _>();
            for (key, val) in &test_values {
                map.put(key, val).unwrap();
            }
            dbtx.commit().unwrap();

            // Iterate over the "foo" prefix
            let dbtx = store.transaction_ro().unwrap();
            let items: Vec<_> = dbtx
                .get::<Map2, _>()
                .prefix_iter(&("foo".into(),))
                .unwrap()
                .map(|((_, k), v)| (k, v.decode()))
                .collect();
            let expected_items = vec![(1, 1), (2, 2), (12, 0)];
            assert_eq!(items, expected_items);
            dbtx.close();

            // Iterate over the "foo" prefix via prefix_iter_keys
            let dbtx = store.transaction_ro().unwrap();
            let keys: Vec<_> = dbtx
                .get::<Map2, _>()
                .prefix_iter_keys(&("foo".into(),))
                .unwrap()
                .map(|(_, k)| k)
                .collect();
            let expected_keys = vec![1, 2, 12];
            assert_eq!(keys, expected_keys);
            dbtx.close();

            // Iterate over the "foo" prefix decoded
            let dbtx = store.transaction_ro().unwrap();
            let items: Vec<_> = dbtx
                .get::<Map2, _>()
                .prefix_iter_decoded(&("foo".into(),))
                .unwrap()
                .map(|((_, k), v)| (k, v))
                .collect();
            assert_eq!(items, expected_items);
            dbtx.close();

            // Iterate over all values
            let test_values_sorted = test_values.to_vec().sorted();
            let dbtx = store.transaction_ro().unwrap();
            let items: Vec<_> = dbtx
                .get::<Map2, _>()
                .prefix_iter(&())
                .unwrap()
                .map(|(k, v)| (k, v.decode()))
                .collect();
            assert_eq!(items, test_values_sorted);
            dbtx.close();

            // Iterate over all decoded values
            let dbtx = store.transaction_ro().unwrap();
            let items: Vec<_> = dbtx.get::<Map2, _>().prefix_iter_decoded(&()).unwrap().collect();
            assert_eq!(items, test_values_sorted);
            dbtx.close();
        }

        // greater-equal iteration
        {
            // Populate the database
            let mut dbtx = store.transaction_rw(None).unwrap();
            let mut map = dbtx.get_mut::<Map2, _>();
            for (key, val) in &test_values {
                map.put(key, val).unwrap();
            }
            dbtx.commit().unwrap();

            // Iterate starting from "foo"
            let dbtx = store.transaction_ro().unwrap();
            let items: Vec<_> = dbtx
                .get::<Map2, _>()
                .greater_equal_iter(&("foo".into(), 0))
                .unwrap()
                .map(|((_, k), v)| (k, v.decode()))
                .collect();
            let expected_items = vec![(1, 1), (2, 2), (12, 0), (1337, 6)];
            assert_eq!(items, expected_items);
            dbtx.close();

            // Iterate starting from "foo" via greater_equal_iter_keys
            let dbtx = store.transaction_ro().unwrap();
            let keys: Vec<_> = dbtx
                .get::<Map2, _>()
                .greater_equal_iter_keys(&("foo".into(), 0))
                .unwrap()
                .map(|(_, k)| k)
                .collect();
            let expected_keys = vec![1, 2, 12, 1337];
            assert_eq!(keys, expected_keys);
            dbtx.close();

            // Iterate starting from "foo" via greater_equal_iter_decoded
            let dbtx = store.transaction_ro().unwrap();
            let items: Vec<_> = dbtx
                .get::<Map2, _>()
                .greater_equal_iter_decoded(&("foo".into(), 0))
                .unwrap()
                .map(|((_, k), v)| (k, v))
                .collect();
            assert_eq!(items, expected_items);
            dbtx.close();

            // Iterate over all values
            let test_values_sorted = {
                let mut values = test_values;
                values.sort();
                values
            };
            let dbtx = store.transaction_ro().unwrap();
            let items: Vec<_> = dbtx
                .get::<Map2, _>()
                .greater_equal_iter(&("".into(), 0))
                .unwrap()
                .map(|(k, v)| (k, v.decode()))
                .collect();
            assert_eq!(items, test_values_sorted);
            dbtx.close();

            // Iterate over all decoded values
            let dbtx = store.transaction_ro().unwrap();
            let items: Vec<_> = dbtx
                .get::<Map2, _>()
                .greater_equal_iter_decoded(&("".into(), 0))
                .unwrap()
                .collect();
            assert_eq!(items, test_values_sorted);
            dbtx.close();
        }
    });
}
