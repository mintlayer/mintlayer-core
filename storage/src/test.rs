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
use storage_core::Data;

decl_schema! {
    Schema {
        Map1: Map<Data, Data>,
    }
}

#[test]
fn empty_ro() {
    utils::concurrency::model(|| {
        let store = Storage::<_, Schema>::new(inmemory::InMemory::new()).unwrap();
        let tx = store.transaction_ro().unwrap();
        assert_eq!(tx.get::<Map1, _>().get(&b"foo".to_vec()), Ok(None));
    });
}

#[test]
fn empty_rw() {
    utils::concurrency::model(|| {
        let store = Storage::<_, Schema>::new(inmemory::InMemory::new()).unwrap();
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
fn prefix_iteration() {
    utils::concurrency::model(|| {
        let store = Storage::<_, Compound>::new(inmemory::InMemory::new()).unwrap();

        let test_values = [
            ((String::from("foo"), 12), 0),
            ((String::from("foo"), 1), 1),
            ((String::from("foo"), 2), 2),
            ((String::from("bar"), 42), 3),
            ((String::from("bar"), 43), 4),
            ((String::from("hello"), 1337), 6),
        ];

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
        let expected = vec![(1, 1), (2, 2), (12, 0)];
        assert_eq!(items, expected);
        dbtx.close();

        // Iterate over the "foo" prefix decoded
        let dbtx = store.transaction_ro().unwrap();
        let items: Vec<_> = dbtx
            .get::<Map2, _>()
            .prefix_iter_decoded(&("foo".into(),))
            .unwrap()
            .map(|((_, k), v)| (k, v))
            .collect();
        assert_eq!(items, expected);
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
            .prefix_iter(&())
            .unwrap()
            .map(|(k, v)| (k, v.decode()))
            .collect();
        assert_eq!(items, test_values_sorted);
        dbtx.close();

        // Iterate over all decoded values
        let dbtx = store.transaction_ro().unwrap();
        let items: Vec<_> = dbtx
            .get::<Map2, _>()
            .prefix_iter_decoded(&())
            .unwrap()
            .map(|(k, v)| (k, v))
            .collect();
        assert_eq!(items, test_values_sorted);
        dbtx.close();
    });
}
