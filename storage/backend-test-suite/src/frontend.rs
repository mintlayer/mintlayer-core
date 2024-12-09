// Copyright (c) 2021-2024 RBB S.r.l
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

// Here are some tests that actually need to use the frontend (i.e. the storage crate itself).
// We keep them in `backend-test-suite` because we want to run them for all possible backends.

use crate::prelude::*;

use test_utils::random::{gen_random_bytes, make_seedable_rng, Rng};

mod iter_sort_preserving_numbers {
    use serialization::{Decode, Encode};
    use storage::{decl_schema, MakeMapRef, OrderPreservingValue, Storage};
    use utils::sorted::Sorted;

    use crate::with_rng_seed;

    use super::*;

    #[derive(Encode, Decode, Clone, Eq, PartialEq, Debug)]
    pub struct CompoundKey1 {
        pub main_part: OrderPreservingValue<u64>,
        pub aux_part: Vec<u8>,
    }

    mod test_schema1 {
        use super::*;

        decl_schema! {
            pub Schema {
                pub TestMap: Map<CompoundKey1, ()>,
            }
        }
    }

    pub fn test1<B: Backend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
        use test_schema1::{Schema, TestMap};

        let mut storage = Storage::<_, Schema>::new(backend_factory.create()).unwrap();

        with_rng_seed(move |seed| {
            let mut rng = make_seedable_rng(seed);

            let test_values = (0..100)
                .map(|_| CompoundKey1 {
                    main_part: OrderPreservingValue::new(rng.gen::<u64>()),
                    aux_part: gen_random_bytes(&mut rng, 1, 100),
                })
                .collect::<Vec<_>>();

            let mut dbtx = storage.transaction_rw(None).unwrap();
            let mut map = dbtx.get_mut::<TestMap, _>();
            for val in &test_values {
                map.put(val, ()).unwrap();
            }
            dbtx.commit().unwrap();

            let sorted_test_values = test_values.clone().sorted_by(|v1, v2| {
                // Note: we explicitly sort by "inner".
                v1.main_part.inner().cmp(&v2.main_part.inner())
            });

            let i = rng.gen_range(0..test_values.len() - 1);

            let item = &sorted_test_values[i];
            let expected_ge_items = &sorted_test_values[i..];
            let dbtx = storage.transaction_ro().unwrap();
            let ge_items = dbtx
                .get::<TestMap, _>()
                .greater_equal_iter_keys(item)
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(ge_items, expected_ge_items);

            // Do the same search, but now with zeroed aux_part.
            let item_with_zeroed_aux_part = CompoundKey1 {
                main_part: item.main_part,
                aux_part: vec![0; item.aux_part.len()],
            };
            let ge_items = dbtx
                .get::<TestMap, _>()
                .greater_equal_iter_keys(&item_with_zeroed_aux_part)
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(ge_items, expected_ge_items);
        });
    }

    // test2 is the same as test1 but here we use a tuple instead of a custom struct.
    type CompoundKey2 = (OrderPreservingValue<u64>, Vec<u8>);

    mod test_schema2 {
        use super::*;

        decl_schema! {
            pub Schema {
                pub TestMap: Map<CompoundKey2, ()>,
            }
        }
    }

    pub fn test2<B: Backend, F: BackendFactory<B>>(backend_factory: Arc<F>) {
        use test_schema2::{Schema, TestMap};

        let mut storage = Storage::<_, Schema>::new(backend_factory.create()).unwrap();

        with_rng_seed(move |seed| {
            let mut rng = make_seedable_rng(seed);

            let test_values = (0..100)
                .map(|_| {
                    (
                        OrderPreservingValue::new(rng.gen::<u64>()),
                        gen_random_bytes(&mut rng, 1, 100),
                    )
                })
                .collect::<Vec<_>>();

            let mut dbtx = storage.transaction_rw(None).unwrap();
            let mut map = dbtx.get_mut::<TestMap, _>();
            for val in &test_values {
                map.put(val, ()).unwrap();
            }
            dbtx.commit().unwrap();

            let sorted_test_values = test_values.clone().sorted_by(|v1, v2| {
                // Note: we explicitly sort by "inner".
                v1.0.inner().cmp(&v2.0.inner())
            });

            let i = rng.gen_range(0..test_values.len() - 1);

            let item = &sorted_test_values[i];
            let expected_ge_items = &sorted_test_values[i..];
            let dbtx = storage.transaction_ro().unwrap();
            let ge_items = dbtx
                .get::<TestMap, _>()
                .greater_equal_iter_keys(item)
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(ge_items, expected_ge_items);

            // Do the same search, but now with zeroed aux_part.
            let item_with_zeroed_aux_part = (item.0, vec![0; item.1.len()]);
            let ge_items = dbtx
                .get::<TestMap, _>()
                .greater_equal_iter_keys(&item_with_zeroed_aux_part)
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(ge_items, expected_ge_items);
        });
    }
}

common_tests![iter_sort_preserving_numbers::test1, iter_sort_preserving_numbers::test2];
