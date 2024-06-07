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

use test_utils::random::{make_seedable_rng, Rng};

mod iter_sort_preserving_numbers {
    use serialization::{Decode, Encode};
    use storage::{decl_schema, MakeMapRef, OrderPreservingValue, Storage};
    use utils::sorted::Sorted;

    use crate::with_rng_seed;

    use super::*;

    #[derive(Encode, Decode, Clone, Eq, PartialEq, Debug)]
    struct CompoundKey {
        main_part: OrderPreservingValue<u64>,
        aux_part: u64,
    }

    decl_schema! {
        TestSchema {
            TestMap: Map<CompoundKey, ()>,
        }
    }

    pub fn test<B: Backend, F: BackendFn<B>>(backend_fn: Arc<F>) {
        let storage = Storage::<_, TestSchema>::new(backend_fn()).unwrap();

        with_rng_seed(move |seed| {
            let mut rng = make_seedable_rng(seed);

            let test_values = (0..100)
                .map(|_| CompoundKey {
                    main_part: OrderPreservingValue::new(rng.gen::<u64>()),
                    aux_part: rng.gen::<u64>(),
                })
                .collect::<Vec<_>>();

            let mut dbtx = storage.transaction_rw(None).unwrap();
            let mut map = dbtx.get_mut::<TestMap, _>();
            for val in &test_values {
                map.put(val, ()).unwrap();
            }
            dbtx.commit().unwrap();

            let sorted_test_values = test_values.sorted_by(|v1, v2| {
                // Note: we explicitly sort by "inner".
                v1.main_part.inner().cmp(&v2.main_part.inner())
            });

            let i = rng.gen_range(0..test_values.len() - 1);

            let dbtx = storage.transaction_ro().unwrap();
            let items = dbtx
                .get::<TestMap, _>()
                .greater_equal_iter_keys(&sorted_test_values[i])
                .unwrap()
                .collect::<Vec<_>>();
            assert_eq!(items, &sorted_test_values[i..]);
        });
    }
}

tests![iter_sort_preserving_numbers::test];
