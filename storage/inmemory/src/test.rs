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

use storage_core::traits::*;

storage_core::decl_schema! {
    MySchema {
        MyMap: Single,
    }
}

type MyStore = crate::Store<MySchema>;

fn generic_aborted_write<St: Backend<MySchema>>(store: &St) -> storage_core::Result<()> {
    store.transaction_rw().run(|tx| {
        tx.get_mut::<MyMap, _>().put(b"hello".to_vec(), b"world".to_vec())?;
        storage_core::abort(())
    })
}

#[test]
fn test_abort() {
    common::concurrency::model(|| {
        let store = MyStore::default();

        let r = generic_aborted_write(&store);
        assert_eq!(r, Ok(()));

        let r = store
            .transaction_ro()
            .run(|tx| Ok(tx.get::<MyMap, _>().get(b"hello")?.is_some()));
        assert_eq!(r, Ok(false));
    })
}
