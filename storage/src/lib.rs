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

//! Storage interface
//!
//! Storage is a collection of key-value maps. Each key-value map is addressed by an index. Index
//! kind specifies whether a key is mapped to just a single value or to a collection of values.
//!
//! # Basic storage
//!
//! For now, only basic storage implementation is provided. It is to be replaced with a proper one
//! abstracting over storage backend and a more complete feature set.
//!
//! # Example
//!
//! ```
//! # use storage::{schema, Storage};
//! // Delcare a schema. Schema specifies which indices are present,
//! // name of each index and its kind. Indices are identified by types.
//! // Here, we create just one index.
//! storage::decl_schema! {
//!     Schema {
//!         MyMap: Single,
//!     }
//! }
//!
//! fn test() -> storage::Result<()> {
//!     // Initialize an empty store.
//!     let mut store = Storage::<_, Schema>::new(storage::inmemory::InMemory::new())?;
//!
//!     // All store operations happen inside of a transaction.
//!     let mut tx = store.transaction_rw();
//!
//!     // Get the storage map, identified by the index type.
//!     let mut map = tx.get_mut::<MyMap, _>();
//!
//!     // Associate the value "bar" with the key "foo"
//!     map.put(b"foo".to_vec(), b"bar".to_vec())?;
//!
//!     // Get the value out again.
//!     let val = map.get(b"foo")?;
//!     assert_eq!(val, Some(&b"bar"[..]));
//!
//!     // End the transaction
//!     tx.commit()?;
//!
//!     // Try writing a value but abort the transaction afterwards.
//!     let mut tx = store.transaction_rw();
//!     tx.get_mut::<MyMap, _>().put(b"baz".to_vec(), b"xyz".to_vec())?;
//!     tx.abort();
//!
//!     // Transaction can return data. Values taken from the database have to be cloned
//!     // in order for them to be available after the transaction terminates.
//!     let tx = store.transaction_ro();
//!     assert_eq!(tx.get::<MyMap, _>().get(b"baz")?, None);
//!     tx.close();
//!
//!     // Check the value we first inserted is still there.
//!     let tx = store.transaction_ro();
//!     assert_eq!(tx.get::<MyMap, _>().get(b"foo")?, Some(&b"bar"[..]));
//!     tx.close();
//!
//!     Ok(())
//! }
//! # test().unwrap();
//! ```

mod interface;
pub mod schema;

// Re-export user-facing items from core
pub use storage_core::{error, Backend, Error, Result};

// Re-export the interface types
pub use interface::*;

// Re-export the in-memory storage
// TODO: Remove this to further decouple the general storage interface from individual backends
#[cfg(feature = "inmemory")]
pub use storage_inmemory as inmemory;

#[cfg(test)]
mod test {
    use super::*;

    decl_schema! {
        Schema {
            MyMap: Single,
        }
    }

    #[test]
    fn empty_ro() {
        common::concurrency::model(|| {
            let store = Storage::<_, Schema>::new(inmemory::InMemory::new()).unwrap();
            let tx = store.transaction_ro();
            assert_eq!(tx.get::<MyMap, _>().get(b"foo".as_ref()), Ok(None));
        });
    }

    #[test]
    fn empty_rw() {
        common::concurrency::model(|| {
            let store = Storage::<_, Schema>::new(inmemory::InMemory::new()).unwrap();
            let tx = store.transaction_rw();
            assert_eq!(tx.get::<MyMap, _>().get(b"foo".as_ref()), Ok(None));
        });
    }
}
