// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
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
//! # use storage::{schema, traits::*};
//! // Delcare a schema. Schema specifies which indices are present,
//! // name of each index and its kind. Indices are identified by types.
//! // Here, we create just one index.
//! storage::decl_schema! {
//!     Schema {
//!         MyMap: Single,
//!     }
//! }
//!
//! // Our store type is parametrized by the schema.
//! type MyStore = storage::inmemory::Store<Schema>;
//!
//! // Initialize an empty store.
//! let mut store = MyStore::default();
//!
//! // All store operations happen inside of a transaction.
//! store.transaction_rw().run(|tx| {
//!     // Get the storage map, identified by the index type.
//!     let mut col = tx.get_mut::<MyMap, _>();
//!
//!     // Associate the value "bar" with the key "foo"
//!     col.put(b"foo".to_vec(), b"bar".to_vec())?;
//!
//!     // Get the value out again.
//!     let val = col.get(b"foo")?;
//!     assert_eq!(val, Some(&b"bar"[..]));
//!
//!     // End the transaction
//!     storage::commit(())
//! });
//!
//! // Try writing a value but abort the transaction afterwards.
//! store.transaction_rw().run(|tx| {
//!     tx.get_mut::<MyMap, _>().put(b"baz".to_vec(), b"xyz".to_vec())?;
//!     storage::abort(())
//! });
//!
//! // Transaction can return data. Values taken from the database have to be cloned
//! // in order for them to be available after the transaction terminates.
//! let result = store.transaction_ro().run(|tx| {
//!     Ok(tx.get::<MyMap, _>().get(b"baz")?.map(ToOwned::to_owned))
//! });
//! assert_eq!(result, Ok(None));
//!
//! // Check the value we first inserted is still there.
//! let result = store.transaction_ro().run(|tx| {
//!     assert_eq!(tx.get::<MyMap, _>().get(b"foo")?, Some(&b"bar"[..]));
//!     Ok(())
//! });
//! ```

// Re-export core abstractions
pub use storage_core::*;

// Re-export the in-memory storage
#[cfg(feature = "inmemory")]
pub use storage_inmemory as inmemory;
