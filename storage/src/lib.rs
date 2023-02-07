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
//! # Prefix iteration
//!
//! You can iterate over a prefix of the key. Consider, as an example, a map from an `Outpoint` to
//! a `Utxo`. Each outpoint consists of a `H256` transaction ID and a `u32` index. You can iterate
//! over all `Utxo`s for given transaction ID by calling `map.prefix_iter(tx_id)`, provided the
//! following trait impl exists:
//!
//! ```ignore
//! impl HasPrefix<H256> for Outpoint {}
//! ```
//!
//! The impl above asserts that the encoding of `Outpoint` starts with an encoding of a value of
//! type `H256` representing the transaction ID. The result is an iterator over all
//! `(Outpoint, Utxo)` pairs that belong to given transaction.
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
//!         MyMap: Map<String, u64>,
//!     }
//! }
//!
//! fn test() -> storage::Result<()> {
//!     // Initialize an empty store.
//!     let mut store = Storage::<_, Schema>::new(storage::inmemory::InMemory::new())?;
//!
//!     // All store operations happen inside of a transaction.
//!     let mut tx = store.transaction_rw(None)?;
//!
//!     // Get the storage map, identified by the index type.
//!     let mut map = tx.get_mut::<MyMap, _>();
//!
//!     // Associate the value 1337 with the key "foo"
//!     map.put("foo", &1337)?;
//!
//!     // Get the value out again.
//!     let val = map.get("foo")?;
//!     assert_eq!(val.map(|x| x.decode()), Some(1337));
//!
//!     // End the transaction
//!     tx.commit()?;
//!
//!     // Try writing a value but abort the transaction afterwards.
//!     let mut tx = store.transaction_rw(None)?;
//!     tx.get_mut::<MyMap, _>().put("baz", &42)?;
//!     tx.abort();
//!
//!     // Transaction can return data. Values taken from the database have to be cloned
//!     // in order for them to be available after the transaction terminates.
//!     let tx = store.transaction_ro()?;
//!     assert_eq!(tx.get::<MyMap, _>().get("baz")?, None);
//!     tx.close();
//!
//!     // Check the value we first inserted is still there.
//!     let tx = store.transaction_ro()?;
//!     assert_eq!(tx.get::<MyMap, _>().get("foo")?.map(|x| x.decode()), Some(1337));
//!     tx.close();
//!
//!     Ok(())
//! }
//! # test().unwrap();
//! ```

mod database;
pub mod schema;

// Re-export user-facing items from core
pub use storage_core::{error, Backend, Error, Result};

// Re-export the interface types
pub use database::*;

// Re-export the in-memory storage
// TODO: Remove this to further decouple the general storage interface from individual backends
#[cfg(feature = "inmemory")]
pub use storage_inmemory as inmemory;

#[cfg(test)]
mod test;
