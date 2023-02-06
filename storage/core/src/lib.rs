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

//! Definitions used to implement storage backends
//!
//! # High-level overview
//!
//! A database can be thought of as a collection of key-value maps.
//!
//! ```notest
//! Map<DbMapId, Map<Key, Value>>
//! ```
//!
//! [DbMapId] is used to identify a particular key-value map. `Key` and `Value` are raw byte
//! sequences ([Data]). To access a particular value, the database needs to be indexed first by a
//! [DbMapId] (to get the key-value map) and then by a key.
//!
//! The inner key-value map is often referred to as DB map or even just map. The set of DB maps is
//! fixed for the duration of backend lifetime but their contents may change.
//!
//! ## Database description
//!
//! The backend is given access to a collection of metadata describing the database structure in
//! an instance of [DbDesc]. Most importantly, it communicates the number of DB maps and contains
//! information about the individual maps in [DbMapDesc], most notably the name.
//!
//! # Backend implementation guidelines
//!
//! Implementing a storage backend involves defining a couple of traits satisfying a number of
//! traits defined in [crate::backend].
//!
//! ## Initialization
//!
//! The main entry point is a type implementing the [Backend] trait. This type is used to identify
//! the backend. The object of this type contains information used to initialize the backend such
//! as database path and various settings.
//!
//! Database is started by calling [Backend::open] which uses the backend-specific information
//! together with database description to initialize the database. That involves opening the
//! database and, if necessary, setting up backend-specific representation of DB maps. The
//! [types::DbMapsData::transform] method can be used to transform backend-agnostic information
//! about DB maps into backend-specific handle to the DB maps.
//!
//! The result of opening a backend is something of type [Backend::Impl] that implements the
//! [backend::BackendImpl] trait. It represents an initialized and running database.
//!
//! ## Transactions
//!
//! Currently, all data accesses in backend happen through transactions. This restriction may be
//! lifted in the future, allowing primitive opertations to be performed without a transaction for
//! performance reasons.
//!
//! Starting read-only and read-write transactions is defined by implementing the
//! [backend::TransactionalRo] and [backend::TransactionalRw] traits on [Backend::Impl].
//!
//! Committing a read-write transaction is defined in defined by implementing [backend::TxRw].
//! A read-only transaction type has to be marked with the [backend::TxRo] trait.
//!
//! Rolling back read-write transaction and closing read-only transaction is defined by dropping
//! the corresponding transaction object. If any special processing is required, [Drop] has to be
//! implemented.
//!
//! ## Implementing operations
//!
//! Individual database operations are defined by implementing the following traits:
//!
//! * [backend::ReadOps]
//! * [backend::WriteOps]
//! * [backend::PrefixIter]
//! * Implementing [Iterator] for the type returned by [backend::PrefixIter::prefix_iter]
//!
//! ## Adaptor pattern
//!
//! Sometimes, it is useful to create a database backend that wraps an arbitrary other backend and
//! adds some functionality. Use cases include but are not limited to logging and caching.

pub mod adaptor;
pub mod backend;
pub mod error;
pub mod types;
pub mod util;

// Re-export some commonly used items
pub use backend::Backend;
pub use error::Error;
pub use types::{DbDesc, DbMapCount, DbMapDesc, DbMapId, DbMapsData};

/// Raw byte sequences, used to represent store keys and values
pub type Data = Vec<u8>;

/// A `Result` type specialized for storage
pub type Result<T> = std::result::Result<T, Error>;
