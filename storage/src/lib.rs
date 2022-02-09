//! Storage interface
//!
//! Storage is a collection of key-value maps. One key-value map is called a column. Column kind
//! specifies whether a key is mapped to just a single value or to a collection of values.
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
//! // Delcare a schema. Schema specifies which columns are present,
//! // name of each column and its kind. Columns are identified by types.
//! // Here, we create just one column.
//!
//! struct MyColumn;
//! impl schema::Column for MyColumn {
//!     const NAME: &'static str = "MyColumnV1";
//!     type Kind = schema::Single;
//! }
//!
//! // Schema is a bunch of nested tuples listing the columns.
//! // The format is (Column1, (Column2, ())) etc.
//! type Schema = (MyColumn, ());
//!
//! // Our store type is parametrized by the schema.
//! type MyStore = storage::Store<Schema>;
//!
//! // Initialize an empty store with columns listed in the schema.
//! let mut store = MyStore::default();
//!
//! // All store operations happen inside of a transaction.
//! store.transaction_rw(|tx| {
//!     // Get the column, identified by the type.
//!     let mut col = tx.get_mut::<MyColumn, _>();
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
//! store.transaction_rw(|tx| {
//!     tx.get_mut::<MyColumn, _>().put(b"baz".to_vec(), b"xyz".to_vec())?;
//!     storage::abort(())
//! });
//!
//! // Transaction can return data. Values taken from the database have to be cloned
//! // in order for them to be available after the transaction terminates.
//! let result = store.transaction_ro(|tx| {
//!     Ok(tx.get::<MyColumn, _>().get(b"baz")?.map(ToOwned::to_owned))
//! });
//! assert_eq!(result, Ok(None));
//!
//! // Check the value we first inserted is still there.
//! let result = store.transaction_ro(|tx| {
//!     assert_eq!(tx.get::<MyColumn, _>().get(b"foo")?, Some(&b"bar"[..]));
//!     Ok(())
//! });
//! ```

mod basic;
pub mod error;
pub mod schema;
pub mod traits;
pub mod transaction;

// Reexport items from the temporary basic implementation.
pub use basic::Store;
pub use error::Error;
pub use transaction::{abort, commit};

pub type Data = Vec<u8>;
pub type Result<T> = std::result::Result<T, Error>;
