//! Traits that constitute storage interface.

use crate::schema;
pub use crate::transaction::{TransactionRo, TransactionRw};

/// Get an immutable reference to given single-valued map
pub trait GetMapRef<'m, Sch: schema::Schema> {
    /// Type representing the map reference
    type MapRef: MapRef + 'm;

    /// Get key-value store for given map mutably (key-to-single-value only for now)
    fn get<'c: 'm, DBIdx, I>(&'c self) -> Self::MapRef
    where
        DBIdx: schema::DBIndex<Kind = schema::Single>,
        Sch: schema::HasDBIndex<DBIdx, I>;
}

/// Get a mutable reference to given single-valued map
pub trait GetMapMut<'m, Sch: schema::Schema>: GetMapRef<'m, Sch> {
    /// Type representing the map reference
    type MapMut: MapMut + 'm;

    /// Get key-value store for given map mutably (key-to-single-value only for now)
    fn get_mut<'c: 'm, DBIdx, I>(&'c mut self) -> Self::MapMut
    where
        DBIdx: schema::DBIndex<Kind = schema::Single>,
        Sch: schema::HasDBIndex<DBIdx, I>;
}

/// Read operations on a single-valued map
pub trait MapRef {
    /// Get value associated with given key
    fn get(&self, key: &[u8]) -> crate::Result<Option<&[u8]>>;
}

/// Modifying operations on a single-valued map
pub trait MapMut: MapRef {
    /// Insert a value associated with given key, overwriting the original one.
    fn put(&mut self, key: crate::Data, val: crate::Data) -> crate::Result<()>;

    /// Delete the value associated with given key.
    fn del(&mut self, key: &[u8]) -> crate::Result<()>;
}

/// A transaction over an immutable store
pub trait StoreTxRo<Sch: schema::Schema>:
    TransactionRo<Error = crate::Error> + for<'m> GetMapRef<'m, Sch>
{
}

impl<S: schema::Schema, T: TransactionRo<Error = crate::Error> + for<'m> GetMapRef<'m, S>>
    StoreTxRo<S> for T
{
}

/// A transaction over a mutable store
pub trait StoreTxRw<Sch: schema::Schema>:
    TransactionRw<Error = crate::Error> + for<'m> GetMapMut<'m, Sch>
{
}

impl<S: schema::Schema, T: TransactionRw<Error = crate::Error> + for<'m> GetMapMut<'m, S>>
    StoreTxRw<S> for T
{
}

/// Type supporting storage transactions.
pub trait Transactional<'t, Sch: schema::Schema> {
    /// Associated read-only transaction type.
    type TransactionRo: TransactionRo<Error = crate::Error> + StoreTxRo<Sch> + 't;

    /// Associated read-write transaction type.
    type TransactionRw: TransactionRw<Error = crate::Error> + StoreTxRw<Sch> + 't;

    /// Start a read-only transaction.
    fn transaction_ro<'s: 't>(&'s self) -> Self::TransactionRo;

    /// Start a read-write transaction.
    fn transaction_rw<'s: 't>(&'s self) -> Self::TransactionRw;
}

/// Storage backend
pub trait Backend<Sch: schema::Schema>: for<'tx> Transactional<'tx, Sch> {}
