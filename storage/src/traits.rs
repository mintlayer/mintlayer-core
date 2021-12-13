//! Traits that constitute storage interface.

use crate::schema;
pub use crate::transaction::{TransactionRo, TransactionRw, Transactional};

/// Get a reference to given single-valued column
pub trait GetMapRef<'tx, Sch: schema::Schema> {
    /// Type representing the map reference
    type MapRef: MapRef;

    /// Get key-value store for given column mutably (key-to-single-value only for now)
    fn get<Col, I>(&'tx self) -> Self::MapRef
    where
        Col: schema::Column<Kind = schema::Single>,
        Sch: schema::HasColumn<Col, I>;
}

/// Get a mutable reference to given single-valued column
pub trait GetMapMut<'tx, Sch: schema::Schema> {
    /// Type representing the map reference
    type MapMut: MapMut;

    /// Get key-value store for given column mutably (key-to-single-value only for now)
    fn get_mut<Col, I>(&'tx mut self) -> Self::MapMut
    where
        Col: schema::Column<Kind = schema::Single>,
        Sch: schema::HasColumn<Col, I>;
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
pub trait StoreTxRo<'tx, Sch: schema::Schema>: TransactionRo + GetMapRef<'tx, Sch> {}
impl<'tx, S: schema::Schema, T: TransactionRo + GetMapRef<'tx, S>> StoreTxRo<'tx, S> for T {}

/// A transaction over a mutable store
pub trait StoreTxRw<'tx, Sch: schema::Schema>: TransactionRw + GetMapMut<'tx, Sch> {}
impl<'tx, S: schema::Schema, T: TransactionRw + GetMapMut<'tx, S>> StoreTxRw<'tx, S> for T {}
