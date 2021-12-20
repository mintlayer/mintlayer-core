//! Describe the database schema at type level

/// Describes single key-value map
pub trait Column {
    /// Column name.
    const NAME: &'static str;

    /// Expected size of values in the column. May be used for storage optimization.
    const SIZE_HINT: core::ops::Range<usize> = 0..usize::MAX;

    /// Whether this maps keys to single or multiple values.
    type Kind: MapKind;
}

/// What constitutes a valid database schema
pub trait Schema: internal::Sealed {}

impl Schema for () {}

impl<Col: Column, Rest: Schema> Schema for (Col, Rest) {}

/// Require given schema to contain given column
pub trait HasColumn<Col: Column, I>: Schema {}
impl<Col: Column, Rest: Schema> HasColumn<Col, ()> for (Col, Rest) {}
impl<Col: Column, Head: Column, Rest: HasColumn<Col, I>, I> HasColumn<Col, (I,)> for (Head, Rest) {}

/// Marker for key-value maps
pub struct Single;
/// Marker for key-multivalue maps
pub struct Multi;

/// Specifies map kind, either [Single] or [Multi].
pub trait MapKind {}
impl MapKind for Single {}
impl MapKind for Multi {}

mod internal {
    use super::*;

    // This is to prevent the Schema trait from being implemented on new types.
    pub trait Sealed {}
    impl Sealed for () {}
    impl<Col: Column, Rest: Schema> Sealed for (Col, Rest) {}
}

#[cfg(test)]
mod test {
    use super::*;

    struct Col1;
    impl Column for Col1 {
        const NAME: &'static str = "col1";
        type Kind = Single;
    }

    struct Col2;
    impl Column for Col2 {
        const NAME: &'static str = "col2";
        type Kind = Multi;
    }

    type MySchema = (Col1, (Col2, ()));

    fn is_schema<T: Schema>() -> bool {
        true
    }

    #[test]
    fn test_is_schema() {
        // we are just interested this compiles
        assert!(is_schema::<MySchema>());
    }
}
