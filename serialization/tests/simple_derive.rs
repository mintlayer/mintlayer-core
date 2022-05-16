mod utils;

use serialization::{Decode, Encode};

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Decode, Encode)]
enum Enum1A {
    X,
}

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Decode, Encode)]
enum Enum1B {
    #[codec(index = 0x42)]
    X,
}

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Decode, Encode)]
enum Enum1C {
    #[codec(index = 0xff)]
    X,
}

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Decode, Encode)]
enum Enum2A {
    X,
    Y,
}

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Decode, Encode)]
enum Enum2B {
    #[codec(index = 0x22)]
    X,
    Y,
}

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Decode, Encode)]
enum Enum2C {
    X,
    #[codec(index = 0x12)]
    Y,
}

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Decode, Encode)]
enum Enum2D {
    #[codec(index = 0x11)]
    X,
    #[codec(index = 0x15)]
    Y,
}

#[test]
fn test_trivial_enums() {
    utils::check_encoding(Enum1A::X, &[0x00]);

    utils::check_encoding(Enum1B::X, &[0x42]);

    utils::check_encoding(Enum1C::X, &[0xff]);

    utils::check_encoding(Enum2A::X, &[0x00]);
    utils::check_encoding(Enum2A::Y, &[0x01]);

    utils::check_encoding(Enum2B::X, &[0x22]);
    utils::check_encoding(Enum2B::Y, &[0x01]);

    utils::check_encoding(Enum2C::X, &[0x00]);
    utils::check_encoding(Enum2C::Y, &[0x12]);

    utils::check_encoding(Enum2D::X, &[0x11]);
    utils::check_encoding(Enum2D::Y, &[0x15]);
}

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Decode, Encode)]
struct Struct0;

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Decode, Encode)]
#[allow(clippy::unit_arg)]
struct Struct1A(());

#[derive(PartialOrd, Ord, PartialEq, Eq, Debug, Decode, Encode)]
struct Struct1B(u8);

#[test]
fn test_trivial_structs() {
    utils::check_encoding(Struct0, &[]);

    utils::check_encoding(Struct1A(()), &[]);

    for n in 0u8..=255 {
        utils::check_encoding(Struct1B(n), &[n]);
    }
}
