#![allow(clippy::unnecessary_cast)]

use serialization_core::*;
use serialization_tagged::*;

use proptest::prelude::*;

// A couple of types to experiment with

#[derive(PartialEq, Eq, Clone, Tagged, Encode, Decode, Debug)]
enum Enum0 {
    This = 55,
}

#[derive(PartialEq, Eq, Clone, Tagged, Encode, Decode, Debug)]
enum Enum1 {
    #[codec(index = 42)]
    The(u16, String),
}

#[derive(PartialEq, Eq, Clone, DirectEncode, DirectDecode, Debug)]
enum Enum2 {
    X(Enum0),
    Y(Enum1),
    Z { tag: Tag<7>, three_bytes: [u8; 3] },
}

#[derive(PartialEq, Eq, Tagged, Encode, Decode, Debug)]
struct Struct0 {
    ver: Tag<25>,
    data: u64,
    extra: Vec<u8>,
}

#[derive(PartialEq, Eq, Tagged, Encode, Decode, Debug)]
struct Struct1 {
    struct0: Struct0,
    more_data: Option<[u8; 32]>,
}

#[derive(PartialEq, Eq, Tagged, Encode, Decode, Debug)]
struct Struct2<T> {
    nested: T,
    stuff: u128,
}

#[derive(PartialEq, Eq, Tagged, Encode, Decode, Debug)]
struct Struct3<const N: u8> {
    version: Tag<N>,
    int: u32,
}

// Generators for the types

prop_compose! {
    fn gen_enum1()(n: u16, s: String) -> Enum1 {
        Enum1::The(n, s)
    }
}
prop_compose! {
    fn gen_struct0()(data: u64, extra: Vec<u8>) -> Struct0 {
        Struct0 { ver: Default::default(), data, extra }
    }
}
prop_compose! {
    fn gen_struct1()(struct0 in gen_struct0(), more_data: Option<[u8; 32]>) -> Struct1 {
        Struct1 { struct0, more_data }
    }
}
prop_compose! {
    fn gen_struct2_enum1()(nested in gen_enum1(), stuff: u128) -> Struct2<Enum1> {
        Struct2 { nested, stuff }
    }
}
prop_compose! {
    fn gen_struct3_75()(int: u32) -> Struct3<75> {
        Struct3 { version: Tag::default(), int }
    }
}
fn gen_enum2() -> impl Strategy<Value = Enum2> {
    prop_oneof![
        Just(Enum2::X(Enum0::This)),
        gen_enum1().prop_map(Enum2::Y),
        any::<[u8; 3]>().prop_map(|three_bytes| Enum2::Z {
            tag: Tag::default(),
            three_bytes
        }),
    ]
}

// Test helpers

fn check_initial_byte<T: Tagged + Encode>(x: &T) {
    x.using_encoded(|encoded| {
        assert_eq!(encoded[0], T::TAG, "tag mismatch");
    });
}

fn check_codec<T: Eq + std::fmt::Debug + Encode + Decode>(original: &T) {
    let encoded = original.encode();
    let decoded = T::decode(&mut &encoded[..]);
    assert_eq!(decoded.as_ref(), Ok(original));

    let reencoded = decoded.map(|x| x.encode());
    assert_eq!(reencoded, Ok(encoded));
}

fn check_all<T: Eq + std::fmt::Debug + Tagged + Encode + Decode>(x: &T) {
    check_initial_byte(x);
    check_codec(x);
}

// Tests

#[test]
fn check_enum0() {
    check_all(&Enum0::This);
    assert_eq!(Enum0::This.encode(), vec![55]);
}

#[test]
fn check_enum2_x() {
    assert_eq!(Enum2::X(Enum0::This).encode(), Enum0::This.encode());
}

proptest! {
    #[test]
    fn check_enum1(x in gen_enum1()) {
        check_all(&x);
    }

    #[test]
    fn check_struct0(x in gen_struct0()) {
        check_all(&x);
    }

    #[test]
    fn check_struct1(x in gen_struct1()) {
        check_all(&x);
    }

    #[test]
    fn check_struct2_enum1(x in gen_struct2_enum1()) {
        check_all(&x);
    }

    #[test]
    fn check_struct3_75(x in gen_struct3_75()) {
        check_all(&x);
    }

    #[test]
    fn check_enum2(x in gen_enum2()) {
        check_codec(&x);
    }

    #[test]
    fn check_enum2_y_tagless(x in gen_enum1()) {
        assert_eq!(Enum2::Y(x.clone()).encode(), x.encode());
    }

    #[test]
    fn check_enum2_z_tagless(three_bytes: [u8; 3]) {
        assert_eq!(
            Enum2::Z { tag: Tag, three_bytes }.encode(),
            (Tag::<7>, three_bytes).encode(),
        );
    }
}

#[test]
fn check_derived_tags() {
    // Could be static assertions but this will do too
    assert_eq!(Enum0::TAG, 55);
    assert_eq!(Enum1::TAG, 42);
    assert_eq!(Struct0::TAG, 25);
    assert_eq!(Struct1::TAG, 25);
    assert_eq!(<Struct2<Struct1>>::TAG, 25);
    assert_eq!(<Struct2<Enum0>>::TAG, 55);
    assert_eq!(<Struct2<Enum1>>::TAG, 42);
    assert_eq!(<Struct3<33>>::TAG, 33);
}

#[test]
fn check_enum2_encoding() {
    fn check(value: Enum2, encoded: impl AsRef<[u8]>) {
        assert_eq!(&value.encode()[..], encoded.as_ref());
    }
    check(Enum2::X(Enum0::This), [55]);
    check(Enum2::Y(Enum1::The(258, String::new())), [42, 2, 1, 0]);
    check(
        Enum2::Y(Enum1::The(257, String::from("d"))),
        [42, 1, 1, 4, 100],
    );
    check(
        Enum2::Z {
            tag: Tag,
            three_bytes: [1, 2, 3],
        },
        [7, 1, 2, 3],
    );
}

#[test]
fn check_enum2_decoding() {
    fn check_ok(encoded: impl AsRef<[u8]>, value: Enum2) {
        assert_eq!(Enum2::decode(&mut encoded.as_ref()).ok(), Some(value));
    }
    fn check_err(encoded: impl AsRef<[u8]>) {
        assert!(Enum2::decode(&mut encoded.as_ref()).is_err());
    }

    check_ok([55], Enum2::X(Enum0::This));
    check_ok(
        [7, 8, 9, 10],
        Enum2::Z {
            tag: Tag,
            three_bytes: [8, 9, 10],
        },
    );
    check_ok(
        [42, 1, 1, 4, 101],
        Enum2::Y(Enum1::The(257, String::from("e"))),
    );

    check_err([]);
    check_err([0]);
    check_err([56]);
    check_err([42, 1, 1, 4]);
}
