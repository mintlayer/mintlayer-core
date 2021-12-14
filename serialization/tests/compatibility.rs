use parity_scale_codec::{Decode, Encode};
use serialization_utils::{OptionWrapper, SimpleWrapper};
use std::collections::BTreeMap;

#[test]
fn test_scale_version_compatibility_numbers() {
    // integers i8, u8, i16, u16, i32, u32, i64, u64, i128, u128
    // i8
    let test = i8::MAX;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(enc, vec![127]);
    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut vec![127].as_slice()).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    // u8
    let test = u8::MAX;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(enc, vec![255]);
    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut vec![255].as_slice()).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    // i16
    let test = i16::MAX;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(enc, vec![255, 127]);
    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut vec![255, 127].as_slice()).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    // u16
    let test = u16::MAX;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(enc, vec![255, 255]);
    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut vec![255, 255].as_slice()).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    // i32
    let test = i32::MAX;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(enc, vec![255, 255, 255, 127]);
    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut vec![255, 255, 255, 127].as_slice()).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    // u32
    let test = u32::MAX;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(enc, vec![255, 255, 255, 255]);
    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut vec![255, 255, 255, 255].as_slice()).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    // i64
    let test = i64::MAX;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(enc, vec![255, 255, 255, 255, 255, 255, 255, 127]);
    // Backward compatibility
    let dec =
        SimpleWrapper::decode(&mut vec![255, 255, 255, 255, 255, 255, 255, 127].as_slice()).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    // u64
    let test = u64::MAX;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(enc, vec![255, 255, 255, 255, 255, 255, 255, 255]);
    // Backward compatibility
    let dec =
        SimpleWrapper::decode(&mut vec![255, 255, 255, 255, 255, 255, 255, 255].as_slice()).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    // i128
    let test = i128::MAX;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(
        enc,
        vec![255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127]
    );
    // Backward compatibility
    let dec = SimpleWrapper::decode(
        &mut vec![255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127]
            .as_slice(),
    )
    .ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    // u128
    let test = u128::MAX;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(
        enc,
        vec![255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
    );
    // Backward compatibility
    let dec = SimpleWrapper::decode(
        &mut vec![255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255]
            .as_slice(),
    )
    .ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));
}

#[test]
fn test_scale_version_compatibility_struct() {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Encode, Decode)]
    enum TestEnum {
        Numbers((i8, u8, i16, u16, i32, u32, i64, u64, i128, u128)),
        Strings(
            (
                String,
                String,
                String,
                // The SCALE doesn't support Copy-On-Write type, lifetimes and chars here =\
                // Cow<'a, str>
                // &'a str,
                // char,
            ),
        ),
        Containers((Vec<u8>, BTreeMap<String, String>)),
    }

    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Encode, Decode)]
    struct TestStruct {
        field_enum_number: TestEnum,
        field_enum_strings: TestEnum,
        field_enum_containers: TestEnum,
        field_optional_some: OptionWrapper<String>,
        field_optional_none: OptionWrapper<String>,
        field_vector_string: Vec<String>,
        field_vector_bytes: Vec<u8>,
        field_btree_map_string: BTreeMap<u128, String>,
        field_btree_map_bytes: BTreeMap<u128, Vec<u8>>,
        field_nested_stuct: Option<Box<Self>>,
    }

    let mut btree_map = BTreeMap::new();
    btree_map.insert(
        "Tom Sawyer".to_string(),
        "The Adventure of Tom Sawyer is a novel by Mark Twain.".to_string(),
    );
    btree_map.insert(
        "Tin-tin".to_string(),
        "Life is rather like a tin of sardines - we're all of us looking for the key.".to_string(),
    );
    btree_map.insert(
            "Red Planet".to_string(),
            "In Red Planet, the only thing thicker than the Martian atmosphere (which is breathable, by the way)".to_string(),
        );
    btree_map.insert(
        "Romeo and Juliet".to_string(),
        "Good night, good night! parting is such sweet sorrow. ".to_string(),
    );

    let mut field_btree_map_string = BTreeMap::new();
    field_btree_map_string.insert(
        0xFF,
        "The Adventure of Tom Sawyer is a novel by Mark Twain.".to_string(),
    );

    let mut field_btree_map_bytes = BTreeMap::new();
    field_btree_map_bytes.insert(0xFF, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

    let test = TestStruct {
        field_enum_number: TestEnum::Numbers((
            -i8::MAX,
            u8::MAX,
            -i16::MAX,
            u16::MAX,
            -i32::MAX,
            u32::MAX,
            -i64::MAX,
            u64::MAX,
            -i128::MAX,
            u128::MAX,
        )),
        field_enum_strings: TestEnum::Strings(
            (("What a hero Tom was become now! He did not go skipping and prancing, but moved  \
              with a dignified swagger, as became a pirate who felt that the public eye was on him.").to_string(),
             "And indeed it was; he tried not to seem to see the looks or hear the remarks as he passed".to_string(),
             "along, but they were food and drink to him. Mark Twain, The Adventure of Tom Sawyer, Ch 18".to_string(),
            )),

        field_enum_containers: TestEnum::Containers((
            vec![0xFF, 0xFE, 0xFB, 0xFA, 0xAA, 0xAB, 0xFF],
            btree_map
        )),
        field_optional_some: OptionWrapper::new(Some(("Looking at these stars suddenly dwarfed my own \
        troubles and all the gravities of terrestrial life.").to_string())),
        field_optional_none: OptionWrapper::new(None),
        field_vector_string: vec!["What a hero Tom was become now! He did not go skipping and prancing, but moved ".to_string(),
                                  "with a dignified swagger, as became a pirate who felt that the public eye was on him".to_string(),
                                  " And indeed it was; he tried not to seem to see the looks or hear the remarks as he passed".to_string(),
                                  "along, but they were food and drink to him. Mark Twain, The Adventure of Tom Sawyer, Ch 18".to_string(),
        ],
        field_vector_bytes: vec![0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x20, 0x6d, 0x79, 0x20, 0x6d, 0x61, 0x6e],
        field_btree_map_string,
        field_btree_map_bytes,
        field_nested_stuct: None,
    };
    let mut test_main = test.clone();
    test_main.field_nested_stuct = Some(Box::new(test));

    let bytes_representation = vec![
        0, 129, 255, 1, 128, 255, 255, 1, 0, 0, 128, 255, 255, 255, 255, 1, 0, 0, 0, 0, 0, 0, 128,
        255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1, 149, 2,
        87, 104, 97, 116, 32, 97, 32, 104, 101, 114, 111, 32, 84, 111, 109, 32, 119, 97, 115, 32,
        98, 101, 99, 111, 109, 101, 32, 110, 111, 119, 33, 32, 72, 101, 32, 100, 105, 100, 32, 110,
        111, 116, 32, 103, 111, 32, 115, 107, 105, 112, 112, 105, 110, 103, 32, 97, 110, 100, 32,
        112, 114, 97, 110, 99, 105, 110, 103, 44, 32, 98, 117, 116, 32, 109, 111, 118, 101, 100,
        32, 32, 119, 105, 116, 104, 32, 97, 32, 100, 105, 103, 110, 105, 102, 105, 101, 100, 32,
        115, 119, 97, 103, 103, 101, 114, 44, 32, 97, 115, 32, 98, 101, 99, 97, 109, 101, 32, 97,
        32, 112, 105, 114, 97, 116, 101, 32, 119, 104, 111, 32, 102, 101, 108, 116, 32, 116, 104,
        97, 116, 32, 116, 104, 101, 32, 112, 117, 98, 108, 105, 99, 32, 101, 121, 101, 32, 119, 97,
        115, 32, 111, 110, 32, 104, 105, 109, 46, 101, 1, 65, 110, 100, 32, 105, 110, 100, 101,
        101, 100, 32, 105, 116, 32, 119, 97, 115, 59, 32, 104, 101, 32, 116, 114, 105, 101, 100,
        32, 110, 111, 116, 32, 116, 111, 32, 115, 101, 101, 109, 32, 116, 111, 32, 115, 101, 101,
        32, 116, 104, 101, 32, 108, 111, 111, 107, 115, 32, 111, 114, 32, 104, 101, 97, 114, 32,
        116, 104, 101, 32, 114, 101, 109, 97, 114, 107, 115, 32, 97, 115, 32, 104, 101, 32, 112,
        97, 115, 115, 101, 100, 105, 1, 97, 108, 111, 110, 103, 44, 32, 98, 117, 116, 32, 116, 104,
        101, 121, 32, 119, 101, 114, 101, 32, 102, 111, 111, 100, 32, 97, 110, 100, 32, 100, 114,
        105, 110, 107, 32, 116, 111, 32, 104, 105, 109, 46, 32, 77, 97, 114, 107, 32, 84, 119, 97,
        105, 110, 44, 32, 84, 104, 101, 32, 65, 100, 118, 101, 110, 116, 117, 114, 101, 32, 111,
        102, 32, 84, 111, 109, 32, 83, 97, 119, 121, 101, 114, 44, 32, 67, 104, 32, 49, 56, 2, 28,
        255, 254, 251, 250, 170, 171, 255, 16, 40, 82, 101, 100, 32, 80, 108, 97, 110, 101, 116,
        141, 1, 73, 110, 32, 82, 101, 100, 32, 80, 108, 97, 110, 101, 116, 44, 32, 116, 104, 101,
        32, 111, 110, 108, 121, 32, 116, 104, 105, 110, 103, 32, 116, 104, 105, 99, 107, 101, 114,
        32, 116, 104, 97, 110, 32, 116, 104, 101, 32, 77, 97, 114, 116, 105, 97, 110, 32, 97, 116,
        109, 111, 115, 112, 104, 101, 114, 101, 32, 40, 119, 104, 105, 99, 104, 32, 105, 115, 32,
        98, 114, 101, 97, 116, 104, 97, 98, 108, 101, 44, 32, 98, 121, 32, 116, 104, 101, 32, 119,
        97, 121, 41, 64, 82, 111, 109, 101, 111, 32, 97, 110, 100, 32, 74, 117, 108, 105, 101, 116,
        216, 71, 111, 111, 100, 32, 110, 105, 103, 104, 116, 44, 32, 103, 111, 111, 100, 32, 110,
        105, 103, 104, 116, 33, 32, 112, 97, 114, 116, 105, 110, 103, 32, 105, 115, 32, 115, 117,
        99, 104, 32, 115, 119, 101, 101, 116, 32, 115, 111, 114, 114, 111, 119, 46, 32, 28, 84,
        105, 110, 45, 116, 105, 110, 49, 1, 76, 105, 102, 101, 32, 105, 115, 32, 114, 97, 116, 104,
        101, 114, 32, 108, 105, 107, 101, 32, 97, 32, 116, 105, 110, 32, 111, 102, 32, 115, 97,
        114, 100, 105, 110, 101, 115, 32, 45, 32, 119, 101, 39, 114, 101, 32, 97, 108, 108, 32,
        111, 102, 32, 117, 115, 32, 108, 111, 111, 107, 105, 110, 103, 32, 102, 111, 114, 32, 116,
        104, 101, 32, 107, 101, 121, 46, 40, 84, 111, 109, 32, 83, 97, 119, 121, 101, 114, 212, 84,
        104, 101, 32, 65, 100, 118, 101, 110, 116, 117, 114, 101, 32, 111, 102, 32, 84, 111, 109,
        32, 83, 97, 119, 121, 101, 114, 32, 105, 115, 32, 97, 32, 110, 111, 118, 101, 108, 32, 98,
        121, 32, 77, 97, 114, 107, 32, 84, 119, 97, 105, 110, 46, 1, 137, 1, 76, 111, 111, 107,
        105, 110, 103, 32, 97, 116, 32, 116, 104, 101, 115, 101, 32, 115, 116, 97, 114, 115, 32,
        115, 117, 100, 100, 101, 110, 108, 121, 32, 100, 119, 97, 114, 102, 101, 100, 32, 109, 121,
        32, 111, 119, 110, 32, 116, 114, 111, 117, 98, 108, 101, 115, 32, 97, 110, 100, 32, 97,
        108, 108, 32, 116, 104, 101, 32, 103, 114, 97, 118, 105, 116, 105, 101, 115, 32, 111, 102,
        32, 116, 101, 114, 114, 101, 115, 116, 114, 105, 97, 108, 32, 108, 105, 102, 101, 46, 0,
        16, 61, 1, 87, 104, 97, 116, 32, 97, 32, 104, 101, 114, 111, 32, 84, 111, 109, 32, 119, 97,
        115, 32, 98, 101, 99, 111, 109, 101, 32, 110, 111, 119, 33, 32, 72, 101, 32, 100, 105, 100,
        32, 110, 111, 116, 32, 103, 111, 32, 115, 107, 105, 112, 112, 105, 110, 103, 32, 97, 110,
        100, 32, 112, 114, 97, 110, 99, 105, 110, 103, 44, 32, 98, 117, 116, 32, 109, 111, 118,
        101, 100, 32, 81, 1, 119, 105, 116, 104, 32, 97, 32, 100, 105, 103, 110, 105, 102, 105,
        101, 100, 32, 115, 119, 97, 103, 103, 101, 114, 44, 32, 97, 115, 32, 98, 101, 99, 97, 109,
        101, 32, 97, 32, 112, 105, 114, 97, 116, 101, 32, 119, 104, 111, 32, 102, 101, 108, 116,
        32, 116, 104, 97, 116, 32, 116, 104, 101, 32, 112, 117, 98, 108, 105, 99, 32, 101, 121,
        101, 32, 119, 97, 115, 32, 111, 110, 32, 104, 105, 109, 105, 1, 32, 65, 110, 100, 32, 105,
        110, 100, 101, 101, 100, 32, 105, 116, 32, 119, 97, 115, 59, 32, 104, 101, 32, 116, 114,
        105, 101, 100, 32, 110, 111, 116, 32, 116, 111, 32, 115, 101, 101, 109, 32, 116, 111, 32,
        115, 101, 101, 32, 116, 104, 101, 32, 108, 111, 111, 107, 115, 32, 111, 114, 32, 104, 101,
        97, 114, 32, 116, 104, 101, 32, 114, 101, 109, 97, 114, 107, 115, 32, 97, 115, 32, 104,
        101, 32, 112, 97, 115, 115, 101, 100, 105, 1, 97, 108, 111, 110, 103, 44, 32, 98, 117, 116,
        32, 116, 104, 101, 121, 32, 119, 101, 114, 101, 32, 102, 111, 111, 100, 32, 97, 110, 100,
        32, 100, 114, 105, 110, 107, 32, 116, 111, 32, 104, 105, 109, 46, 32, 77, 97, 114, 107, 32,
        84, 119, 97, 105, 110, 44, 32, 84, 104, 101, 32, 65, 100, 118, 101, 110, 116, 117, 114,
        101, 32, 111, 102, 32, 84, 111, 109, 32, 83, 97, 119, 121, 101, 114, 44, 32, 67, 104, 32,
        49, 56, 72, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 32, 109, 121, 32, 109, 97,
        110, 4, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 212, 84, 104, 101, 32, 65, 100,
        118, 101, 110, 116, 117, 114, 101, 32, 111, 102, 32, 84, 111, 109, 32, 83, 97, 119, 121,
        101, 114, 32, 105, 115, 32, 97, 32, 110, 111, 118, 101, 108, 32, 98, 121, 32, 77, 97, 114,
        107, 32, 84, 119, 97, 105, 110, 46, 4, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        40, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 0, 129, 255, 1, 128, 255, 255, 1, 0, 0, 128, 255, 255,
        255, 255, 1, 0, 0, 0, 0, 0, 0, 128, 255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 1, 149, 2, 87, 104, 97, 116, 32, 97, 32, 104, 101, 114, 111, 32,
        84, 111, 109, 32, 119, 97, 115, 32, 98, 101, 99, 111, 109, 101, 32, 110, 111, 119, 33, 32,
        72, 101, 32, 100, 105, 100, 32, 110, 111, 116, 32, 103, 111, 32, 115, 107, 105, 112, 112,
        105, 110, 103, 32, 97, 110, 100, 32, 112, 114, 97, 110, 99, 105, 110, 103, 44, 32, 98, 117,
        116, 32, 109, 111, 118, 101, 100, 32, 32, 119, 105, 116, 104, 32, 97, 32, 100, 105, 103,
        110, 105, 102, 105, 101, 100, 32, 115, 119, 97, 103, 103, 101, 114, 44, 32, 97, 115, 32,
        98, 101, 99, 97, 109, 101, 32, 97, 32, 112, 105, 114, 97, 116, 101, 32, 119, 104, 111, 32,
        102, 101, 108, 116, 32, 116, 104, 97, 116, 32, 116, 104, 101, 32, 112, 117, 98, 108, 105,
        99, 32, 101, 121, 101, 32, 119, 97, 115, 32, 111, 110, 32, 104, 105, 109, 46, 101, 1, 65,
        110, 100, 32, 105, 110, 100, 101, 101, 100, 32, 105, 116, 32, 119, 97, 115, 59, 32, 104,
        101, 32, 116, 114, 105, 101, 100, 32, 110, 111, 116, 32, 116, 111, 32, 115, 101, 101, 109,
        32, 116, 111, 32, 115, 101, 101, 32, 116, 104, 101, 32, 108, 111, 111, 107, 115, 32, 111,
        114, 32, 104, 101, 97, 114, 32, 116, 104, 101, 32, 114, 101, 109, 97, 114, 107, 115, 32,
        97, 115, 32, 104, 101, 32, 112, 97, 115, 115, 101, 100, 105, 1, 97, 108, 111, 110, 103, 44,
        32, 98, 117, 116, 32, 116, 104, 101, 121, 32, 119, 101, 114, 101, 32, 102, 111, 111, 100,
        32, 97, 110, 100, 32, 100, 114, 105, 110, 107, 32, 116, 111, 32, 104, 105, 109, 46, 32, 77,
        97, 114, 107, 32, 84, 119, 97, 105, 110, 44, 32, 84, 104, 101, 32, 65, 100, 118, 101, 110,
        116, 117, 114, 101, 32, 111, 102, 32, 84, 111, 109, 32, 83, 97, 119, 121, 101, 114, 44, 32,
        67, 104, 32, 49, 56, 2, 28, 255, 254, 251, 250, 170, 171, 255, 16, 40, 82, 101, 100, 32,
        80, 108, 97, 110, 101, 116, 141, 1, 73, 110, 32, 82, 101, 100, 32, 80, 108, 97, 110, 101,
        116, 44, 32, 116, 104, 101, 32, 111, 110, 108, 121, 32, 116, 104, 105, 110, 103, 32, 116,
        104, 105, 99, 107, 101, 114, 32, 116, 104, 97, 110, 32, 116, 104, 101, 32, 77, 97, 114,
        116, 105, 97, 110, 32, 97, 116, 109, 111, 115, 112, 104, 101, 114, 101, 32, 40, 119, 104,
        105, 99, 104, 32, 105, 115, 32, 98, 114, 101, 97, 116, 104, 97, 98, 108, 101, 44, 32, 98,
        121, 32, 116, 104, 101, 32, 119, 97, 121, 41, 64, 82, 111, 109, 101, 111, 32, 97, 110, 100,
        32, 74, 117, 108, 105, 101, 116, 216, 71, 111, 111, 100, 32, 110, 105, 103, 104, 116, 44,
        32, 103, 111, 111, 100, 32, 110, 105, 103, 104, 116, 33, 32, 112, 97, 114, 116, 105, 110,
        103, 32, 105, 115, 32, 115, 117, 99, 104, 32, 115, 119, 101, 101, 116, 32, 115, 111, 114,
        114, 111, 119, 46, 32, 28, 84, 105, 110, 45, 116, 105, 110, 49, 1, 76, 105, 102, 101, 32,
        105, 115, 32, 114, 97, 116, 104, 101, 114, 32, 108, 105, 107, 101, 32, 97, 32, 116, 105,
        110, 32, 111, 102, 32, 115, 97, 114, 100, 105, 110, 101, 115, 32, 45, 32, 119, 101, 39,
        114, 101, 32, 97, 108, 108, 32, 111, 102, 32, 117, 115, 32, 108, 111, 111, 107, 105, 110,
        103, 32, 102, 111, 114, 32, 116, 104, 101, 32, 107, 101, 121, 46, 40, 84, 111, 109, 32, 83,
        97, 119, 121, 101, 114, 212, 84, 104, 101, 32, 65, 100, 118, 101, 110, 116, 117, 114, 101,
        32, 111, 102, 32, 84, 111, 109, 32, 83, 97, 119, 121, 101, 114, 32, 105, 115, 32, 97, 32,
        110, 111, 118, 101, 108, 32, 98, 121, 32, 77, 97, 114, 107, 32, 84, 119, 97, 105, 110, 46,
        1, 137, 1, 76, 111, 111, 107, 105, 110, 103, 32, 97, 116, 32, 116, 104, 101, 115, 101, 32,
        115, 116, 97, 114, 115, 32, 115, 117, 100, 100, 101, 110, 108, 121, 32, 100, 119, 97, 114,
        102, 101, 100, 32, 109, 121, 32, 111, 119, 110, 32, 116, 114, 111, 117, 98, 108, 101, 115,
        32, 97, 110, 100, 32, 97, 108, 108, 32, 116, 104, 101, 32, 103, 114, 97, 118, 105, 116,
        105, 101, 115, 32, 111, 102, 32, 116, 101, 114, 114, 101, 115, 116, 114, 105, 97, 108, 32,
        108, 105, 102, 101, 46, 0, 16, 61, 1, 87, 104, 97, 116, 32, 97, 32, 104, 101, 114, 111, 32,
        84, 111, 109, 32, 119, 97, 115, 32, 98, 101, 99, 111, 109, 101, 32, 110, 111, 119, 33, 32,
        72, 101, 32, 100, 105, 100, 32, 110, 111, 116, 32, 103, 111, 32, 115, 107, 105, 112, 112,
        105, 110, 103, 32, 97, 110, 100, 32, 112, 114, 97, 110, 99, 105, 110, 103, 44, 32, 98, 117,
        116, 32, 109, 111, 118, 101, 100, 32, 81, 1, 119, 105, 116, 104, 32, 97, 32, 100, 105, 103,
        110, 105, 102, 105, 101, 100, 32, 115, 119, 97, 103, 103, 101, 114, 44, 32, 97, 115, 32,
        98, 101, 99, 97, 109, 101, 32, 97, 32, 112, 105, 114, 97, 116, 101, 32, 119, 104, 111, 32,
        102, 101, 108, 116, 32, 116, 104, 97, 116, 32, 116, 104, 101, 32, 112, 117, 98, 108, 105,
        99, 32, 101, 121, 101, 32, 119, 97, 115, 32, 111, 110, 32, 104, 105, 109, 105, 1, 32, 65,
        110, 100, 32, 105, 110, 100, 101, 101, 100, 32, 105, 116, 32, 119, 97, 115, 59, 32, 104,
        101, 32, 116, 114, 105, 101, 100, 32, 110, 111, 116, 32, 116, 111, 32, 115, 101, 101, 109,
        32, 116, 111, 32, 115, 101, 101, 32, 116, 104, 101, 32, 108, 111, 111, 107, 115, 32, 111,
        114, 32, 104, 101, 97, 114, 32, 116, 104, 101, 32, 114, 101, 109, 97, 114, 107, 115, 32,
        97, 115, 32, 104, 101, 32, 112, 97, 115, 115, 101, 100, 105, 1, 97, 108, 111, 110, 103, 44,
        32, 98, 117, 116, 32, 116, 104, 101, 121, 32, 119, 101, 114, 101, 32, 102, 111, 111, 100,
        32, 97, 110, 100, 32, 100, 114, 105, 110, 107, 32, 116, 111, 32, 104, 105, 109, 46, 32, 77,
        97, 114, 107, 32, 84, 119, 97, 105, 110, 44, 32, 84, 104, 101, 32, 65, 100, 118, 101, 110,
        116, 117, 114, 101, 32, 111, 102, 32, 84, 111, 109, 32, 83, 97, 119, 121, 101, 114, 44, 32,
        67, 104, 32, 49, 56, 72, 72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 32, 109, 121,
        32, 109, 97, 110, 4, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 212, 84, 104, 101,
        32, 65, 100, 118, 101, 110, 116, 117, 114, 101, 32, 111, 102, 32, 84, 111, 109, 32, 83, 97,
        119, 121, 101, 114, 32, 105, 115, 32, 97, 32, 110, 111, 118, 101, 108, 32, 98, 121, 32, 77,
        97, 114, 107, 32, 84, 119, 97, 105, 110, 46, 4, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 40, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
    ];

    let enc = SimpleWrapper::encode(&SimpleWrapper(test_main.clone()));
    assert!(!enc.is_empty());
    assert_eq!(&enc, &bytes_representation);

    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test_main)));
}

#[test]
fn test_scale_version_compatibility_enum() {
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Encode, Decode)]
    enum TestEnum {
        Numbers((i8, u8, i16, u16, i32, u32, i64, u64, i128, u128)),
        Strings(
            (
                String,
                String,
                String,
                // The SCALE doesn't support Copy-On-Write type, lifetimes and chars here =\
                // Cow<'a, str>
                // &'a str,
                // char,
            ),
        ),
        Containers((Vec<u8>, BTreeMap<String, String>)),
    }

    let numbers = TestEnum::Numbers((
        -i8::MAX,
        u8::MAX,
        -i16::MAX,
        u16::MAX,
        -i32::MAX,
        u32::MAX,
        -i64::MAX,
        u64::MAX,
        -i128::MAX,
        u128::MAX,
    ));
    let enc = SimpleWrapper::encode(&SimpleWrapper(numbers.clone()));

    let bytes_representation = vec![
        0, 129, 255, 1, 128, 255, 255, 1, 0, 0, 128, 255, 255, 255, 255, 1, 0, 0, 0, 0, 0, 0, 128,
        255, 255, 255, 255, 255, 255, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    ];
    assert_eq!(&enc, &bytes_representation);

    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(numbers)));

    let strings = TestEnum::Strings(
        (("What a hero Tom was become now! He did not go skipping and prancing, but moved  \
              with a dignified swagger, as became a pirate who felt that the public eye was on him.").to_string(),
         "And indeed it was; he tried not to seem to see the looks or hear the remarks as he passed".to_string(),
         "along, but they were food and drink to him. Mark Twain, The Adventure of Tom Sawyer, Ch 18".to_string(),
        ));
    let enc = SimpleWrapper::encode(&SimpleWrapper(strings.clone()));

    let bytes_representation = vec![
        1, 149, 2, 87, 104, 97, 116, 32, 97, 32, 104, 101, 114, 111, 32, 84, 111, 109, 32, 119, 97,
        115, 32, 98, 101, 99, 111, 109, 101, 32, 110, 111, 119, 33, 32, 72, 101, 32, 100, 105, 100,
        32, 110, 111, 116, 32, 103, 111, 32, 115, 107, 105, 112, 112, 105, 110, 103, 32, 97, 110,
        100, 32, 112, 114, 97, 110, 99, 105, 110, 103, 44, 32, 98, 117, 116, 32, 109, 111, 118,
        101, 100, 32, 32, 119, 105, 116, 104, 32, 97, 32, 100, 105, 103, 110, 105, 102, 105, 101,
        100, 32, 115, 119, 97, 103, 103, 101, 114, 44, 32, 97, 115, 32, 98, 101, 99, 97, 109, 101,
        32, 97, 32, 112, 105, 114, 97, 116, 101, 32, 119, 104, 111, 32, 102, 101, 108, 116, 32,
        116, 104, 97, 116, 32, 116, 104, 101, 32, 112, 117, 98, 108, 105, 99, 32, 101, 121, 101,
        32, 119, 97, 115, 32, 111, 110, 32, 104, 105, 109, 46, 101, 1, 65, 110, 100, 32, 105, 110,
        100, 101, 101, 100, 32, 105, 116, 32, 119, 97, 115, 59, 32, 104, 101, 32, 116, 114, 105,
        101, 100, 32, 110, 111, 116, 32, 116, 111, 32, 115, 101, 101, 109, 32, 116, 111, 32, 115,
        101, 101, 32, 116, 104, 101, 32, 108, 111, 111, 107, 115, 32, 111, 114, 32, 104, 101, 97,
        114, 32, 116, 104, 101, 32, 114, 101, 109, 97, 114, 107, 115, 32, 97, 115, 32, 104, 101,
        32, 112, 97, 115, 115, 101, 100, 105, 1, 97, 108, 111, 110, 103, 44, 32, 98, 117, 116, 32,
        116, 104, 101, 121, 32, 119, 101, 114, 101, 32, 102, 111, 111, 100, 32, 97, 110, 100, 32,
        100, 114, 105, 110, 107, 32, 116, 111, 32, 104, 105, 109, 46, 32, 77, 97, 114, 107, 32, 84,
        119, 97, 105, 110, 44, 32, 84, 104, 101, 32, 65, 100, 118, 101, 110, 116, 117, 114, 101,
        32, 111, 102, 32, 84, 111, 109, 32, 83, 97, 119, 121, 101, 114, 44, 32, 67, 104, 32, 49,
        56,
    ];
    assert_eq!(&enc, &bytes_representation);

    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(strings)));

    let mut btree_map = BTreeMap::new();
    btree_map.insert(
        "Tom Sawyer".to_string(),
        "The Adventure of Tom Sawyer is a novel by Mark Twain.".to_string(),
    );
    btree_map.insert(
        "Tin-tin".to_string(),
        "Life is rather like a tin of sardines - we're all of us looking for the key.".to_string(),
    );
    btree_map.insert(
            "Red Planet".to_string(),
            "In Red Planet, the only thing thicker than the Martian atmosphere (which is breathable, by the way)".to_string(),
        );
    btree_map.insert(
        "Romeo and Juliet".to_string(),
        "Good night, good night! parting is such sweet sorrow. ".to_string(),
    );

    let containers =
        TestEnum::Containers((vec![0xFF, 0xFE, 0xFB, 0xFA, 0xAA, 0xAB, 0xFF], btree_map));

    let enc = SimpleWrapper::encode(&SimpleWrapper(containers.clone()));
    let bytes_representation = vec![
        2, 28, 255, 254, 251, 250, 170, 171, 255, 16, 40, 82, 101, 100, 32, 80, 108, 97, 110, 101,
        116, 141, 1, 73, 110, 32, 82, 101, 100, 32, 80, 108, 97, 110, 101, 116, 44, 32, 116, 104,
        101, 32, 111, 110, 108, 121, 32, 116, 104, 105, 110, 103, 32, 116, 104, 105, 99, 107, 101,
        114, 32, 116, 104, 97, 110, 32, 116, 104, 101, 32, 77, 97, 114, 116, 105, 97, 110, 32, 97,
        116, 109, 111, 115, 112, 104, 101, 114, 101, 32, 40, 119, 104, 105, 99, 104, 32, 105, 115,
        32, 98, 114, 101, 97, 116, 104, 97, 98, 108, 101, 44, 32, 98, 121, 32, 116, 104, 101, 32,
        119, 97, 121, 41, 64, 82, 111, 109, 101, 111, 32, 97, 110, 100, 32, 74, 117, 108, 105, 101,
        116, 216, 71, 111, 111, 100, 32, 110, 105, 103, 104, 116, 44, 32, 103, 111, 111, 100, 32,
        110, 105, 103, 104, 116, 33, 32, 112, 97, 114, 116, 105, 110, 103, 32, 105, 115, 32, 115,
        117, 99, 104, 32, 115, 119, 101, 101, 116, 32, 115, 111, 114, 114, 111, 119, 46, 32, 28,
        84, 105, 110, 45, 116, 105, 110, 49, 1, 76, 105, 102, 101, 32, 105, 115, 32, 114, 97, 116,
        104, 101, 114, 32, 108, 105, 107, 101, 32, 97, 32, 116, 105, 110, 32, 111, 102, 32, 115,
        97, 114, 100, 105, 110, 101, 115, 32, 45, 32, 119, 101, 39, 114, 101, 32, 97, 108, 108, 32,
        111, 102, 32, 117, 115, 32, 108, 111, 111, 107, 105, 110, 103, 32, 102, 111, 114, 32, 116,
        104, 101, 32, 107, 101, 121, 46, 40, 84, 111, 109, 32, 83, 97, 119, 121, 101, 114, 212, 84,
        104, 101, 32, 65, 100, 118, 101, 110, 116, 117, 114, 101, 32, 111, 102, 32, 84, 111, 109,
        32, 83, 97, 119, 121, 101, 114, 32, 105, 115, 32, 97, 32, 110, 111, 118, 101, 108, 32, 98,
        121, 32, 77, 97, 114, 107, 32, 84, 119, 97, 105, 110, 46,
    ];
    assert_eq!(&enc, &bytes_representation);

    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(containers)));
}

#[test]
fn test_scale_version_compatibility_array() {
    let test = [1, 2, 3, 4, 5, 6, 7, 8, 9];
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    let bytes_representation = vec![
        1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0, 8, 0,
        0, 0, 9, 0, 0, 0,
    ];
    assert_eq!(&enc, &bytes_representation);
    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    let test = [true, false, true, false, false, false, true, true, true];
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));

    let bytes_representation = vec![1, 0, 1, 0, 0, 0, 1, 1, 1];
    assert_eq!(&enc, &bytes_representation);
    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));

    let test = [
        "Something".to_string(),
        "About".to_string(),
        "the".to_string(),
        "Way".to_string(),
        "You".to_string(),
        "Look".to_string(),
        "Tonight".to_string(),
        "1997".to_string(),
    ];
    let enc = SimpleWrapper::encode(&SimpleWrapper(test.clone()));

    let bytes_representation = vec![
        36, 83, 111, 109, 101, 116, 104, 105, 110, 103, 20, 65, 98, 111, 117, 116, 12, 116, 104,
        101, 12, 87, 97, 121, 12, 89, 111, 117, 16, 76, 111, 111, 107, 28, 84, 111, 110, 105, 103,
        104, 116, 16, 49, 57, 57, 55,
    ];
    assert_eq!(&enc, &bytes_representation);

    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test)));
}

#[test]
fn test_scale_version_compatibility_bool() {
    let test = true;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(enc, vec![1]);

    let test = false;
    let enc = SimpleWrapper::encode(&SimpleWrapper(test));
    assert_eq!(enc, vec![0]);

    // Backward compatibility
    let dec = SimpleWrapper::decode(&mut vec![1].as_slice()).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(true)));

    let dec = SimpleWrapper::decode(&mut vec![0].as_slice()).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(false)));
}
