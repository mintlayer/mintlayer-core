mod utils;

use rand::Rng;
use serialization::{Decode, Encode};
use std::collections::BTreeMap;
use utils::{OptionWrapper, SimpleWrapper};

#[test]
fn test_scale_structures() {
    let mut rng = rand::thread_rng();

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
    for _ in 0..1024 {
        btree_map.insert(
            format!("Tom Sawyer {}", rng.gen::<u64>()),
            "The Adventure of Tom Sawyer is a novel by Mark Twain.".to_string(),
        );
        btree_map.insert(
            format!("Tin-tin {}", rng.gen::<u64>()),
            "Life is rather like a tin of sardines - we're all of us looking for the key."
                .to_string(),
        );
        btree_map.insert(
            format!("Red Planet {}", rng.gen::<u64>()),
            "In Red Planet, the only thing thicker than the Martian atmosphere (which is breathable, by the way)".to_string(),
        );
        btree_map.insert(
            format!("Romeo and Juliet {}", rng.gen::<u64>()),
            "Good night, good night! parting is such sweet sorrow. ".to_string(),
        );
    }

    let mut field_btree_map_string = BTreeMap::new();
    for _ in 0..1024 {
        field_btree_map_string.insert(
            rng.gen::<u128>(),
            "The Adventure of Tom Sawyer is a novel by Mark Twain.".to_string(),
        );
    }

    let mut field_btree_map_bytes = BTreeMap::new();
    for _ in 0..1024 {
        field_btree_map_bytes.insert(
            rng.gen::<u128>(),
            vec![
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
                rng.gen::<u8>(),
            ],
        );
    }

    let test = TestStruct {
        field_enum_number: TestEnum::Numbers((
            -1i8,
            2u8,
            -1234i16,
            5678u16,
            -1036572536i32,
            2415369116u32,
            -2321372031054735191i64,
            1091632910434195781u64,
            -170141123460424235652481386091358552721i128,
            210614612912676532892982561042679146832u128,
        )),
        field_enum_strings: TestEnum::Strings(
            (("What a hero Tom was become now! He did not go skipping and prancing, but moved  \
              with a dignified swagger, as became a pirate who felt that the public eye was on him.").to_string(),
             "And indeed it was; he tried not to seem to see the looks or hear the remarks as he passed".to_string(),
             "along, but they were food and drink to him. Mark Twain, The Adventure of Tom Sawyer, Ch 18".to_string(),
            )),

        field_enum_containers: TestEnum::Containers((
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
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

    let enc = SimpleWrapper::encode(&SimpleWrapper(test_main.clone()));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(test_main)));
}

#[test]
fn test_scale_enums_with_single_variant() {
    #[derive(Encode, Decode, Debug, PartialEq, Eq)]
    enum TestEnum {
        OnlyOneVariant,
    }
    let te = TestEnum::OnlyOneVariant;
    let enc = TestEnum::encode(&te);
    assert!(!enc.is_empty());
    dbg!(&enc);
    let dec = TestEnum::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(TestEnum::OnlyOneVariant));

    #[derive(Encode, Decode, Debug, PartialEq, Eq)]
    enum TestEnum2 {
        OnlyOneVariant(u8),
    }
    let te = TestEnum2::OnlyOneVariant(0xAB);
    let enc = TestEnum2::encode(&te);
    assert!(!enc.is_empty());
    dbg!(&enc);
    let dec = TestEnum2::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(TestEnum2::OnlyOneVariant(0xAB)));

    #[derive(Encode, Decode, Debug, PartialEq, Eq)]
    enum TestEnum3 {
        OnlyOneVariant(u16),
    }
    let te = TestEnum3::OnlyOneVariant(0xABCD);
    let enc = TestEnum3::encode(&te);
    assert!(!enc.is_empty());
    dbg!(&enc);
    let dec = TestEnum3::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(TestEnum3::OnlyOneVariant(0xABCD)));

    #[derive(Encode, Decode, Debug, PartialEq, Eq)]
    enum TestEnum4 {
        OnlyOneVariant(u32),
    }
    let te = TestEnum4::OnlyOneVariant(0xABCDEF12);
    let enc = TestEnum4::encode(&te);
    assert!(!enc.is_empty());
    dbg!(&enc);
    let dec = TestEnum4::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(TestEnum4::OnlyOneVariant(0xABCDEF12)));

    #[derive(Encode, Decode, Debug, PartialEq, Eq)]
    enum TestEnum5 {
        OnlyOneVariant(u64),
    }
    let te = TestEnum5::OnlyOneVariant(0xABCDEF1213141516);
    let enc = TestEnum5::encode(&te);
    assert!(!enc.is_empty());
    dbg!(&enc);
    let dec = TestEnum5::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(TestEnum5::OnlyOneVariant(0xABCDEF1213141516)));

    #[derive(Encode, Decode, Debug, PartialEq, Eq)]
    enum TestEnum6 {
        OnlyOneVariant(String),
    }
    let te = TestEnum6::OnlyOneVariant("Hello, world!".to_string());
    let enc = TestEnum6::encode(&te);
    assert!(!enc.is_empty());
    dbg!(&enc);
    let dec = TestEnum6::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(
        dec,
        Some(TestEnum6::OnlyOneVariant("Hello, world!".to_string()))
    );

    #[derive(Encode, Decode, Debug, PartialEq, Eq)]
    enum TestEnum7 {
        OnlyOneVariant(Vec<u8>),
    }
    let te = TestEnum7::OnlyOneVariant(vec![1, 2, 3, 4]);
    let enc = TestEnum7::encode(&te);
    assert!(!enc.is_empty());
    dbg!(&enc);
    let dec = TestEnum7::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(TestEnum7::OnlyOneVariant(vec![1, 2, 3, 4])));

    #[derive(Encode, Decode, Debug, PartialEq, Eq)]
    enum TestEnum8 {
        OnlyOneVariant((u64, Vec<u8>, String, Option<i32>)),
    }
    let te = TestEnum8::OnlyOneVariant((
        u64::MAX,
        vec![1, 2, 3, 4],
        "Hello, world!".to_string(),
        Some(i32::MAX),
    ));
    let enc = TestEnum8::encode(&te);
    assert!(!enc.is_empty());
    dbg!(&enc);
    let dec = TestEnum8::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(
        dec,
        Some(TestEnum8::OnlyOneVariant((
            u64::MAX,
            vec![1, 2, 3, 4],
            "Hello, world!".to_string(),
            Some(i32::MAX),
        )))
    );
}
