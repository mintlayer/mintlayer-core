mod utils;

use arraytools::ArrayTools;
use hex_literal::hex;
use serialization_core::{Decode, Encode};
use std::collections::BTreeMap;
use utils::{OptionWrapper, SimpleWrapper};

#[test]
fn test_scale_version_compatibility_numbers() {
    // integers i8, u8, i16, u16, i32, u32, i64, u64, i128, u128
    {
        // i8
        let test = 1i8;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, hex!("01"));
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut ArrayTools::as_slice(&hex!("01"))).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
        // u8
        let test = 2u8;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, hex!("02"));
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut ArrayTools::as_slice(&hex!("02"))).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
        // i16
        let test = 1234i16;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, hex!("d204"));
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut ArrayTools::as_slice(&hex!("d204"))).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
        // u16
        let test = 5678u16;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, hex!("2e16"));
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut ArrayTools::as_slice(&hex!("2e16"))).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
        // i32
        let test = 1036572536i32;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, hex!("78d7c83d"));
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut ArrayTools::as_slice(&hex!("78d7c83d"))).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
        // u32
        let test = 2415369116u32;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, hex!("9c9bf78f"));
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut ArrayTools::as_slice(&hex!("9c9bf78f"))).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
        // i64
        let test = -2321372031054735191i64;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, hex!("a99874d96fd4c8df"));
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut ArrayTools::as_slice(&hex!("a99874d96fd4c8df"))).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
        // u64
        let test = 1091632910434195781u64;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, hex!("45598e2b5942260f"));
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut ArrayTools::as_slice(&hex!("45598e2b5942260f"))).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
        // i128
        let test = -170141123460424235652481386091358552721i128;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, hex!("6f7d32890204cfda1af9994ef5020080"));
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut ArrayTools::as_slice(&hex!(
            "6f7d32890204cfda1af9994ef5020080"
        )))
        .ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
        // u128
        let test = 210614612912676532892982561042679146832u128;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, hex!("5029f787d210ec973296fe1e23e6729e"));
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut ArrayTools::as_slice(&hex!(
            "5029f787d210ec973296fe1e23e6729e"
        )))
        .ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
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
            vec![1, 2, 3, 4, 5, 6, 7],
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
        field_vector_bytes: hex!("48656c6c6f20776f726c64206d79206d616e").to_vec(),
        field_btree_map_string,
        field_btree_map_bytes,
        field_nested_stuct: None,
    };
    let mut test_main = test.clone();
    test_main.field_nested_stuct = Some(Box::new(test));

    let bytes_representation = hex!(
        "0081ff0180ffff01000080ffffffff0100000000000080ffffffffffffffff0100000000000000000000000000
        0080ffffffffffffffffffffffffffffffff019502576861742061206865726f20546f6d20776173206265636f6
        d65206e6f772120486520646964206e6f7420676f20736b697070696e6720616e64207072616e63696e672c2062
        7574206d6f7665642020776974682061206469676e696669656420737761676765722c20617320626563616d652
        061207069726174652077686f2066656c74207468617420746865207075626c69632065796520776173206f6e20
        68696d2e6501416e6420696e64656564206974207761733b206865207472696564206e6f7420746f207365656d2
        0746f2073656520746865206c6f6f6b73206f722068656172207468652072656d61726b73206173206865207061
        737365646901616c6f6e672c206275742074686579207765726520666f6f6420616e64206472696e6b20746f206
    8696d2e204d61726b20547761696e2c2054686520416476656e74757265206f6620546f6d205361777965722c204368
    203138021c01020304050607102852656420506c616e65748d01496e2052656420506c616e65742c20746865206f6e6
    c79207468696e6720746869636b6572207468616e20746865204d61727469616e2061746d6f73706865726520287768
    6963682069732062726561746861626c652c20627920746865207761792940526f6d656f20616e64204a756c696574d
    8476f6f64206e696768742c20676f6f64206e69676874212070617274696e6720697320737563682073776565742073
    6f72726f772e201c54696e2d74696e31014c69666520697320726174686572206c696b6520612074696e206f6620736
    17264696e6573202d20776527726520616c6c206f66207573206c6f6f6b696e6720666f7220746865206b65792e2854
    6f6d20536177796572d454686520416476656e74757265206f6620546f6d205361777965722069732061206e6f76656
    c206279204d61726b20547761696e2e0189014c6f6f6b696e672061742074686573652073746172732073756464656e
    6c792064776172666564206d79206f776e2074726f75626c657320616e6420616c6c207468652067726176697469657
    3206f6620746572726573747269616c206c6966652e00103d01576861742061206865726f20546f6d20776173206265
    636f6d65206e6f772120486520646964206e6f7420676f20736b697070696e6720616e64207072616e63696e672c206
    27574206d6f766564205101776974682061206469676e696669656420737761676765722c20617320626563616d6520
    61207069726174652077686f2066656c74207468617420746865207075626c69632065796520776173206f6e2068696
    d690120416e6420696e64656564206974207761733b206865207472696564206e6f7420746f207365656d20746f2073
    656520746865206c6f6f6b73206f722068656172207468652072656d61726b732061732068652070617373656469016
    16c6f6e672c206275742074686579207765726520666f6f6420616e64206472696e6b20746f2068696d2e204d61726b
    20547761696e2c2054686520416476656e74757265206f6620546f6d205361777965722c2043682031384848656c6c6
    f20776f726c64206d79206d616e04ff000000000000000000000000000000d454686520416476656e74757265206f66
    20546f6d205361777965722069732061206e6f76656c206279204d61726b20547761696e2e04ff00000000000000000
    00000000000002800010203040506070809010081ff0180ffff01000080ffffffff0100000000000080ffffffffffff
    ffff01000000000000000000000000000080ffffffffffffffffffffffffffffffff019502576861742061206865726
    f20546f6d20776173206265636f6d65206e6f772120486520646964206e6f7420676f20736b697070696e6720616e64
    207072616e63696e672c20627574206d6f7665642020776974682061206469676e696669656420737761676765722c2
    0617320626563616d652061207069726174652077686f2066656c74207468617420746865207075626c696320657965
    20776173206f6e2068696d2e6501416e6420696e64656564206974207761733b206865207472696564206e6f7420746
    f207365656d20746f2073656520746865206c6f6f6b73206f722068656172207468652072656d61726b732061732068
    65207061737365646901616c6f6e672c206275742074686579207765726520666f6f6420616e64206472696e6b20746
    f2068696d2e204d61726b20547761696e2c2054686520416476656e74757265206f6620546f6d205361777965722c20
    4368203138021c01020304050607102852656420506c616e65748d01496e2052656420506c616e65742c20746865206
    f6e6c79207468696e6720746869636b6572207468616e20746865204d61727469616e2061746d6f7370686572652028
    77686963682069732062726561746861626c652c20627920746865207761792940526f6d656f20616e64204a756c696
    574d8476f6f64206e696768742c20676f6f64206e69676874212070617274696e672069732073756368207377656574
    20736f72726f772e201c54696e2d74696e31014c69666520697320726174686572206c696b6520612074696e206f662
    073617264696e6573202d20776527726520616c6c206f66207573206c6f6f6b696e6720666f7220746865206b65792e
    28546f6d20536177796572d454686520416476656e74757265206f6620546f6d205361777965722069732061206e6f7
    6656c206279204d61726b20547761696e2e0189014c6f6f6b696e672061742074686573652073746172732073756464
    656e6c792064776172666564206d79206f776e2074726f75626c657320616e6420616c6c20746865206772617669746
    96573206f6620746572726573747269616c206c6966652e00103d01576861742061206865726f20546f6d2077617320
    6265636f6d65206e6f772120486520646964206e6f7420676f20736b697070696e6720616e64207072616e63696e672
    c20627574206d6f766564205101776974682061206469676e696669656420737761676765722c20617320626563616d
    652061207069726174652077686f2066656c74207468617420746865207075626c69632065796520776173206f6e206
    8696d690120416e6420696e64656564206974207761733b206865207472696564206e6f7420746f207365656d20746f
    2073656520746865206c6f6f6b73206f722068656172207468652072656d61726b73206173206865207061737365646
    901616c6f6e672c206275742074686579207765726520666f6f6420616e64206472696e6b20746f2068696d2e204d61
    726b20547761696e2c2054686520416476656e74757265206f6620546f6d205361777965722c2043682031384848656
    c6c6f20776f726c64206d79206d616e04ff000000000000000000000000000000d454686520416476656e7475726520
    6f6620546f6d205361777965722069732061206e6f76656c206279204d61726b20547761696e2e04ff0000000000000
    00000000000000000280001020304050607080900"
    );

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
    {
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

        let bytes_representation = hex!(
            "0081ff0180ffff01000080ffffffff0100000000000080ffffffffffffffff
    01000000000000000000000000000080ffffffffffffffffffffffffffffffff"
        );
        assert_eq!(&enc, &bytes_representation);

        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(numbers)));
    }
    {
        let strings = TestEnum::Strings(
        (("What a hero Tom was become now! He did not go skipping and prancing, but moved  \
              with a dignified swagger, as became a pirate who felt that the public eye was on him.").to_string(),
         "And indeed it was; he tried not to seem to see the looks or hear the remarks as he passed".to_string(),
         "along, but they were food and drink to him. Mark Twain, The Adventure of Tom Sawyer, Ch 18".to_string(),
        ));
        let enc = SimpleWrapper::encode(&SimpleWrapper(strings.clone()));

        let bytes_representation = hex!(
        "019502576861742061206865726f20546f6d20776173206265636f6d65206e6f772120486520646964206e6f74
        20676f20736b697070696e6720616e64207072616e63696e672c20627574206d6f7665642020776974682061206
        469676e696669656420737761676765722c20617320626563616d652061207069726174652077686f2066656c74
        207468617420746865207075626c69632065796520776173206f6e2068696d2e6501416e6420696e64656564206
        974207761733b206865207472696564206e6f7420746f207365656d20746f2073656520746865206c6f6f6b7320
        6f722068656172207468652072656d61726b73206173206865207061737365646901616c6f6e672c20627574207
        4686579207765726520666f6f6420616e64206472696e6b20746f2068696d2e204d61726b20547761696e2c2054
        686520416476656e74757265206f6620546f6d205361777965722c204368203138"
    );
        assert_eq!(&enc, &bytes_representation);

        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(strings)));
    }
    {
        let mut btree_map = BTreeMap::new();
        btree_map.insert(
            "Tom Sawyer".to_string(),
            "The Adventure of Tom Sawyer is a novel by Mark Twain.".to_string(),
        );
        btree_map.insert(
            "Tin-tin".to_string(),
            "Life is rather like a tin of sardines - we're all of us looking for the key."
                .to_string(),
        );
        btree_map.insert(
            "Red Planet".to_string(),
            "In Red Planet, the only thing thicker than the Martian atmosphere (which is breathable, by the way)".to_string(),
        );
        btree_map.insert(
            "Romeo and Juliet".to_string(),
            "Good night, good night! parting is such sweet sorrow. ".to_string(),
        );

        let containers = TestEnum::Containers((vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10], btree_map));

        let enc = SimpleWrapper::encode(&SimpleWrapper(containers.clone()));
        let bytes_representation = hex!(
        "02280102030405060708090a102852656420506c616e65748d01496e2052656420506c616e65742c2074686520
        6f6e6c79207468696e6720746869636b6572207468616e20746865204d61727469616e2061746d6f73706865726
        5202877686963682069732062726561746861626c652c20627920746865207761792940526f6d656f20616e6420
        4a756c696574d8476f6f64206e696768742c20676f6f64206e69676874212070617274696e67206973207375636
        820737765657420736f72726f772e201c54696e2d74696e31014c69666520697320726174686572206c696b6520
        612074696e206f662073617264696e6573202d20776527726520616c6c206f66207573206c6f6f6b696e6720666
        f7220746865206b65792e28546f6d20536177796572d454686520416476656e74757265206f6620546f6d205361
        777965722069732061206e6f76656c206279204d61726b20547761696e2e"
    );
        assert_eq!(&enc, &bytes_representation);

        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(containers)));
    }
}

#[test]
fn test_scale_version_compatibility_array() {
    {
        let test = [
            12345, 67890, 10111213, 141516171, 192021229, 232425262, 293031323, 343536373,
            394041424, 454647484,
        ];
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        let bytes_representation = hex!(
            "3930000032090100ed489a008b5d6f08ed02720b2e87da0d9b4d7711f5f2791450987c17bc5e191b"
        );
        assert_eq!(&enc, &bytes_representation);
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
        let test = [true, false, true, false, false, false, true, true, true];
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));

        let bytes_representation = vec![1, 0, 1, 0, 0, 0, 1, 1, 1];
        assert_eq!(&enc, &bytes_representation);
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
    {
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

        let bytes_representation = hex!(
        "24536f6d657468696e671441626f75740c7468650c5761790c596f75104c6f6f6b1c546f6e6967687410313939
        37"
    );
        assert_eq!(&enc, &bytes_representation);

        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut &bytes_representation[..]).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(test)));
    }
}

#[test]
fn test_scale_version_compatibility_bool() {
    {
        let test = true;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, vec![1]);
    }
    {
        let test = false;
        let enc = SimpleWrapper::encode(&SimpleWrapper(test));
        assert_eq!(enc, vec![0]);
    }
    {
        // Backward compatibility
        let dec = SimpleWrapper::decode(&mut vec![1].as_slice()).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(true)));
    }
    {
        let dec = SimpleWrapper::decode(&mut vec![0].as_slice()).ok();
        assert!(&dec.is_some());
        assert_eq!(dec, Some(SimpleWrapper(false)));
    }
}
