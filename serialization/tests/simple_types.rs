mod utils;

use serialization::{Decode, Encode};
use utils::{OptionWrapper, SimpleWrapper};

#[test]
fn test_scale_numbers() {
    // 8-bit	i8	u8
    let enc = SimpleWrapper::encode(&SimpleWrapper(0i8));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0i8)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(-12i8));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(-12i8)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(98i8));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(98i8)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(104i8));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(104i8)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(0u8));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0u8)));

    // 16-bit	i16	u16
    let enc = SimpleWrapper::encode(&SimpleWrapper(0i16));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0i16)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(-1234i16));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(-1234i16)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(-1234i16));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(-1234i16)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(5678u16));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(5678u16)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(0u16));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0u16)));

    // 32-bit	i32	u32
    let enc = SimpleWrapper::encode(&SimpleWrapper(0i32));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0i32)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(-1036572536i32));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(-1036572536i32)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(1036572536i32));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(1036572536i32)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(2415369116u32));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(2415369116u32)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(0u32));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0u32)));

    // 64-bit	i64	u64
    let enc = SimpleWrapper::encode(&SimpleWrapper(0i64));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0i64)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(-2321372031054735191i64));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(-2321372031054735191i64)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(1091632910434195781u64));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(1091632910434195781u64)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(141123460424235652u64));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(141123460424235652u64)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(0u64));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0u64)));

    // 128-bit	i128	u128
    let enc = SimpleWrapper::encode(&SimpleWrapper(0i128));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0i128)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(-170141123460424235652481386091358552721i128));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(
        dec,
        Some(SimpleWrapper(-170141123460424235652481386091358552721i128))
    );

    let enc = SimpleWrapper::encode(&SimpleWrapper(10614612912676532892982561042679146832i128));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(
        dec,
        Some(SimpleWrapper(10614612912676532892982561042679146832i128))
    );

    let enc = SimpleWrapper::encode(&SimpleWrapper(210614612912676532892982561042679146832u128));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(
        dec,
        Some(SimpleWrapper(210614612912676532892982561042679146832u128))
    );

    let enc = SimpleWrapper::encode(&SimpleWrapper(0u128));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0u128)));

    // arch	isize	usize - unfortunately, doesn't implement at SCALE
    //
    // the trait `WrapperTypeEncode` is not implemented for `isize`
    // the trait `WrapperTypeEncode` is not implemented for `usize`
}

#[test]
fn test_scale_options() {
    // Strings
    let result = Some("any error message".to_string());
    let enc = OptionWrapper::encode(&OptionWrapper::new(result.clone()));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(result)));

    // Decode and encode 1_048_576 chars 'X'
    let result = Some(format!("!{:X<4194304}!", ""));
    let enc = OptionWrapper::encode(&OptionWrapper::new(result.clone()));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(result)));

    // Numbers
    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(0i8)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(0i8))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(-54i8)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(-54i8))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(73i8)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(73i8))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(123u8)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(123u8))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(0u8)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(0u8))));

    // 16-bit	i16	u16
    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(0i16)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(0i16))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(-12345i16)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(-12345i16))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(5432i16)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(5432i16))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(5678u16)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(5678u16))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(0u16)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(0u16))));

    // 32-bit	i32	u32
    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(0i32)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(0i32))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(-1036572536i32)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(-1036572536i32))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(52756301i32)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(52756301i32))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(2415369116u32)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(2415369116u32))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(0u32)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(0u32))));

    // 64-bit	i64	u64
    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(0i64)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(0i64))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(-2321372031054735191i64)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(-2321372031054735191i64))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(2106146129126765328i64)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(2106146129126765328i64))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(1091632910434195781u64)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(1091632910434195781u64))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(0u64)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(0u64))));

    // 128-bit	i128	u128
    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(0i128)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(0i128))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(
        -170141123460424235652481386091358552721i128,
    )));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(
        dec,
        Some(OptionWrapper::new(Some(
            -170141123460424235652481386091358552721i128
        )))
    );

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(
        170141123460424235652481386091358552721i128,
    )));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(
        dec,
        Some(OptionWrapper::new(Some(
            170141123460424235652481386091358552721i128
        )))
    );

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(
        210614612912676532892982561042679146832u128,
    )));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(
        dec,
        Some(OptionWrapper::new(Some(
            210614612912676532892982561042679146832u128
        )))
    );

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(0u128)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(0u128))));

    // Nested enums
    #[derive(Debug, Clone, PartialEq, PartialOrd, Encode, Decode)]
    enum TestEnum {
        TestField1(Option<String>),
        TestField2(Option<Box<Option<String>>>),
    }

    let result = TestEnum::TestField1(Some("any error message".to_string()));
    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(result)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(
        dec,
        Some(OptionWrapper::new(Some(TestEnum::TestField1(Some(
            "any error message".to_string()
        )))))
    );

    let result = TestEnum::TestField2(Some(Box::new(Some("any error message".to_string()))));
    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(result)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(
        dec,
        Some(OptionWrapper::new(Some(TestEnum::TestField2(Some(
            Box::new(Some("any error message".to_string()))
        )))))
    );
}

#[test]
fn test_scale_arrays() {
    let array = [0xFF; 64_000];
    let enc = SimpleWrapper::encode(&SimpleWrapper(array));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(array)));

    let array = [0x00; 64_000];
    let enc = SimpleWrapper::encode(&SimpleWrapper(array));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(array)));

    let array = [0xFF; 0];
    let enc = SimpleWrapper::encode(&SimpleWrapper(array));
    assert!(enc.is_empty());

    let array = [0xFF; 1];
    let enc = SimpleWrapper::encode(&SimpleWrapper(array));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(array)));
}

#[test]
fn test_scale_tuples() {
    let tuple = (
        -11i8,
        12u8,
        // SCALE doesn't support floats here
        // 12.1f32,
        // 12.9f64,
        -13i16,
        14u16,
        -15i32,
        16u32,
        -17i64,
        18u64,
        -19i128,
        20u128,
        "Hello, world!".to_string(),
        // SCALE doesn't support chars here
        // 'c',
        Some([0xFF; 32]),
    );
    let enc = SimpleWrapper::encode(&SimpleWrapper(tuple.clone()));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(tuple)));
}
