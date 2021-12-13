use parity_scale_codec::{Decode, Encode};
use serialization_utils::{OptionWrapper, SimpleWrapper};

#[test]
fn test_scale_numbers() {
    // 8-bit	i8	u8
    let enc = SimpleWrapper::encode(&SimpleWrapper(0i8));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(0i8)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(-i8::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(-i8::MAX)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(i8::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(i8::MAX)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(u8::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(u8::MAX)));

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

    let enc = SimpleWrapper::encode(&SimpleWrapper(-i16::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(-i16::MAX)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(i16::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(i16::MAX)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(u16::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(u16::MAX)));

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

    let enc = SimpleWrapper::encode(&SimpleWrapper(-i32::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(-i32::MAX)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(i32::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(i32::MAX)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(u32::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(u32::MAX)));

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

    let enc = SimpleWrapper::encode(&SimpleWrapper(-i64::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(-i64::MAX)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(i64::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(i64::MAX)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(u64::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(u64::MAX)));

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

    let enc = SimpleWrapper::encode(&SimpleWrapper(-i128::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(-i128::MAX)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(i128::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(i128::MAX)));

    let enc = SimpleWrapper::encode(&SimpleWrapper(u128::MAX));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(u128::MAX)));

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

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(-i8::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(-i8::MAX))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(i8::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(i8::MAX))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(u8::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(u8::MAX))));

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

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(-i16::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(-i16::MAX))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(i16::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(i16::MAX))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(u16::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(u16::MAX))));

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

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(-i32::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(-i32::MAX))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(i32::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(i32::MAX))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(u32::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(u32::MAX))));

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

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(-i64::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(-i64::MAX))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(i64::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(i64::MAX))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(u64::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(u64::MAX))));

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

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(-i128::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(-i128::MAX))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(i128::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(i128::MAX))));

    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(u128::MAX)));
    assert!(!enc.is_empty());
    let dec = OptionWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(OptionWrapper::new(Some(u128::MAX))));

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
    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(result.clone())));
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
    let enc = OptionWrapper::encode(&OptionWrapper::new(Some(result.clone())));
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
    let enc = SimpleWrapper::encode(&SimpleWrapper(array.clone()));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(array)));

    let array = [0x00; 64_000];
    let enc = SimpleWrapper::encode(&SimpleWrapper(array.clone()));
    assert!(!enc.is_empty());
    let dec = SimpleWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(SimpleWrapper(array)));

    let array = [0xFF; 0];
    let enc = SimpleWrapper::encode(&SimpleWrapper(array.clone()));
    assert!(enc.is_empty());

    let array = [0xFF; 1];
    let enc = SimpleWrapper::encode(&SimpleWrapper(array.clone()));
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
