use parity_scale_codec::{Decode, Encode};
use serialization_utils::CompactWrapper;

#[test]
fn test_scale_compact_numbers() {
    // Numbers
    let enc = CompactWrapper::encode(&CompactWrapper::new(u8::MAX));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(u8::MAX)));

    let enc = CompactWrapper::encode(&CompactWrapper::new(0u8));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(0u8)));

    // 16-bit
    let enc = CompactWrapper::encode(&CompactWrapper::new(u16::MAX));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(u16::MAX)));

    let enc = CompactWrapper::encode(&CompactWrapper::new(0u16));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(0u16)));

    // 32-bit
    let enc = CompactWrapper::encode(&CompactWrapper::new(u32::MAX));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(u32::MAX)));

    let enc = CompactWrapper::encode(&CompactWrapper::new(0u32));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(0u32)));

    // 64-bit
    let enc = CompactWrapper::encode(&CompactWrapper::new(u64::MAX));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(u64::MAX)));

    let enc = CompactWrapper::encode(&CompactWrapper::new(0u64));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(0u64)));

    // 128-bit
    let enc = CompactWrapper::encode(&CompactWrapper::new(u128::MAX));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(u128::MAX)));

    let enc = CompactWrapper::encode(&CompactWrapper::new(0u128));
    assert!(!enc.is_empty());
    let dec = CompactWrapper::decode(&mut &enc[..]).ok();
    assert!(&dec.is_some());
    assert_eq!(dec, Some(CompactWrapper::new(0u128)));
}
