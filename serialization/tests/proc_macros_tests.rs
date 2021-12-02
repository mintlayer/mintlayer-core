#[macro_use]
extern crate serialization_derive;

#[test]
fn test_mint_encode() {
    #[macro_use]
    use parity_scale_codec_derive::{Decode, Encode};
    use serialization_derive::MintEncode;

    #[derive(MintEncode)]
    // #[derive(Encode, Decode)]
    pub struct TestStruct {
        value_u8: u8,
        value_u16: u16,
        value_u32: u32,
        value_u64: u64,
        value_u128: u128,
        value_vec: Vec<u8>,
    }
    let data = TestStruct {
        value_u8: u8::MAX,
        value_u16: u16::MAX,
        value_u32: u32::MAX,
        value_u64: u64::MAX,
        value_u128: u128::MAX,
        value_vec: vec![u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX, u8::MAX],
    };
    let enc = data.encode();
}
