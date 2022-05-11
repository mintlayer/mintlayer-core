use super::Bech32Error;
use bech32::convert_bits;
use bech32::u5;
use bech32::CheckBase32;

pub fn encode<T: AsRef<[u8]>>(raw_data: T) -> Result<Vec<u5>, Bech32Error> {
    convert_bits(raw_data.as_ref(), 8, 5, true)
        .map_err(Bech32Error::from)?
        .check_base32()
        .map_err(Bech32Error::from)
}

pub fn decode<T: AsRef<[u5]>>(base32_data: T) -> Result<Vec<u8>, Bech32Error> {
    convert_bits(base32_data.as_ref(), 5, 8, false).map_err(Bech32Error::from)
}

#[cfg(test)]
mod tests {
    use std::vec;

    use super::*;

    #[test]
    fn base32_test() {
        // Empty buffer
        let buffer = encode(Vec::<u8>::new()).unwrap();
        assert_eq!(decode(buffer).unwrap(), Vec::<u8>::new());

        // Vec with one byte
        for i in 0..=255 {
            let buffer = encode(vec![i]).unwrap();
            println!("[{}, {}]", &buffer[0].to_u8(), &buffer[1].to_u8());
            assert_eq!(decode(buffer).unwrap(), vec![i]);
        }

        // Long vec
        let mut buffer = Vec::new();
        for i in 0..=255 {
            buffer.push(i);
        }
        let enc_buffer = encode(&buffer).unwrap();
        assert_eq!(decode(enc_buffer).unwrap(), buffer);
    }
}
