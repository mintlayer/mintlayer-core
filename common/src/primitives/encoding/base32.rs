use super::Bech32Error;
use bech32::convert_bits;
use bech32::u5;
use bech32::CheckBase32;

pub fn encode<T: AsRef<[u8]>>(raw_data: T) -> Result<Vec<u5>, Bech32Error> {
    convert_bits(raw_data.as_ref(), 8, 5, false)
        .map_err(Bech32Error::from)?
        .check_base32()
        .map_err(Bech32Error::from)
}

pub fn decode<T: AsRef<[u5]>>(base32_data: T) -> Result<Vec<u8>, Bech32Error> {
    convert_bits(base32_data.as_ref(), 5, 8, false).map_err(Bech32Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_test() {
        let buffer = encode(vec![0u8]).unwrap();
        assert_eq!(decode(buffer).unwrap(), vec![0u8]);

        let buffer = encode(Vec::<u8>::new()).unwrap();
        assert_eq!(decode(buffer).unwrap(), Vec::<u8>::new());
    }
}
