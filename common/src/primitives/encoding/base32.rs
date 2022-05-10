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
    convert_bits(base32_data.as_ref(), 5, 8, true).map_err(Bech32Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::u5;

    #[test]
    fn numeric_test() {
        let buffer = vec![u5::try_from_u8(0).unwrap()];
        assert_eq!(decode(buffer).unwrap(), vec![0]);

        let buffer = vec![u5::try_from_u8(b'M').unwrap(), u5::try_from_u8(b'Y').unwrap()];
        assert_eq!(decode(buffer).unwrap(), vec![0]);
    }
}
