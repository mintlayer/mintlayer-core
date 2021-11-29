use crate::primitives::Error;
use bech32::{self, encode_to_fmt, u5, FromBase32, ToBase32, Variant};

#[derive(Debug, Clone, PartialEq)]
pub struct Bech32Address {
    /// the bech32 address in string
    addr: String,
    /// the variant used to encode the `hrp` and `data` into `addr`
    variant: Bech32Variant,
    data: Vec<u8>,
    hrp: String,
}

impl Bech32Address {
    pub fn address(&self) -> &str {
        &self.addr
    }

    pub fn variant(&self) -> Bech32Variant {
        self.variant
    }

    pub fn raw_hrp(&self) -> &str {
        &self.hrp
    }

    pub fn create_address<T: AsRef<[u8]>>(
        hrp: &str,
        data: T,
        variant: Bech32Variant,
    ) -> Result<Self, Error> {
        let mut buf = String::new();
        let data: &[u8] = data.as_ref();

        let b_variant = variant.into_variant();

        encode_to_fmt(&mut buf, hrp, data.to_base32(), b_variant)
            .map_err(|e| Error::Bech32Error(e))?
            .map_err(|e| Error::CustomError(e))?;

        Ok(Self {
            addr: buf,
            variant,
            data: data.to_vec(),
            hrp: hrp.to_string(),
        })
    }

    pub fn decode_to_address(s: &str) -> Result<Self, Error> {
        let (hrp, data, variant) = bech32::decode(s).map_err(|e| Error::Bech32Error(e))?;

        Ok(Self {
            addr: s.to_string(),
            variant: Bech32Variant::from_variant(variant),
            data: to_vec_of_u8(&data)?,
            hrp,
        })
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Bech32Variant {
    BIP0173,
    BIP0350,
}

impl Bech32Variant {
    fn into_variant(self) -> Variant {
        match self {
            Bech32Variant::BIP0173 => Variant::Bech32,
            Bech32Variant::BIP0350 => Variant::Bech32m,
        }
    }

    fn from_variant(v: Variant) -> Self {
        match v {
            Variant::Bech32 => Bech32Variant::BIP0173,
            Variant::Bech32m => Bech32Variant::BIP0350,
        }
    }
}

pub trait CreateAddress {
    fn create_address(&self) -> Result<Bech32Address, Error>;
}

fn to_vec_of_u8(data: &[u5]) -> Result<Vec<u8>, Error> {
    Vec::<u8>::from_base32(data).map_err(|e| Error::Bech32Error(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_vec_of_u8_test() {
        // simple test
        let parameter = vec![0x00, 0x01, 0x02];
        match to_vec_of_u8(&parameter.to_base32()) {
            Ok(x) => {
                assert_eq!(x, parameter);
            }
            Err(e) => {
                assert!(false);
            }
        }

        let parameter: Vec<u8> = vec![35, 34, 33, 32, 31];
        match to_vec_of_u8(&parameter.to_base32()) {
            Ok(_) => {
                assert!(true);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn variant_test() {
        assert_eq!(Bech32Variant::BIP0173.into_variant(), Variant::Bech32);
        assert_eq!(Bech32Variant::BIP0350.into_variant(), Variant::Bech32m);
    }

    #[test]
    fn address_structure() {
        let hrp = "bech32";

        // testing BIP0173
        let bip0173_addr = "bech321qqqsyrhqy2a".to_string();
        match Bech32Address::create_address(hrp, vec![0x00, 0x01, 0x02], Bech32Variant::BIP0173) {
            Ok(x) => {
                assert_eq!(x.addr, bip0173_addr);
                assert_eq!(x.variant, Bech32Variant::BIP0173);
                assert_eq!(x.hrp, hrp.to_string());
                assert_eq!(x.data, vec![0x00, 0x01, 0x02]);
            }
            Err(_) => {
                assert!(false);
            }
        }

        match Bech32Address::decode_to_address(&bip0173_addr) {
            Ok(x) => {
                assert_eq!(x.addr, bip0173_addr);
                assert_eq!(x.variant, Bech32Variant::BIP0173);
                assert_eq!(x.hrp, hrp.to_string());
                assert_eq!(x.data, vec![0x00, 0x01, 0x02]);
            }
            Err(_) => {
                assert!(false);
            }
        }

        // testing BIP0350
        let bip0350_addr = "bech321qqqsyktsg0l".to_string();
        match Bech32Address::create_address(hrp, vec![0x00, 0x01, 0x02], Bech32Variant::BIP0350) {
            Ok(x) => {
                assert_eq!(x.addr, bip0350_addr);
                assert_eq!(x.variant, Bech32Variant::BIP0350);
            }
            Err(_) => {
                assert!(false);
            }
        }
    }

    #[test]
    fn invalid_decoding() {
        // testing invalid addresses
        fn invalid_decoding(s: &str) {
            assert!(Bech32Address::decode_to_address(s).is_err());
        }

        invalid_decoding(" 1nwldj5");
        invalid_decoding("abc1\u{2192}axkwrx");
        invalid_decoding("an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx");
        invalid_decoding("pzry9x0s0muk");
        invalid_decoding("1pzry9x0s0muk");
        invalid_decoding("x1b4n0q5v");
        invalid_decoding("li1dgmt3");
        invalid_decoding("de1lg7wt\u{ff}");
        invalid_decoding("A1G7SGD8");
        invalid_decoding("10a06t8");
        invalid_decoding("1qzzfhee");
    }

    #[test]
    fn valid_decoding() {
        // testing valid address
        fn valid_decoding(s: &str) {
            assert!(Bech32Address::decode_to_address(s).is_ok());
        }

        valid_decoding("A12UEL5L");
        valid_decoding("a12uel5l");
        valid_decoding("an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs");
        valid_decoding("abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw");
        valid_decoding("11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j");
        valid_decoding("split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w");
        valid_decoding("?1ezyfcl");
    }
}
