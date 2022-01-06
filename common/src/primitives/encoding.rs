use bech32::{self, CheckBase32, Error, ToBase32, Variant};
use core::fmt;
use displaydoc::Display;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedBech32 {
    hrp: String,
    base32_data: Vec<u8>,
}

impl DecodedBech32 {
    fn get_hrp(&self) -> &str {
        &self.hrp
    }

    fn get_base32_data(&self) -> &[u8] {
        &self.base32_data
    }

    fn encode(self) -> Result<String, Bech32Error> {
        let data = &self.base32_data.check_base32()?;
        bech32::encode(&self.hrp, data, Variant::Bech32m).map_err(|e| e.into())
    }
}

#[derive(Error, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
pub enum Bech32Error {
    /// missing separator
    NoSeparator,
    /// Invalid checksum
    FailedChecksum,
    /// Length either too short or too long
    InvalidLength,
    /// char value not supported
    InvalidChar(char),
    /// the provided u8 value in the data is invalid
    InvalidData(u8),
    /// Padding issue
    InvalidPadding,
    /// a mix of lowercase and uppercase is not allowed
    MixCase,
    /// only variant Bech32M is supported
    UnsupportedVariant,
    /// list of indices containing invalid characters in a bech32 string
    ErrorLocation(Vec<usize>),
    /// wraps the rust error
    StdError(#[from] fmt::Error),
}

impl From<bech32::Error> for Bech32Error {
    fn from(e: Error) -> Self {
        match e {
            Error::MissingSeparator => Self::NoSeparator,
            Error::InvalidChecksum => Self::FailedChecksum,
            Error::InvalidLength => Self::InvalidLength,
            Error::InvalidChar(x) => Self::InvalidChar(x),
            Error::InvalidData(x) => Self::InvalidData(x),
            Error::InvalidPadding => Self::InvalidPadding,
            Error::MixedCase => Self::MixCase,
        }
    }
}

pub fn encode<T: AsRef<[u8]>>(hrp: &str, data: T) -> Result<String, Bech32Error> {
    let data = data.to_base32();
    bech32::encode(hrp, data, Variant::Bech32m).map_err(|e| e.into())
}

pub fn decode(s: &str) -> Result<DecodedBech32, Bech32Error> {
    match bech32::decode(s) {
        Ok((hrp, data, variant)) => {
            if variant == Variant::Bech32 {
                return Err(Bech32Error::UnsupportedVariant);
            }
            let data = data.into_iter().map(|x| x.to_u8()).collect();

            Ok(DecodedBech32 {
                hrp,
                base32_data: data,
            })
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_encode() {
        let data = vec![0x00, 0x01, 0x02];
        let hrp = "bech32";

        let encoded = encode(hrp, data.clone()).expect("it should not fail");
        assert_eq!(encoded, "bech321qqqsyktsg0l".to_string());

        let decoded = decode(&encoded).expect("should decode okay");
        println!("value of decoded: {:?}", decoded);

        let base32_data: Vec<u8> = data.to_base32().into_iter().map(|x| x.to_u8()).collect();
        assert_eq!(base32_data, decoded.get_base32_data());
        assert_eq!(hrp, decoded.get_hrp());

        assert_ne!(data, decoded.get_base32_data());
    }

    #[test]
    fn check_valid_strings() {
        vec!(
            "A1LQFN3A",
            "a1lqfn3a",
            "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
            "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
            "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
            "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
            "?1v759aa",
        ).iter().for_each(|s| {
           match decode(*s) {
               Ok(decoded) => {
                   match decoded.encode() {
                       Ok(encoded) => { assert_eq!(s.to_lowercase(), encoded.to_lowercase()) }
                       Err(e) => { panic!("Did not encode: {:?} Reason: {:?}",s,e) }
                   }
               }
               Err(e) => {
                   panic!("Did not decode: {:?} Reason: {:?}", s, e)
               }
           }
        })
    }

    #[test]
    fn check_invalid_strings() {
        vec!(
            (" 1xj0phk", Bech32Error::InvalidChar(' ')),
            ("\u{7F}1g6xzxy", Bech32Error::InvalidChar('\u{7f}')),
            ("\u{80}1vctc34", Bech32Error::InvalidChar('Â')),
            ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", Bech32Error::InvalidLength),
            ("qyrz8wqd2c9m", Bech32Error::NoSeparator),
            ("1qyrz8wqd2c9m", Bech32Error::InvalidLength),
            ("y1b0jsk6g", Bech32Error::InvalidChar('b')),
            ("lt1igcx5c0", Bech32Error::InvalidChar('i')),
            ("in1muywd", Bech32Error::InvalidLength),
            ("mm1crxm3i", Bech32Error::InvalidChar('i')),
            ("au1s5cgom", Bech32Error::InvalidChar('o')),
            ("M1VUXWEZ", Bech32Error::FailedChecksum),
            ("16plkw9", Bech32Error::InvalidLength),
            ("1p2gdwpf", Bech32Error::InvalidLength),
            ("bech321qqqsyrhqy2a", Bech32Error::UnsupportedVariant)
        ).iter().for_each(|(s,b_err)| {
            match decode(*s) {
                Ok(_) => { panic!("Should be invalid: {:?}", s) }
                Err(e) => { assert_eq!(*b_err,e) }
            }
        });
    }
}
