use bech32::{self, CheckBase32, Variant};
use core::fmt;
use displaydoc::Display;
use thiserror::Error;

#[derive(Default, Debug, Clone, PartialEq)]
pub struct DecodedBech32 {
    pub hrp: String,
    pub data: Vec<u8>,
}

#[derive(Error, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
pub enum Bech32Error {
    /// only variant Bech32M is supported
    UnsupportedBech32,
    /// wraps any Bech32 Error
    Invalid(#[from] bech32::Error),
    /// list of indices containing invalid characters in a bech32 string
    ErrorLocation(Vec<usize>),
    /// wraps the rust error
    StdError(#[from] fmt::Error),
}

pub fn encode<T: AsRef<[u8]>>(hrp: &str, data: T) -> Result<String, Bech32Error> {
    let data = data.check_base32()?;
    bech32::encode(hrp, data, Variant::Bech32m).map_err(|e| e.into())
}

pub fn decode(s: &str) -> Result<DecodedBech32, Bech32Error> {
    match bech32::decode(s) {
        Ok((hrp, data, variant)) => {
            if variant == Variant::Bech32 {
                return Err(Bech32Error::UnsupportedBech32);
            }
            let data = data.into_iter().map(|x| x.to_u8()).collect();

            Ok(DecodedBech32 { hrp, data })
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::Error as bErr;

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
               Ok(DecodedBech32{ hrp, data }) => {
                   match encode(&hrp,data){
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
            (" 1xj0phk", Bech32Error::Invalid(bErr::InvalidChar(' '))),
            ("\u{7F}1g6xzxy", Bech32Error::Invalid(bErr::InvalidChar('\u{7f}'))),
            ("\u{80}1vctc34", Bech32Error::Invalid(bErr::InvalidChar('Â'))),
            ("an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", Bech32Error::Invalid(bErr::InvalidLength)),
            ("qyrz8wqd2c9m", Bech32Error::Invalid(bErr::MissingSeparator)),
            ("1qyrz8wqd2c9m", Bech32Error::Invalid(bErr::InvalidLength)),
            ("y1b0jsk6g", Bech32Error::Invalid(bErr::InvalidChar('b'))),
            ("lt1igcx5c0", Bech32Error::Invalid(bErr::InvalidChar('i'))),
            ("in1muywd", Bech32Error::Invalid(bErr::InvalidLength)),
            ("mm1crxm3i", Bech32Error::Invalid(bErr::InvalidChar('i'))),
            ("au1s5cgom", Bech32Error::Invalid(bErr::InvalidChar('o'))),
            ("M1VUXWEZ", Bech32Error::Invalid(bErr::InvalidChecksum)),
            ("16plkw9", Bech32Error::Invalid(bErr::InvalidLength)),
            ("1p2gdwpf", Bech32Error::Invalid(bErr::InvalidLength)),
            ("bech321qqqsyrhqy2a", Bech32Error::UnsupportedBech32)
        ).iter().for_each(|(s,b_err)| {
            match decode(*s) {
                Ok(_) => { panic!("Should be invalid: {:?}", s) }
                Err(e) => { assert_eq!(*b_err,e) }
            }
        });
    }
}
