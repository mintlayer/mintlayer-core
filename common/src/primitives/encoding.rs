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
    pub fn get_hrp(&self) -> &str {
        &self.hrp
    }

    pub fn get_base32_data(&self) -> &[u8] {
        &self.base32_data
    }

    pub fn encode(self) -> Result<String, Bech32Error> {
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

            // ------- this checking is only for BITCOIN: Witness Programs
            // if hrp == "bc" && ( s.len() < 2 || s.len() > 40 ) {
            //     return Err(Bech32Error::InvalidLength);
            // }
            // ------- EOL

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
            // valid addresses
            "bc1p5rgvqejqh9dh37t9g94dd9cm8vtqns7dndgj423egwggsggcdzmsspvr7j",
            "bc1zr4pq63udck",
            "tb1ray6e8gxfx49ers6c4c70l3c8lsxtcmlx",
            "tb1pxqf7d825wjtcftj7uep8w24jq3tz8vudfaqj20rns8ahqya56gcs92eqtu",
            "tb1rsrzkyvu2rt0dcgexajtazlw5nft4j7494ay396q6auw9375wxsrsgag884",
            "bcrt1p3xat2ryucc2v0adrktqnavfzttvezrr27ngltsa2726p2ehvxz4se722v2",
            "bcrt1saflydw6e26xhp29euhy5jke5jjqyywk3wvtc9ulgw9dvxyuqy9hdnxthyw755c7ldavy7u",
            "bc1ps8cndas60cntk8x79sg9f5e5jz7x050z8agyugln2ukkks23rryqpejzkc",
            "bc1zn4tsczge9l",
            "bc10rmfwl8nxdweeyc4sf89t0tn9fv9w6qpyzsnl2r4k48vjqh03qas9asdje0rlr0phru0wqw0p", // should fail on bitcoin, because it's > 40 bytes
            "bc1qxmf2d6aerjzam3rur0zufqxqnyqfts5u302s7x", // should fail on bitcoin, version 0 for bech32m
            "bcrt1rhsveeudk", // should fail on bitcoin, Invalid hrp, "bc" or "tb" expected
            "tb13h83rtwq62udrhwpn87uely7cyxcjrj0azz6a4r3n9s87x5uj98ys6ufp83", // should fail on bitcoin, Invalid script version
            "tb130lvl2lyugsk2tf3zhwcjjv39dmwt2tt7ytqaexy8edwcuwks6p5scll5kz", // should fail on bitcoin, Invalid script version
            "tb13c553hwygcgj48qwmr9f8q0hgdcfklyaye5sxzcpcjnmxv4z506xs90tchn" // should fail on bitcoin, Invalid script version

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
            ("bech321qqqsyrhqy2a", Bech32Error::UnsupportedVariant),
            // invalid addresses
            ("bc1q5cuatynjmk4szh40mmunszfzh7zrc5xm9w8ccy", Bech32Error::UnsupportedVariant),
            ("bc1qkw7lz3ahms6e0ajv27mzh7g62tchjpmve4afc29u7w49tddydy2syv0087", Bech32Error::UnsupportedVariant),
            ("tb1q74fxwnvhsue0l8wremgq66xzvn48jlc5zthsvz", Bech32Error::UnsupportedVariant),
            ("tb1qpt7cqgq8ukv92dcraun9c3n0s3aswrt62vtv8nqmkfpa2tjfghesv9ln74", Bech32Error::UnsupportedVariant),
            ("tb1q0sqzfp3zj42u0perxr6jahhu4y03uw4dypk6sc", Bech32Error::UnsupportedVariant),
            ("tb1q9jv4qnawnuevqaeadn47gkq05ev78m4qg3zqejykdr9u0cm7yutq6gu5dj", Bech32Error::UnsupportedVariant),
            ("bc1qz377zwe5awr68dnggengqx9vrjt05k98q3sw2n", Bech32Error::UnsupportedVariant),
            ("tb1qgk665m2auw09rc7pqyf7aulcuhmatz9xqtr5mxew7zuysacaascqs9v0vn", Bech32Error::FailedChecksum)
        ).iter().for_each(|(s,b_err)| {
            match decode(*s) {
                Ok(_) => { panic!("Should be invalid: {:?}", s) }
                Err(e) => { assert_eq!(*b_err,e) }
            }
        });
    }
}
