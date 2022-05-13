use super::Bech32Error;
use super::DecodedArbitraryDataFromBech32;
use super::DecodedBase32FromBech32;
use bech32::u5;
use bech32::{self, Variant};

pub fn base32_to_bech32m<T: AsRef<[u5]>>(hrp: &str, data: T) -> Result<String, Bech32Error> {
    bech32::encode(hrp, data, Variant::Bech32m).map_err(|e| e.into())
}

#[allow(dead_code)]
pub fn bech32m_to_base32(s: &str) -> Result<DecodedBase32FromBech32, Bech32Error> {
    match bech32::decode(s) {
        Ok((hrp, base32, variant)) => {
            if variant == Variant::Bech32 {
                return Err(Bech32Error::UnsupportedVariant);
            }

            // ------- this checking is only for BITCOIN: Witness Programs
            // if hrp == "bc" && ( s.len() < 2 || s.len() > 40 ) {
            //     return Err(Bech32Error::InvalidLength);
            // }
            // ------- EOL

            Ok(DecodedBase32FromBech32::new(hrp, base32))
        }
        Err(e) => Err(e.into()),
    }
}

pub fn arbitrary_data_to_bech32m<T: AsRef<[u8]>>(
    hrp: &str,
    data: T,
) -> Result<String, Bech32Error> {
    let data = super::base32::encode(data.as_ref())?;
    bech32::encode(hrp, data, Variant::Bech32m).map_err(|e| e.into())
}

pub fn bech32m_to_arbitrary_data(s: &str) -> Result<DecodedArbitraryDataFromBech32, Bech32Error> {
    match bech32::decode(s) {
        Ok((hrp, base32, variant)) => {
            if variant == Variant::Bech32 {
                return Err(Bech32Error::UnsupportedVariant);
            }

            let data = super::base32::decode(base32)?;
            Ok(DecodedArbitraryDataFromBech32::new(hrp, data))
        }
        Err(e) => Err(e.into()),
    }
}
