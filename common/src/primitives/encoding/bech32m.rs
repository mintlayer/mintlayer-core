use super::Bech32Error;
use super::DecodedBech32;
use bech32::{self, convert_bits, Variant};

pub fn encode<T: AsRef<[u8]>>(hrp: &str, data: T) -> Result<String, Bech32Error> {
    let data = super::base32::encode(data.as_ref())?;
    bech32::encode(hrp, data, Variant::Bech32m).map_err(|e| e.into())
}

pub fn decode(s: &str) -> Result<DecodedBech32, Bech32Error> {
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

            let data = convert_bits(&base32, 5, 8, false)?;

            Ok(DecodedBech32 { hrp, data, base32 })
        }
        Err(e) => Err(e.into()),
    }
}
