use super::Bech32Error;
use super::DecodedBase32FromBech32;
use bech32::CheckBase32;
use bech32::{self, Variant};

pub fn encode<T: AsRef<[u8]>>(hrp: &str, data: T) -> Result<String, Bech32Error> {
    let data = data.check_base32()?;
    // let data = super::base32::encode(data.as_ref())?;
    bech32::encode(hrp, data, Variant::Bech32m).map_err(|e| e.into())
}

pub fn decode(s: &str) -> Result<DecodedBase32FromBech32, Bech32Error> {
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

            let data = base32.iter().map(|x| x.to_u8()).collect();
            // let data = super::base32::decode(base32)?;
            Ok(DecodedBase32FromBech32 { hrp, data })
        }
        Err(e) => Err(e.into()),
    }
}
