use crate::primitives::{Error, encode,decode, DecodedBech32};

pub trait AddressExt {
    fn encode_to_address(&self) -> Result<String, Error> {
        encode(
            self.get_hrp(),
                self.get_data()
        )
    }

    /// get hrp from the provided Bech32 Address
    fn get_hrp(s:&str) -> Result<String,Error> {
        decode(s).map(|d| d.hrp)
    }

    fn hrp(&self) -> &str;
    fn data<T: AsRef<[u8]>>(&self) -> T;
}