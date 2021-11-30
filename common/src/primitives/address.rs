use crate::primitives::{Error, encode, decode};

pub trait AddressExt<T: AsRef<[u8]>> {
    fn encode_to_address(&self) -> Result<String, Error> {
        encode(self.hrp(), self.data())
    }

    /// get hrp from the provided Bech32 Address
    fn get_hrp(bech32_address:&str) -> Result<String,Error> {
        decode(bech32_address).map(|d| d.hrp)
    }

    fn hrp(&self) -> &str;
    fn data(&self) -> T;
}