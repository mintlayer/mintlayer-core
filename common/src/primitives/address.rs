use crate::primitives::{decode, encode, Bech32Error};

pub trait AddressExtNoData {
    fn encode_to_address<T: AsRef<[u8]>>(&self, data: T) -> Result<String, Bech32Error> {
        encode(self.hrp(), data)
    }

    fn hrp(&self) -> &str;
}

pub trait AddressExt<T: AsRef<[u8]>> {
    fn encode_to_address(&self) -> Result<String, Bech32Error> {
        encode(self.hrp(), self.data())
    }

    fn hrp(&self) -> &str;
    fn data(&self) -> T;
}
