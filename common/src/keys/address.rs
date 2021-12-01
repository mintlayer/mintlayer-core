use crate::primitives::{encoding, Bech32Error};

pub trait AddressExt<T: AsRef<[u8]>> {
    fn encode(&self) -> Result<String, Bech32Error> {
        encoding::encode(self.hrp(), self.data())
    }

    fn hrp(&self) -> &str;
    fn data(&self) -> T;
}
