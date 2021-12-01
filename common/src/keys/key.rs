use crate::chain::ChainConfig;
use crate::keys::AddressExt;
use crypto::hash::Hasher;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Public { //TODO: define a proper one
    prefix: String,
}

impl Public {
    fn new(cfg: &ChainConfig) -> Self {
        Self {
            prefix: cfg.address_prefix(),
        }
    }
}

impl<T: AsRef<[u8]>> AddressExt<T> for Public {
    fn hrp(&self) -> &str {
        &self.prefix
    }

    fn data(&self) -> T {
        todo!()
    }
}
