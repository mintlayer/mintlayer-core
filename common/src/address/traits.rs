use crate::chain::ChainConfig;

pub trait Addressable {
    type Error: std::error::Error;

    #[must_use]
    fn address_prefix(&self, chain_config: &ChainConfig) -> &str;

    #[must_use]
    fn encode_to_bytes_for_address(&self) -> Vec<u8>;

    #[must_use]
    fn decode_from_bytes_from_address<T: AsRef<[u8]>>(
        address_bytes: T,
    ) -> Result<Self, Self::Error>
    where
        Self: Sized;
}
