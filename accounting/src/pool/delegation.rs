use common::primitives::H256;
use crypto::key::PublicKey;

pub struct DelegationData {
    spend_key: PublicKey,
    source_pool: H256,
}

impl DelegationData {
    pub fn new(source_pool: H256, spend_key: PublicKey) -> Self {
        Self {
            spend_key,
            source_pool,
        }
    }

    pub fn spend_public_key(&self) -> &PublicKey {
        &self.spend_key
    }

    pub fn source_pool(&self) -> &H256 {
        &self.source_pool
    }
}
