use crypto::key::PublicKey;
use serialization::{Decode, Encode};

use crate::PoolId;

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct DelegationData {
    spend_key: PublicKey,
    source_pool: PoolId,
}

impl DelegationData {
    pub fn new(source_pool: PoolId, spend_key: PublicKey) -> Self {
        Self {
            spend_key,
            source_pool,
        }
    }

    pub fn spend_public_key(&self) -> &PublicKey {
        &self.spend_key
    }

    pub fn source_pool(&self) -> &PoolId {
        &self.source_pool
    }
}
