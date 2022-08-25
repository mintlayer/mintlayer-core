use crypto::key::PublicKey;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct PoolData {
    decommission_public_key: PublicKey,
}

impl PoolData {
    pub fn new(decommission_public_key: PublicKey) -> Self {
        Self {
            decommission_public_key,
        }
    }

    pub fn decommission_key(&self) -> &PublicKey {
        &self.decommission_public_key
    }
}
