use common::primitives::Amount;
use crypto::key::PublicKey;
use serialization::{Decode, Encode};

#[derive(Debug, Eq, PartialEq, Clone, Encode, Decode)]
pub struct PoolData {
    decommission_public_key: PublicKey,
    pledge_amount: Amount,
}

impl PoolData {
    pub fn new(decommission_public_key: PublicKey, pledge_amount: Amount) -> Self {
        Self {
            decommission_public_key,
            pledge_amount,
        }
    }

    pub fn decommission_key(&self) -> &PublicKey {
        &self.decommission_public_key
    }

    pub fn pledge_amount(&self) -> Amount {
        self.pledge_amount
    }
}
