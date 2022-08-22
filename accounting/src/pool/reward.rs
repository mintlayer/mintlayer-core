use common::primitives::{Amount, H256};
use crypto::key::PublicKey;

use crate::error::Error;

pub struct RewardAddress {
    amount: Amount,
    spend_key: PublicKey,
    source_pool: H256,
}

impl RewardAddress {
    pub fn new(source_pool: H256, spend_key: PublicKey) -> Self {
        Self {
            amount: Amount::from_atoms(0),
            spend_key,
            source_pool,
        }
    }

    pub fn amount(&self) -> Amount {
        self.amount
    }

    pub fn spend_public_key(&self) -> &PublicKey {
        &self.spend_key
    }

    pub fn source_pool(&self) -> &H256 {
        &self.source_pool
    }

    pub fn add_amount(&mut self, amount: Amount) -> Result<(), Error> {
        let new_amount = (self.amount + amount).ok_or(Error::DelegationBalanceAdditionError)?;
        self.amount = new_amount;
        Ok(())
    }
}
