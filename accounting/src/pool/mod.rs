use std::collections::BTreeMap;

use common::{
    chain::OutPoint,
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        Amount, H256,
    },
};
use crypto::{hash::StreamHasher, key::PublicKey};

use crate::error::Error;

pub mod reward;
use self::reward::RewardAddress;

pub struct PoSAccounting {
    pool_addresses_balances: BTreeMap<H256, Amount>,
    reward_addresses_balances: BTreeMap<H256, reward::RewardAddress>,
}

impl PoSAccounting {
    pub fn new_empty() -> Self {
        Self {
            pool_addresses_balances: Default::default(),
            reward_addresses_balances: Default::default(),
        }
    }

    fn pool_address_preimage_suffix() -> u32 {
        // arbitrary, we use this to create different values when hashing with no security requirements
        0
    }

    fn reward_address_preimage_suffix() -> u32 {
        // arbitrary, we use this to create different values when hashing with no security requirements
        1
    }

    pub fn make_pool_address(input0_outpoint: &OutPoint) -> H256 {
        let mut pool_address_creator = DefaultHashAlgoStream::new();
        hash_encoded_to(&input0_outpoint, &mut pool_address_creator);
        // 0 is arbitrary here, we use this as prefix to use this information again
        hash_encoded_to(
            &Self::pool_address_preimage_suffix(),
            &mut pool_address_creator,
        );
        pool_address_creator.finalize().into()
    }

    pub fn make_reward_address(input0_outpoint: &OutPoint) -> H256 {
        let mut pool_address_creator = DefaultHashAlgoStream::new();
        hash_encoded_to(&input0_outpoint, &mut pool_address_creator);
        // 1 is arbitrary here, we use this as prefix to use this information again
        hash_encoded_to(
            &Self::reward_address_preimage_suffix(),
            &mut pool_address_creator,
        );
        pool_address_creator.finalize().into()
    }

    pub fn create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pledge_amount: Amount,
    ) -> Result<(), Error> {
        let pool_address = Self::make_pool_address(input0_outpoint);

        match self.pool_addresses_balances.entry(pool_address) {
            std::collections::btree_map::Entry::Vacant(entry) => entry.insert(pledge_amount),
            std::collections::btree_map::Entry::Occupied(_entry) => {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorPoolAlreadyExists);
            }
        };

        Ok(())
    }

    pub fn decomission_pool(&mut self, pool_address: H256) -> Result<Amount, Error> {
        self.pool_addresses_balances
            .remove(&pool_address)
            .ok_or(Error::AttemptedDecommissionNonexistingPool)
    }

    pub fn pool_exists(&self, pool_id: H256) -> bool {
        self.pool_addresses_balances.contains_key(&pool_id)
    }

    pub fn create_delegation_address(
        &mut self,
        target_pool: H256,
        spend_key: PublicKey,
        input0_outpoint: &OutPoint,
    ) -> Result<H256, Error> {
        let reward_address = Self::make_reward_address(input0_outpoint);

        if !self.pool_exists(target_pool) {
            return Err(Error::DelegationCreationFailedPoolDoesNotExist);
        }

        match self.reward_addresses_balances.entry(reward_address) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(RewardAddress::new(target_pool, spend_key))
            }
            std::collections::btree_map::Entry::Occupied(_entry) => {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorPoolAlreadyExists);
            }
        };

        Ok(reward_address)
    }

    fn add_to_reward_balance_and_get(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<&RewardAddress, Error> {
        let reward_target = self
            .reward_addresses_balances
            .get_mut(&delegation_target)
            .ok_or(Error::DelegateToNonexistingRewardAddress)?;
        reward_target.add_amount(amount_to_delegate)?;
        Ok(reward_target)
    }

    fn add_balance_to_pool(&mut self, pool_id: H256, amount_to_add: Amount) -> Result<(), Error> {
        let pool_amount = self
            .pool_addresses_balances
            .get_mut(&pool_id)
            .ok_or(Error::DelegateToNonexistingPool)?;
        let new_pool_amount =
            (*pool_amount + amount_to_add).ok_or(Error::PoolBalanceAdditionError)?;
        *pool_amount = new_pool_amount;
        Ok(())
    }

    pub fn delegate_staking(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        let reward_target =
            self.add_to_reward_balance_and_get(delegation_target, amount_to_delegate)?;

        let pool_id = *reward_target.source_pool();

        self.add_balance_to_pool(pool_id, amount_to_delegate)?;

        Ok(())
    }
}
