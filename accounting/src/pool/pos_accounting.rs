use std::collections::BTreeMap;
use std::ops::Bound::Included;

use common::{
    chain::OutPoint,
    primitives::{
        id::{hash_encoded_to, DefaultHashAlgoStream},
        Amount, H256,
    },
};
use crypto::{hash::StreamHasher, key::PublicKey};

use crate::error::Error;

use super::delegation::DelegationData;

pub struct PoSAccounting {
    pool_addresses_balances: BTreeMap<H256, Amount>,
    delegation_to_pool_shares: BTreeMap<(H256, H256), Amount>,
    delegation_addresses_balances: BTreeMap<H256, Amount>,
    delegation_addresses_data: BTreeMap<H256, DelegationData>,
}

impl PoSAccounting {
    pub fn new_empty() -> Self {
        Self {
            pool_addresses_balances: Default::default(),
            delegation_to_pool_shares: Default::default(),
            delegation_addresses_balances: Default::default(),
            delegation_addresses_data: Default::default(),
        }
    }

    fn pool_address_preimage_suffix() -> u32 {
        // arbitrary, we use this to create different values when hashing with no security requirements
        0
    }

    fn delegation_address_preimage_suffix() -> u32 {
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

    pub fn make_delegation_address(input0_outpoint: &OutPoint) -> H256 {
        let mut pool_address_creator = DefaultHashAlgoStream::new();
        hash_encoded_to(&input0_outpoint, &mut pool_address_creator);
        // 1 is arbitrary here, we use this as prefix to use this information again
        hash_encoded_to(
            &Self::delegation_address_preimage_suffix(),
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
        let delegation_address = Self::make_delegation_address(input0_outpoint);

        if !self.pool_exists(target_pool) {
            return Err(Error::DelegationCreationFailedPoolDoesNotExist);
        }

        match self.delegation_addresses_data.entry(delegation_address) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(DelegationData::new(target_pool, spend_key))
            }
            std::collections::btree_map::Entry::Occupied(_entry) => {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorPoolAlreadyExists);
            }
        };

        Ok(delegation_address)
    }

    fn add_to_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        let current_amount = self
            .delegation_addresses_balances
            .get_mut(&delegation_target)
            .ok_or(Error::DelegateToNonexistingAddress)?;
        *current_amount =
            (*current_amount + amount_to_delegate).ok_or(Error::DelegationBalanceAdditionError)?;
        Ok(())
    }

    fn get_delegation_data(&mut self, delegation_target: H256) -> Result<&DelegationData, Error> {
        let delegation_target = self
            .delegation_addresses_data
            .get_mut(&delegation_target)
            .ok_or(Error::DelegateToNonexistingAddress)?;
        Ok(delegation_target)
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

    fn add_delegation_to_pool_share(
        &mut self,
        pool_id: H256,
        delegation_address: H256,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        let current_amount = self
            .delegation_to_pool_shares
            .entry((pool_id, delegation_address))
            .or_insert(Amount::from_atoms(0));
        let new_amount =
            (*current_amount + amount_to_add).ok_or(Error::PoolBalanceAdditionError)?;
        *current_amount = new_amount;
        Ok(())
    }

    pub fn delegate_staking(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        let delegation_data = self.get_delegation_data(delegation_target)?;

        let pool_id = *delegation_data.source_pool();

        self.add_to_delegation_balance(delegation_target, amount_to_delegate)?;

        self.add_balance_to_pool(pool_id, amount_to_delegate)?;

        self.add_delegation_to_pool_share(pool_id, delegation_target, amount_to_delegate)?;

        Ok(())
    }

    // TODO: test that all values within the pool will be returned, especially boundary values
    pub fn get_delegation_shares(&self, pool_id: H256) -> Option<BTreeMap<H256, Amount>> {
        let iter = self
            .delegation_to_pool_shares
            .range((pool_id, H256::zero())..=(pool_id, H256::repeat_byte(0xFF)));
        let result = iter.map(|(k, v)| (k.1, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            return None;
        } else {
            return Some(result);
        }
    }
}
