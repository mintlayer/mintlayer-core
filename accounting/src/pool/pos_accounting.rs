use std::collections::BTreeMap;

use common::{
    chain::OutPoint,
    primitives::{Amount, H256},
};
use crypto::key::PublicKey;

use crate::error::Error;

use super::{
    delegation::DelegationData,
    helpers::{make_delegation_address, make_pool_address},
};

pub enum PoSAccountingUndo {
    CreatePool {
        input0_outpoint: OutPoint,
        pledge_amount: Amount,
    },
    DecommissionPool {
        pool_address: H256,
        last_amount: Amount,
    },
    CreateDelegationAddress {
        delegation_data: DelegationData,
        input0_outpoint: OutPoint,
    },
    AddDelegationBalance {
        pool_id: H256,
        delegation_address: H256,
        amount_to_add: Amount,
    },
    DelegateStaking {
        delegation_target: H256,
        amount_to_delegate: Amount,
    },
}

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

    pub fn create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pledge_amount: Amount,
    ) -> Result<PoSAccountingUndo, Error> {
        let pool_address = make_pool_address(input0_outpoint);

        match self.pool_addresses_balances.entry(pool_address) {
            std::collections::btree_map::Entry::Vacant(entry) => entry.insert(pledge_amount),
            std::collections::btree_map::Entry::Occupied(_entry) => {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorPoolAlreadyExists);
            }
        };

        Ok(PoSAccountingUndo::CreatePool {
            input0_outpoint: input0_outpoint.clone(),
            pledge_amount,
        })
    }

    pub fn undo_create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pledge_amount: Amount,
    ) -> Result<(), Error> {
        let pool_address = make_pool_address(input0_outpoint);

        let amount = self.pool_addresses_balances.remove(&pool_address);

        match amount {
            Some(amount) => {
                if amount != pledge_amount {
                    return Err(Error::InvariantErrorPoolCreationReversalFailedAmountChanged);
                }
            }
            None => return Err(Error::InvariantErrorPoolCreationReversalFailedNotFound),
        }

        Ok(())
    }

    pub fn decommission_pool(&mut self, pool_address: H256) -> Result<PoSAccountingUndo, Error> {
        let last_amount = self
            .pool_addresses_balances
            .remove(&pool_address)
            .ok_or(Error::AttemptedDecommissionNonexistingPool)?;

        Ok(PoSAccountingUndo::DecommissionPool {
            pool_address,
            last_amount,
        })
    }

    pub fn undo_decommission_pool(
        &mut self,
        pool_address: H256,
        last_amount: Amount,
    ) -> Result<(), Error> {
        match self.pool_addresses_balances.entry(pool_address) {
            std::collections::btree_map::Entry::Vacant(entry) => entry.insert(last_amount),
            std::collections::btree_map::Entry::Occupied(_entry) => {
                return Err(Error::InvariantErrorDecommissionUndoFailedAlreadyExists);
            }
        };
        Ok(())
    }

    pub fn pool_exists(&self, pool_id: H256) -> bool {
        self.pool_addresses_balances.contains_key(&pool_id)
    }

    pub fn create_delegation_address(
        &mut self,
        target_pool: H256,
        spend_key: PublicKey,
        input0_outpoint: &OutPoint,
    ) -> Result<(H256, PoSAccountingUndo), Error> {
        let delegation_address = make_delegation_address(input0_outpoint);

        if !self.pool_exists(target_pool) {
            return Err(Error::DelegationCreationFailedPoolDoesNotExist);
        }

        let delegation_data = match self.delegation_addresses_data.entry(delegation_address) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                let delegation_data = DelegationData::new(target_pool, spend_key);
                entry.insert(delegation_data.clone());
                delegation_data
            }
            std::collections::btree_map::Entry::Occupied(_entry) => {
                // This should never happen since it's based on an unspent input
                return Err(Error::InvariantErrorPoolAlreadyExists);
            }
        };

        Ok((
            delegation_address,
            PoSAccountingUndo::CreateDelegationAddress {
                delegation_data,
                input0_outpoint: input0_outpoint.clone(),
            },
        ))
    }

    pub fn undo_create_delegation_address(
        &mut self,
        delegation_data: DelegationData,
        input0_outpoint: &OutPoint,
    ) -> Result<(), Error> {
        let delegation_address = make_delegation_address(input0_outpoint);

        let removed_data = self.delegation_addresses_data.remove(&delegation_address);

        let removed_data = match removed_data {
            Some(d) => d,
            None => return Err(Error::InvariantErrorDelegationAddressUndoFailedNotFound),
        };

        if removed_data != delegation_data {
            return Err(Error::InvariantErrorDelegationAddressUndoFailedDataConflict);
        }

        Ok(())
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

    fn undo_add_to_delegation_balance(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        let current_amount = self
            .delegation_addresses_balances
            .get_mut(&delegation_target)
            .ok_or(Error::DelegateToNonexistingAddress)?;
        *current_amount = (*current_amount - amount_to_delegate)
            .ok_or(Error::InvariantErrorDelegationBalanceAdditionUndoError)?;
        Ok(())
    }

    fn get_delegation_data(&self, delegation_target: H256) -> Result<&DelegationData, Error> {
        let delegation_target = self
            .delegation_addresses_data
            .get(&delegation_target)
            .ok_or(Error::DelegateToNonexistingAddress)?;
        Ok(delegation_target)
    }

    fn add_balance_to_pool(&mut self, pool_id: H256, amount_to_add: Amount) -> Result<(), Error> {
        let pool_amount = self
            .pool_addresses_balances
            .get_mut(&pool_id)
            .ok_or(Error::DelegateToNonexistingPool)?;
        *pool_amount = (*pool_amount + amount_to_add).ok_or(Error::PoolBalanceAdditionError)?;
        Ok(())
    }

    fn undo_add_balance_to_pool(
        &mut self,
        pool_id: H256,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        let pool_amount = self
            .pool_addresses_balances
            .get_mut(&pool_id)
            .ok_or(Error::DelegateToNonexistingPool)?;
        *pool_amount = (*pool_amount - amount_to_add)
            .ok_or(Error::InvariantErrorPoolBalanceAdditionUndoError)?;
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
        *current_amount =
            (*current_amount + amount_to_add).ok_or(Error::DelegationSharesAdditionError)?;
        Ok(())
    }

    fn undo_add_delegation_to_pool_share(
        &mut self,
        pool_id: H256,
        delegation_address: H256,
        amount_to_add: Amount,
    ) -> Result<(), Error> {
        let current_amount = self
            .delegation_to_pool_shares
            .entry((pool_id, delegation_address))
            .or_insert(Amount::from_atoms(0));
        *current_amount = (*current_amount - amount_to_add)
            .ok_or(Error::InvariantErrorDelegationSharesAdditionUndoError)?;
        Ok(())
    }

    pub fn delegate_staking(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<PoSAccountingUndo, Error> {
        let pool_id = *self.get_delegation_data(delegation_target)?.source_pool();

        self.add_to_delegation_balance(delegation_target, amount_to_delegate)?;

        self.add_balance_to_pool(pool_id, amount_to_delegate)?;

        self.add_delegation_to_pool_share(pool_id, delegation_target, amount_to_delegate)?;

        Ok(PoSAccountingUndo::DelegateStaking {
            delegation_target,
            amount_to_delegate,
        })
    }

    pub fn undo_delegate_staking(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<(), Error> {
        let pool_id = *self.get_delegation_data(delegation_target)?.source_pool();

        self.undo_add_delegation_to_pool_share(pool_id, delegation_target, amount_to_delegate)?;

        self.undo_add_balance_to_pool(pool_id, amount_to_delegate)?;

        self.undo_add_to_delegation_balance(delegation_target, amount_to_delegate)?;

        Ok(())
    }

    // TODO: test that all values within the pool will be returned, especially boundary values, and off boundary aren't returned
    pub fn get_delegation_shares(&self, pool_id: H256) -> Option<BTreeMap<H256, Amount>> {
        let range_start = (pool_id, H256::zero());
        let range_end = (pool_id, H256::repeat_byte(0xFF));
        let range = self.delegation_to_pool_shares.range(range_start..=range_end);
        let result = range.map(|((_pool_id, del_id), v)| (*del_id, *v)).collect::<BTreeMap<_, _>>();
        if result.is_empty() {
            None
        } else {
            Some(result)
        }
    }

    pub fn get_delegation_share(&self, pool_id: H256, delegation_address: H256) -> Option<Amount> {
        self.delegation_to_pool_shares.get(&(pool_id, delegation_address)).copied()
    }

    pub fn get_pool_balance(&self, pool_id: H256) -> Option<Amount> {
        self.pool_addresses_balances.get(&pool_id).copied()
    }

    pub fn get_delegation_address_balance(&self, delegation_address: H256) -> Option<Amount> {
        self.delegation_addresses_balances.get(&delegation_address).copied()
    }

    pub fn get_delegation_address_data(&self, delegation_address: H256) -> Option<DelegationData> {
        self.delegation_addresses_data.get(&delegation_address).cloned()
    }
}
