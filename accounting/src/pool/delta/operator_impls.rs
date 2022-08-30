use std::collections::BTreeMap;

use common::primitives::{Amount, H256};

use crate::{
    error::Error,
    pool::{delegation::DelegationData, operations::PoSAccountingOperatorRead},
};

use super::{combine::combine_amount_delta, sum_maps, PoSAccountingDelta};

impl<'a> PoSAccountingOperatorRead for PoSAccountingDelta<'a> {
    fn pool_exists(&self, pool_id: H256) -> Result<bool, Error> {
        Ok(self.parent.get_pool_data(pool_id)?.is_some())
    }

    fn get_delegation_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        let parent_shares = self.parent.get_pool_delegations_shares(pool_id)?.unwrap_or_default();
        let local_shares = self.get_cached_delegations_shares(pool_id).unwrap_or_default();
        if parent_shares.is_empty() && local_shares.is_empty() {
            Ok(None)
        } else {
            Ok(Some(sum_maps(parent_shares, local_shares)?))
        }
    }

    fn get_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error> {
        let parent_share = self.parent.get_pool_delegation_share(pool_id, delegation_id)?;
        let local_share = self.pool_delegation_shares.get(&(pool_id, delegation_id));
        combine_amount_delta(&parent_share, &local_share.copied())
    }

    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        let parent_amount = self.parent.get_pool_balance(pool_id)?;
        let local_amount = self.pool_balances.get(&pool_id);
        combine_amount_delta(&parent_amount, &local_amount.copied())
    }

    fn get_delegation_id_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error> {
        let parent_amount = self.parent.get_delegation_balance(delegation_id)?;
        let local_amount = self.delegation_balances.get(&delegation_id);
        combine_amount_delta(&parent_amount, &local_amount.copied())
    }

    fn get_delegation_id_data(&self, delegation_id: H256) -> Result<Option<DelegationData>, Error> {
        let parent_data = self.parent.get_delegation_data(delegation_id)?;
        let local_data = self.delegation_data.get(&delegation_id);
        match (parent_data, local_data) {
            (None, None) => Ok(None),
            (None, Some(d)) => match d {
                super::DelegationDataDelta::Add(d) => Ok(Some(*d.clone())),
                super::DelegationDataDelta::Remove => Ok(None),
            },
            (Some(p), None) => Ok(Some(p)),
            (Some(_), Some(d)) => match d {
                super::DelegationDataDelta::Add(_) => {
                    Err(Error::DelegationDataCreatedMultipleTimes)
                }
                super::DelegationDataDelta::Remove => Ok(None),
            },
        }
    }
}
