use std::collections::BTreeMap;

use common::primitives::{signed_amount::SignedAmount, Amount, H256};

use crate::{
    error::Error,
    pool::{delegation::DelegationData, pool_data::PoolData, view::PoSAccountingView},
};

use super::{
    combine::combine_amount_delta, DelegationDataDelta, PoSAccountingDelta, PoolDataDelta,
};

fn signed_to_unsigned_pair((k, v): (H256, SignedAmount)) -> Result<(H256, Amount), Error> {
    let v = v.into_unsigned().ok_or(Error::ArithmeticErrorToUnsignedFailed)?;
    Ok((k, v))
}

fn sum_maps(
    mut m1: BTreeMap<H256, Amount>,
    m2: BTreeMap<H256, SignedAmount>,
) -> Result<BTreeMap<H256, Amount>, Error> {
    for (k, v) in m2 {
        let base_value = match m1.get(&k) {
            Some(pv) => *pv,
            None => Amount::from_atoms(0),
        };
        let base_amount = base_value.into_signed().ok_or(Error::ArithmeticErrorToUnsignedFailed)?;
        let new_amount = (base_amount + v).ok_or(Error::ArithmeticErrorSumToSignedFailed)?;
        let new_amount =
            new_amount.into_unsigned().ok_or(Error::ArithmeticErrorToUnsignedFailed)?;
        m1.insert(k, new_amount);
    }
    Ok(m1)
}

impl<'a> PoSAccountingView for PoSAccountingDelta<'a> {
    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error> {
        let parent_balance = self.parent.get_pool_balance(pool_id)?;
        let local_delta = self.pool_balances.get(&pool_id).cloned();
        combine_amount_delta(&parent_balance, &local_delta)
    }

    fn get_pool_data(&self, pool_id: H256) -> Result<Option<PoolData>, Error> {
        let local_data = self.pool_data.get(&pool_id);
        match local_data {
            Some(d) => match d {
                PoolDataDelta::CreatePool(d) => Ok(Some(d.clone())),
                PoolDataDelta::DecommissionPool => Ok(None),
            },
            None => self.parent.get_pool_data(pool_id),
        }
    }

    fn get_pool_delegations_shares(
        &self,
        pool_id: H256,
    ) -> Result<Option<BTreeMap<H256, Amount>>, Error> {
        let parent_shares = self.parent.get_pool_delegations_shares(pool_id)?;
        let local_shares = self.get_cached_delegations_shares(pool_id);

        match (parent_shares, local_shares) {
            (None, None) => Ok(None),
            (None, Some(m)) => Ok(Some(
                m.into_iter()
                    .map(signed_to_unsigned_pair)
                    .collect::<Result<BTreeMap<H256, Amount>, Error>>()?,
            )),
            (Some(m), None) => Ok(Some(m)),
            (Some(m1), Some(m2)) => Ok(Some(sum_maps(m1, m2)?)),
        }
    }

    fn get_delegation_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error> {
        let parent_amount = self.parent.get_delegation_balance(delegation_id)?;
        let local_amount = self.delegation_balances.get(&delegation_id).copied();
        combine_amount_delta(&parent_amount, &local_amount)
    }

    fn get_delegation_data(&self, delegation_id: H256) -> Result<Option<DelegationData>, Error> {
        let local_data = self.delegation_data.get(&delegation_id);
        match local_data {
            Some(d) => match d {
                DelegationDataDelta::Add(d) => Ok(Some(*d.clone())),
                DelegationDataDelta::Remove => Ok(None),
            },
            None => self.parent.get_delegation_data(delegation_id),
        }
    }

    fn get_pool_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error> {
        let parent_amount = self.parent.get_pool_delegation_share(pool_id, delegation_id)?;
        let local_amount = self.pool_delegation_shares.get(&(pool_id, delegation_id)).copied();
        combine_amount_delta(&parent_amount, &local_amount)
    }
}
