use crate::pool::operations::PoSAccountingOperatorRead;

use super::{sum_maps, PoSAccountingDelta};

impl<'a> PoSAccountingOperatorRead for PoSAccountingDelta<'a> {
    fn pool_exists(&self, pool_id: common::primitives::H256) -> Result<bool, crate::error::Error> {
        Ok(self.parent.get_pool_data(pool_id)?.is_some())
    }

    fn get_delegation_shares(
        &self,
        pool_id: common::primitives::H256,
    ) -> Result<
        Option<std::collections::BTreeMap<common::primitives::H256, common::primitives::Amount>>,
        crate::error::Error,
    > {
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
        _pool_id: common::primitives::H256,
        _delegation_id: common::primitives::H256,
    ) -> Result<Option<common::primitives::Amount>, crate::error::Error> {
        todo!()
    }

    fn get_pool_balance(
        &self,
        _pool_id: common::primitives::H256,
    ) -> Result<Option<common::primitives::Amount>, crate::error::Error> {
        todo!()
    }

    fn get_delegation_id_balance(
        &self,
        _delegation_id: common::primitives::H256,
    ) -> Result<Option<common::primitives::Amount>, crate::error::Error> {
        todo!()
    }

    fn get_delegation_id_data(
        &self,
        _delegation_id: common::primitives::H256,
    ) -> Result<Option<crate::pool::delegation::DelegationData>, crate::error::Error> {
        todo!()
    }
}
