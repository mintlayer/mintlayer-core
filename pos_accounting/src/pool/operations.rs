use std::collections::BTreeMap;

use accounting::DataDeltaUndoOp;
use common::{
    chain::OutPoint,
    primitives::{Amount, H256},
};
use crypto::key::PublicKey;

use crate::error::Error;

pub(crate) enum PoolDataUndo {
    Data(PoolData),
    DataDelta((Amount, DataDeltaUndoOp<PoolData>)),
}

pub(crate) enum DelegationDataUndo {
    Data(DelegationData),
    DataDelta(DataDeltaUndoOp<DelegationData>),
}

pub struct CreatePoolUndo {
    pub(crate) pool_id: H256,
    pub(crate) data_undo: PoolDataUndo,
}

pub struct CreateDelegationIdUndo {
    pub(crate) delegation_id: H256,
    pub(crate) data_undo: DelegationDataUndo,
}

pub struct DecommissionPoolUndo {
    pub(crate) pool_id: H256,
    pub(crate) data_undo: PoolDataUndo,
}

pub struct DelegateStakingUndo {
    pub(crate) delegation_target: H256,
    pub(crate) amount_to_delegate: Amount,
}

pub struct SpendFromShareUndo {
    pub(crate) delegation_id: H256,
    pub(crate) amount: Amount,
}

pub enum PoSAccountingUndo {
    CreatePool(CreatePoolUndo),
    DecommissionPool(DecommissionPoolUndo),
    CreateDelegationId(CreateDelegationIdUndo),
    DelegateStaking(DelegateStakingUndo),
    SpendFromShare(SpendFromShareUndo),
}

use super::{delegation::DelegationData, pool_data::PoolData};

pub trait PoSAccountingOperatorWrite {
    fn create_pool(
        &mut self,
        input0_outpoint: &OutPoint,
        pledge_amount: Amount,
        decommission_key: PublicKey,
    ) -> Result<(H256, PoSAccountingUndo), Error>;

    fn decommission_pool(&mut self, pool_id: H256) -> Result<PoSAccountingUndo, Error>;

    fn create_delegation_id(
        &mut self,
        target_pool: H256,
        spend_key: PublicKey,
        input0_outpoint: &OutPoint,
    ) -> Result<(H256, PoSAccountingUndo), Error>;

    fn delegate_staking(
        &mut self,
        delegation_target: H256,
        amount_to_delegate: Amount,
    ) -> Result<PoSAccountingUndo, Error>;

    fn spend_share_from_delegation_id(
        &mut self,
        delegation_id: H256,
        amount: Amount,
    ) -> Result<PoSAccountingUndo, Error>;

    fn undo(&mut self, undo_data: PoSAccountingUndo) -> Result<(), Error>;
}

pub trait PoSAccountingOperatorRead {
    fn pool_exists(&self, pool_id: H256) -> Result<bool, Error>;

    fn get_delegation_shares(&self, pool_id: H256)
        -> Result<Option<BTreeMap<H256, Amount>>, Error>;

    fn get_delegation_share(
        &self,
        pool_id: H256,
        delegation_id: H256,
    ) -> Result<Option<Amount>, Error>;

    fn get_pool_balance(&self, pool_id: H256) -> Result<Option<Amount>, Error>;

    fn get_delegation_id_balance(&self, delegation_id: H256) -> Result<Option<Amount>, Error>;

    fn get_delegation_id_data(&self, delegation_id: H256) -> Result<Option<DelegationData>, Error>;

    fn get_pool_data(&self, pool_id: H256) -> Result<Option<PoolData>, Error>;
}
