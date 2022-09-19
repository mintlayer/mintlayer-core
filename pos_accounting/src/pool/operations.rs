use std::collections::BTreeMap;

use accounting::DataDeltaUndoOp;
use common::{chain::OutPoint, primitives::Amount};
use crypto::key::PublicKey;

use crate::{error::Error, DelegationId, PoolId};

pub(crate) enum PoolDataUndo {
    Data(PoolData),
    DataDelta((Amount, DataDeltaUndoOp<PoolData>)),
}

pub(crate) enum DelegationDataUndo {
    Data(Box<DelegationData>),
    DataDelta(DataDeltaUndoOp<DelegationData>),
}

pub struct CreatePoolUndo {
    pub(crate) pool_id: PoolId,
    pub(crate) data_undo: PoolDataUndo,
}

pub struct CreateDelegationIdUndo {
    pub(crate) delegation_id: DelegationId,
    pub(crate) data_undo: DelegationDataUndo,
}

pub struct DecommissionPoolUndo {
    pub(crate) pool_id: PoolId,
    pub(crate) data_undo: PoolDataUndo,
}

pub struct DelegateStakingUndo {
    pub(crate) delegation_target: DelegationId,
    pub(crate) amount_to_delegate: Amount,
}

pub struct SpendFromShareUndo {
    pub(crate) delegation_id: DelegationId,
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
    ) -> Result<(PoolId, PoSAccountingUndo), Error>;

    fn decommission_pool(&mut self, pool_id: PoolId) -> Result<PoSAccountingUndo, Error>;

    fn create_delegation_id(
        &mut self,
        target_pool: PoolId,
        spend_key: PublicKey,
        input0_outpoint: &OutPoint,
    ) -> Result<(DelegationId, PoSAccountingUndo), Error>;

    fn delegate_staking(
        &mut self,
        delegation_target: DelegationId,
        amount_to_delegate: Amount,
    ) -> Result<PoSAccountingUndo, Error>;

    fn spend_share_from_delegation_id(
        &mut self,
        delegation_id: DelegationId,
        amount: Amount,
    ) -> Result<PoSAccountingUndo, Error>;

    fn undo(&mut self, undo_data: PoSAccountingUndo) -> Result<(), Error>;
}

pub trait PoSAccountingOperatorRead {
    fn pool_exists(&self, pool_id: PoolId) -> Result<bool, Error>;

    fn get_delegation_shares(
        &self,
        pool_id: PoolId,
    ) -> Result<Option<BTreeMap<DelegationId, Amount>>, Error>;

    fn get_delegation_share(
        &self,
        pool_id: PoolId,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error>;

    fn get_pool_balance(&self, pool_id: PoolId) -> Result<Option<Amount>, Error>;

    fn get_delegation_id_balance(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<Amount>, Error>;

    fn get_delegation_id_data(
        &self,
        delegation_id: DelegationId,
    ) -> Result<Option<DelegationData>, Error>;

    fn get_pool_data(&self, pool_id: PoolId) -> Result<Option<PoolData>, Error>;
}
