// Copyright (c) 2024 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::BTreeMap;

use common::{
    chain::{GenBlock, PoolId, UtxoOutPoint},
    primitives::Id,
};
use crypto::{key::PrivateKey, vrf::VRFPrivateKey};

pub enum StakingPoolUpdate {
    Created {
        pool_id: PoolId,
        staker_key: PrivateKey,
        vrf_sk: VRFPrivateKey,
        outpoint: UtxoOutPoint,
    },
    Decommissioned {
        pool_id: PoolId,
    },
    UsedForStaking {
        pool_id: PoolId,
        outpoint: UtxoOutPoint,
    },
}

pub fn apply_staking_pools_updates(
    updates: &[StakingPoolUpdate],
    observer: &mut impl StakingPoolsForAllHeightsObserver,
    base_block: &Id<GenBlock>,
    base_block_parent: Option<&Id<GenBlock>>,
) {
    for update in updates {
        match update {
            StakingPoolUpdate::Created {
                pool_id,
                staker_key,
                vrf_sk,
                outpoint,
            } => observer.on_pool_created(
                *pool_id,
                staker_key.clone(),
                vrf_sk.clone(),
                outpoint.clone(),
                base_block,
                base_block_parent,
            ),
            StakingPoolUpdate::Decommissioned { pool_id } => {
                observer.on_pool_decommissioned(*pool_id, base_block, base_block_parent)
            }
            StakingPoolUpdate::UsedForStaking { pool_id, outpoint } => observer
                .on_pool_used_for_staking(
                    *pool_id,
                    outpoint.clone(),
                    base_block,
                    base_block_parent,
                ),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StakingPoolsForOneHeight {
    staking_pools: BTreeMap<
        PoolId,
        (
            PrivateKey,
            VRFPrivateKey,
            /*kernel_outpoint:*/ UtxoOutPoint,
            /*kernel_utxo_block_id:*/ Id<GenBlock>,
        ),
    >,
}

impl StakingPoolsForOneHeight {
    pub fn new() -> Self {
        Self {
            staking_pools: BTreeMap::new(),
        }
    }

    pub fn from_data(
        staking_pools: BTreeMap<PoolId, (PrivateKey, VRFPrivateKey, UtxoOutPoint, Id<GenBlock>)>,
    ) -> Self {
        Self { staking_pools }
    }

    pub fn staking_pools(
        &self,
    ) -> &BTreeMap<PoolId, (PrivateKey, VRFPrivateKey, UtxoOutPoint, Id<GenBlock>)> {
        &self.staking_pools
    }

    fn on_pool_created(
        &mut self,
        pool_id: PoolId,
        staker_key: PrivateKey,
        vrf_sk: VRFPrivateKey,
        outpoint: UtxoOutPoint,
        utxo_block_id: Id<GenBlock>,
    ) {
        self.staking_pools
            .insert(pool_id, (staker_key, vrf_sk, outpoint, utxo_block_id));
    }

    fn on_pool_decommissioned(&mut self, pool_id: PoolId) {
        self.staking_pools.remove(&pool_id);
    }

    fn on_pool_used_for_staking(
        &mut self,
        pool_id: PoolId,
        new_outpoint: UtxoOutPoint,
        new_utxo_block_id: Id<GenBlock>,
    ) {
        if let Some((_, _, kernel_outpoint, kernel_utxo_block_id)) =
            self.staking_pools.get_mut(&pool_id)
        {
            *kernel_outpoint = new_outpoint;
            *kernel_utxo_block_id = new_utxo_block_id;
        };
    }
}

/// Struct that holds possible pools and info required for staking
#[derive(Debug, Clone)]
pub struct StakingPoolsForAllHeights {
    staking_pools: BTreeMap<Id<GenBlock>, StakingPoolsForOneHeight>,
}

impl StakingPoolsForAllHeights {
    pub fn new() -> Self {
        Self {
            staking_pools: BTreeMap::new(),
        }
    }

    pub fn from_data(staking_pools: BTreeMap<Id<GenBlock>, StakingPoolsForOneHeight>) -> Self {
        Self { staking_pools }
    }

    pub fn staking_pools_for_base_block(
        &self,
        base_block: &Id<GenBlock>,
    ) -> &StakingPoolsForOneHeight {
        self.staking_pools.get(base_block).unwrap()
    }

    pub fn set_staking_pools_for_base_block(
        &mut self,
        base_block: &Id<GenBlock>,
        pools: StakingPoolsForOneHeight,
    ) -> &StakingPoolsForOneHeight {
        use std::collections::btree_map::Entry;

        match self.staking_pools.entry(*base_block) {
            Entry::Vacant(e) => e.insert(pools),
            Entry::Occupied(_) => {
                panic!("Staking pools for base block {base_block} already present")
            }
        }
    }

    pub fn all_staking_pools(&self) -> &BTreeMap<Id<GenBlock>, StakingPoolsForOneHeight> {
        &self.staking_pools
    }

    fn get_or_create_entry(
        &mut self,
        base_block: &Id<GenBlock>,
        base_block_parent: Option<&Id<GenBlock>>,
    ) -> &mut StakingPoolsForOneHeight {
        // Note: here we clone the info for base_block_parent before checking if we need it,
        // to pacify the borrow checker (which is ugly, but ok for tests).
        let init = if let Some(base_block_parent) = base_block_parent {
            // Note: normally we should panic if pools data for base_block_parent is not set.
            // But some tests don't bother specifying pool data for the genesis (via with_staking_pools_at_genesis).
            self.staking_pools
                .get(base_block_parent)
                .cloned()
                .unwrap_or(StakingPoolsForOneHeight::new())
        } else {
            StakingPoolsForOneHeight::new()
        };
        self.staking_pools.entry(*base_block).or_insert(init)
    }
}

impl StakingPoolsForAllHeightsObserver for StakingPoolsForAllHeights {
    fn on_pool_created(
        &mut self,
        pool_id: PoolId,
        staker_key: PrivateKey,
        vrf_sk: VRFPrivateKey,
        outpoint: UtxoOutPoint,
        base_block: &Id<GenBlock>,
        base_block_parent: Option<&Id<GenBlock>>,
    ) {
        self.get_or_create_entry(base_block, base_block_parent).on_pool_created(
            pool_id,
            staker_key,
            vrf_sk,
            outpoint,
            *base_block,
        );
    }

    fn on_pool_decommissioned(
        &mut self,
        pool_id: PoolId,
        base_block: &Id<GenBlock>,
        base_block_parent: Option<&Id<GenBlock>>,
    ) {
        self.get_or_create_entry(base_block, base_block_parent)
            .on_pool_decommissioned(pool_id);
    }

    fn on_pool_used_for_staking(
        &mut self,
        pool_id: PoolId,
        new_outpoint: UtxoOutPoint,
        base_block: &Id<GenBlock>,
        base_block_parent: Option<&Id<GenBlock>>,
    ) {
        self.get_or_create_entry(base_block, base_block_parent)
            .on_pool_used_for_staking(pool_id, new_outpoint, *base_block);
    }
}

pub trait StakingPoolsForAllHeightsObserver {
    fn on_pool_created(
        &mut self,
        pool_id: PoolId,
        staker_key: PrivateKey,
        vrf_sk: VRFPrivateKey,
        outpoint: UtxoOutPoint,
        base_block: &Id<GenBlock>,
        base_block_parent: Option<&Id<GenBlock>>,
    );
    fn on_pool_decommissioned(
        &mut self,
        pool_id: PoolId,
        base_block: &Id<GenBlock>,
        base_block_parent: Option<&Id<GenBlock>>,
    );
    fn on_pool_used_for_staking(
        &mut self,
        pool_id: PoolId,
        outpoint: UtxoOutPoint,
        base_block: &Id<GenBlock>,
        base_block_parent: Option<&Id<GenBlock>>,
    );
}

impl<'a, O> StakingPoolsForAllHeightsObserver for &'a mut O
where
    O: StakingPoolsForAllHeightsObserver,
{
    fn on_pool_created(
        &mut self,
        pool_id: PoolId,
        staker_key: PrivateKey,
        vrf_sk: VRFPrivateKey,
        outpoint: UtxoOutPoint,
        base_block: &Id<GenBlock>,
        base_block_parent: Option<&Id<GenBlock>>,
    ) {
        (*self).on_pool_created(
            pool_id,
            staker_key,
            vrf_sk,
            outpoint,
            base_block,
            base_block_parent,
        )
    }

    fn on_pool_decommissioned(
        &mut self,
        pool_id: PoolId,
        base_block: &Id<GenBlock>,
        base_block_parent: Option<&Id<GenBlock>>,
    ) {
        (*self).on_pool_decommissioned(pool_id, base_block, base_block_parent)
    }

    fn on_pool_used_for_staking(
        &mut self,
        pool_id: PoolId,
        outpoint: UtxoOutPoint,
        base_block: &Id<GenBlock>,
        base_block_parent: Option<&Id<GenBlock>>,
    ) {
        (*self).on_pool_used_for_staking(pool_id, outpoint, base_block, base_block_parent)
    }
}
