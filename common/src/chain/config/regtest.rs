// Copyright (c) 2022 RBB S.r.l
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

use std::{
    convert::Infallible,
    fmt::{Display, Formatter},
    str::FromStr,
};

use crate::{
    chain::{
        block::timestamp::BlockTimestamp,
        config::{decode_hex, StakePoolData, DEFAULT_INITIAL_MINT, MIN_STAKE_POOL_PLEDGE},
        tokens::OutputValue,
        transaction::Destination,
        Genesis, PoolId, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount},
};
use crypto::{
    key::{PrivateKey, PublicKey},
    vrf::{VRFPrivateKey, VRFPublicKey},
};

#[derive(Clone, Debug)]
pub struct GenesisStakingSettings {
    pool_id: PoolId,
    stake_private_key: PrivateKey,
    vrf_private_key: VRFPrivateKey,
}

impl GenesisStakingSettings {
    pub fn new(settings: &str) -> Self {
        let settings_parts: Vec<&str> = settings.split(',').map(|s| s.trim()).collect();

        let pool_id = settings_parts
            .iter()
            .find_map(|s| s.strip_prefix("genesis_pool_id:"))
            .or(Some(
                "123c4c600097c513e088b9be62069f0c74c7671c523c8e3469a1c3f14b7ea2c4",
            ))
            .map(decode_hex::<PoolId>)
            .expect("Pool Id decoded");

        let stake_private_key = settings_parts
            .iter()
            .find_map(|s| s.strip_prefix("genesis_stake_private_key:"))
            .or(Some(
                "008717e6946febd3a33ccdc3f3a27629ec80c33461c33a0fc56b4836fcedd26638",
            ))
            .map(decode_hex::<PrivateKey>)
            .expect("Private key decoded");

        let vrf_private_key = settings_parts
            .iter()
            .find_map(|s| s.strip_prefix("genesis_vrf_private_key:"))
            .or(Some(
                "003fcf7b813bec2a293f574b842988895278b396dd72471de2583b242097a59f06e9f3cd7b78d45750afd17292031373fddb5e7a8090db51221038f5e05f29998e",
            ))
            .map(decode_hex::<VRFPrivateKey>)
            .expect("VRF private key decoded");

        Self {
            pool_id,
            stake_private_key,
            vrf_private_key,
        }
    }

    pub fn pool_id(&self) -> PoolId {
        self.pool_id
    }

    pub fn stake_private_key(&self) -> PrivateKey {
        self.stake_private_key.clone()
    }

    pub fn vrf_private_key(&self) -> VRFPrivateKey {
        self.vrf_private_key.clone()
    }
}

impl Default for GenesisStakingSettings {
    fn default() -> Self {
        Self::new("")
    }
}

impl FromStr for GenesisStakingSettings {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(s))
    }
}

impl Display for GenesisStakingSettings {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "{{pool_id: {:?}, stake_private_key: {:?}, vrf_private_key: {:?}}}",
            self.pool_id(),
            self.stake_private_key(),
            self.vrf_private_key()
        )
    }
}

pub fn genesis_values(
    genesis_staking_settings: GenesisStakingSettings,
) -> (
    PoolId,
    Box<StakePoolData>,
    PrivateKey,
    PublicKey,
    VRFPrivateKey,
    VRFPublicKey,
) {
    let genesis_stake_private_key = genesis_staking_settings.stake_private_key();
    let genesis_stake_public_key = PublicKey::from_private_key(&genesis_stake_private_key);

    let genesis_vrf_private_key = genesis_staking_settings.vrf_private_key();
    let genesis_vrf_public_key = VRFPublicKey::from_private_key(&genesis_vrf_private_key);

    let genesis_pool_stake_data = Box::new(StakePoolData::new(
        MIN_STAKE_POOL_PLEDGE,
        Destination::PublicKey(genesis_stake_public_key.clone()),
        genesis_vrf_public_key.clone(),
        Destination::PublicKey(genesis_stake_public_key.clone()),
        PerThousand::new(1000).expect("Valid per thousand"),
        Amount::ZERO,
    ));

    (
        genesis_staking_settings.pool_id(),
        genesis_pool_stake_data,
        genesis_stake_private_key,
        genesis_stake_public_key,
        genesis_vrf_private_key,
        genesis_vrf_public_key,
    )
}

pub fn create_regtest_pos_genesis(
    genesis_staking_settings: GenesisStakingSettings,
    premine_destination: Destination,
) -> Genesis {
    let (
        genesis_pool_id,
        genesis_stake_pool_data,
        _genesis_stake_private_key,
        _genesis_stake_public_key,
        _genesis_vrf_private_key,
        _genesis_vrf_public_key,
    ) = genesis_values(genesis_staking_settings);

    let create_genesis_pool_txoutput =
        TxOutput::CreateStakePool(genesis_pool_id, genesis_stake_pool_data);

    let premine_output =
        TxOutput::Transfer(OutputValue::Coin(DEFAULT_INITIAL_MINT), premine_destination);

    Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(1639975460),
        vec![premine_output, create_genesis_pool_txoutput],
    )
}
