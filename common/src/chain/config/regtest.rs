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
    collections::HashMap,
    fmt::{Display, Formatter},
    str::FromStr,
};

use crate::{
    chain::{
        block::timestamp::BlockTimestamp,
        config::{StakePoolData, DEFAULT_INITIAL_MINT, MIN_STAKE_POOL_PLEDGE},
        output_value::OutputValue,
        transaction::Destination,
        Genesis, PoolId, TxOutput,
    },
    primitives::{per_thousand::PerThousand, Amount},
};
use crypto::{
    key::{PrivateKey, PublicKey},
    vrf::{VRFPrivateKey, VRFPublicKey},
};
use hex::FromHex;
use serialization::hex::HexEncode;

const GENESIS_BLOCK_TIMESTAMP: u64 = 1639975460;
const GENESIS_POOL_ID: &str = "123c4c600097c513e088b9be62069f0c74c7671c523c8e3469a1c3f14b7ea2c4";
const GENESIS_STAKE_PRIVATE_KEY: &str =
    "008717e6946febd3a33ccdc3f3a27629ec80c33461c33a0fc56b4836fcedd26638";
const GENESIS_VRF_PRIVATE_KEY: &str = "003fcf7b813bec2a293f574b842988895278b396dd72471de2583b242097a59f06e9f3cd7b78d45750afd17292031373fddb5e7a8090db51221038f5e05f29998e";

#[derive(Clone, Debug, PartialEq)]
pub struct GenesisStakingSettings {
    pool_id: PoolId,
    stake_private_key: PrivateKey,
    vrf_private_key: VRFPrivateKey,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum GenesisStakingSettingsInputErrors {
    #[error("Duplicate staking setting {0}")]
    DupicateStakingSetting(String),
    #[error("Hex decoding failed {0}")]
    HexDecodingFailed(String),
    #[error("Invalid pool Id {0}")]
    InvalidPoolId(String),
    #[error("Invalid staking private key {0}")]
    InvalidStakingPrivateKey(String),
    #[error("Invalid VRF private key {0}")]
    InvalidVRFPrivateKey(String),
    #[error("Type decoding failed {0}")]
    TypeDecodingFailed(String),
    #[error("Unknown staking settings parameter {0}")]
    UnknownParameter(String),
}

fn decode_hex<T: serialization::DecodeAll>(
    hex: &str,
) -> Result<T, GenesisStakingSettingsInputErrors> {
    let bytes = Vec::from_hex(hex)
        .map_err(|_| GenesisStakingSettingsInputErrors::HexDecodingFailed(hex.to_string()))?;
    <T as serialization::DecodeAll>::decode_all(&mut bytes.as_slice())
        .map_err(|_| GenesisStakingSettingsInputErrors::TypeDecodingFailed(hex.to_string()))
}

impl GenesisStakingSettings {
    pub fn new(
        pool_id: PoolId,
        stake_private_key: PrivateKey,
        vrf_private_key: VRFPrivateKey,
    ) -> Self {
        Self {
            pool_id,
            stake_private_key,
            vrf_private_key,
        }
    }

    pub fn pool_id(&self) -> PoolId {
        self.pool_id
    }

    pub fn stake_private_key(&self) -> &PrivateKey {
        &self.stake_private_key
    }

    pub fn vrf_private_key(&self) -> &VRFPrivateKey {
        &self.vrf_private_key
    }
}

impl Default for GenesisStakingSettings {
    fn default() -> Self {
        Self::from_str("").expect("Default value")
    }
}

impl FromStr for GenesisStakingSettings {
    type Err = GenesisStakingSettingsInputErrors;

    fn from_str(settings: &str) -> Result<Self, Self::Err> {
        let settings_parts = settings
            .split(',')
            .filter_map(|s| s.split_once(':').or(if s.is_empty() { None } else { Some((s, "")) }))
            .map(|(k, v)| (k.trim(), v.trim()))
            .collect::<Vec<(&str, &str)>>();

        let mut settings_parts_uniq = HashMap::new();

        for (key, value) in settings_parts {
            if settings_parts_uniq.insert(key, value).is_some() {
                return Err(GenesisStakingSettingsInputErrors::DupicateStakingSetting(
                    key.into(),
                ));
            }
        }

        let pool_id = {
            let pool_id = settings_parts_uniq.remove("pool_id").unwrap_or(GENESIS_POOL_ID);

            decode_hex::<PoolId>(pool_id)
                .map_err(|_| GenesisStakingSettingsInputErrors::InvalidPoolId(pool_id.into()))?
        };

        let stake_private_key = {
            let stake_private_key = settings_parts_uniq
                .remove("stake_private_key")
                .unwrap_or(GENESIS_STAKE_PRIVATE_KEY);

            decode_hex::<PrivateKey>(stake_private_key).map_err(|_| {
                GenesisStakingSettingsInputErrors::InvalidStakingPrivateKey(
                    stake_private_key.into(),
                )
            })?
        };

        let vrf_private_key = {
            let vrf_private_key =
                settings_parts_uniq.remove("vrf_private_key").unwrap_or(GENESIS_VRF_PRIVATE_KEY);

            decode_hex::<VRFPrivateKey>(vrf_private_key).map_err(|_| {
                GenesisStakingSettingsInputErrors::InvalidVRFPrivateKey(vrf_private_key.into())
            })?
        };

        if !settings_parts_uniq.is_empty() {
            return Err(GenesisStakingSettingsInputErrors::UnknownParameter(
                settings_parts_uniq
                    .drain()
                    .map(|(k, v)| {
                        if v.is_empty() {
                            k.to_string()
                        } else {
                            [k, v].join(":")
                        }
                    })
                    .collect::<Vec<String>>()
                    .join(","),
            ));
        }

        Ok(Self {
            pool_id,
            stake_private_key,
            vrf_private_key,
        })
    }
}

impl Display for GenesisStakingSettings {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        let mut values = vec![];

        let pool_id = self.pool_id().hex_encode();
        let stake_private_key = self.stake_private_key().hex_encode();
        let vrf_private_key = self.vrf_private_key().hex_encode();

        if !pool_id.is_empty() {
            values.push(format!("pool_id:{}", pool_id))
        }

        if !stake_private_key.is_empty() {
            values.push(format!("stake_private_key:{}", stake_private_key))
        }

        if !vrf_private_key.is_empty() {
            values.push(format!("vrf_private_key:{}", vrf_private_key))
        }

        write!(f, "{}", values.join(","))
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
    let genesis_stake_public_key = PublicKey::from_private_key(genesis_stake_private_key);

    let genesis_vrf_private_key = genesis_staking_settings.vrf_private_key();
    let genesis_vrf_public_key = VRFPublicKey::from_private_key(genesis_vrf_private_key);

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
        genesis_stake_private_key.clone(),
        genesis_stake_public_key,
        genesis_vrf_private_key.clone(),
        genesis_vrf_public_key,
    )
}

pub fn create_regtest_pos_genesis(
    genesis_staking_settings: GenesisStakingSettings,
    genesis_block_timestamp: Option<u64>,
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
        BlockTimestamp::from_int_seconds(
            genesis_block_timestamp.unwrap_or(GENESIS_BLOCK_TIMESTAMP),
        ),
        vec![premine_output, create_genesis_pool_txoutput],
    )
}

pub fn create_regtest_pow_genesis(
    genesis_block_timestamp: Option<u64>,
    premine_destination: Destination,
) -> Genesis {
    let premine_output =
        TxOutput::Transfer(OutputValue::Coin(DEFAULT_INITIAL_MINT), premine_destination);

    Genesis::new(
        String::new(),
        BlockTimestamp::from_int_seconds(
            genesis_block_timestamp.unwrap_or(GENESIS_BLOCK_TIMESTAMP),
        ),
        vec![premine_output],
    )
}

#[cfg(test)]
mod test {
    use super::*;

    const NEW_POOL_ID: &str = "ee06c7325d7e18d29f04ada56cda0ed71d3ebd2e8679795b3a99a4985707d3f3";
    const NEW_STAKE_PRIVATE_KEY: &str =
        "00cf07d9ea2f571a456619470d5a816023137f22969f9507d37b7a54089a6a12dc";
    const NEW_VRF_PRIVATE_KEY: &str = "001556d3f237865226dcab9698be70566cf2d018f6bf5421074c37bdeaef85f30c860b56f4c0fef96a97d5906890c5371f6e11eb521b26138c2f8a38dc92edc458";

    #[test]
    fn default() {
        let default = GenesisStakingSettings::default();

        assert_eq!(
            default.pool_id().hex_encode(),
            GENESIS_POOL_ID,
            "Default Genesis pool Id is incorrect"
        );
        assert_eq!(
            default.stake_private_key().hex_encode(),
            GENESIS_STAKE_PRIVATE_KEY,
            "Default Genesis stake private key is incorrect"
        );
        assert_eq!(
            default.vrf_private_key().hex_encode(),
            GENESIS_VRF_PRIVATE_KEY,
            "Default Genesis VRF private key is incorrect"
        );
    }

    #[test]
    fn missing_value() {
        let result = GenesisStakingSettings::from_str("key");

        assert_eq!(
            result,
            Err(GenesisStakingSettingsInputErrors::UnknownParameter(
                "key".to_string()
            )),
            "Missing value was valid"
        );
    }

    #[test]
    fn empty_value() {
        let result = GenesisStakingSettings::from_str("key:");

        assert_eq!(
            result,
            Err(GenesisStakingSettingsInputErrors::UnknownParameter(
                "key".to_string()
            )),
            "Empty value was valid"
        );
    }

    #[test]
    fn duplicate_key() {
        let result = GenesisStakingSettings::from_str("key:value1,key:value2");

        assert_eq!(
            result,
            Err(GenesisStakingSettingsInputErrors::DupicateStakingSetting(
                "key".to_string()
            )),
            "Duplicate key was valid"
        );
    }

    #[test]
    fn invalid_pool_id() {
        let result = GenesisStakingSettings::from_str("pool_id:invalid_value");

        assert_eq!(
            result,
            Err(GenesisStakingSettingsInputErrors::InvalidPoolId(
                "invalid_value".to_string()
            )),
            "Genesis pool Id was valid"
        );
    }

    #[test]
    fn invalid_stake_private_key() {
        let result = GenesisStakingSettings::from_str("stake_private_key:invalid_value");

        assert_eq!(
            result,
            Err(GenesisStakingSettingsInputErrors::InvalidStakingPrivateKey(
                "invalid_value".to_string()
            )),
            "Genesis staking private key was valid"
        );
    }

    #[test]
    fn invalid_vrf_private_key() {
        let result = GenesisStakingSettings::from_str("vrf_private_key:invalid_value");

        assert_eq!(
            result,
            Err(GenesisStakingSettingsInputErrors::InvalidVRFPrivateKey(
                "invalid_value".to_string()
            )),
            "Genesis vrf private key was valid"
        );
    }

    #[test]
    fn overrides() {
        for pool_id_override in [true, false] {
            for stake_private_key_override in [true, false] {
                for vrf_private_key_override in [true, false] {
                    let pool_id = if pool_id_override {
                        NEW_POOL_ID
                    } else {
                        GENESIS_POOL_ID
                    };

                    let stake_private_key = if stake_private_key_override {
                        NEW_STAKE_PRIVATE_KEY
                    } else {
                        GENESIS_STAKE_PRIVATE_KEY
                    };

                    let vrf_private_key = if vrf_private_key_override {
                        NEW_VRF_PRIVATE_KEY
                    } else {
                        GENESIS_VRF_PRIVATE_KEY
                    };

                    let new_settings = format!(
                        "pool_id:{},stake_private_key:{},vrf_private_key:{}",
                        pool_id, stake_private_key, vrf_private_key,
                    );

                    let new_genesis_staking_settings =
                        GenesisStakingSettings::from_str(&new_settings).expect("Parsed ok");

                    assert_eq!(
                        new_genesis_staking_settings.pool_id().hex_encode(),
                        pool_id,
                        "Genesis pool Id is incorrect"
                    );

                    assert_eq!(
                        new_genesis_staking_settings.stake_private_key().hex_encode(),
                        stake_private_key,
                        "Genesis stake private key is incorrect"
                    );

                    assert_eq!(
                        new_genesis_staking_settings.vrf_private_key().hex_encode(),
                        vrf_private_key,
                        "Genesis VRF private key is incorrect"
                    );
                }
            }
        }
    }

    #[test]
    fn missing_and_leftover() {
        for pool_id_missing in [true, false] {
            for stake_private_key_missing in [true, false] {
                for vrf_private_key_missing in [true, false] {
                    for leftover in [true, false] {
                        let mut expected_values = vec![];
                        let mut settings_parts = vec![];

                        if pool_id_missing {
                            expected_values.push(GENESIS_POOL_ID)
                        } else {
                            expected_values.push(NEW_POOL_ID);
                            settings_parts.push(format!("pool_id:{}", NEW_POOL_ID));
                        };

                        if stake_private_key_missing {
                            expected_values.push(GENESIS_STAKE_PRIVATE_KEY)
                        } else {
                            expected_values.push(NEW_STAKE_PRIVATE_KEY);
                            settings_parts
                                .push(format!("stake_private_key:{}", NEW_STAKE_PRIVATE_KEY));
                        };

                        if vrf_private_key_missing {
                            expected_values.push(GENESIS_VRF_PRIVATE_KEY)
                        } else {
                            expected_values.push(NEW_VRF_PRIVATE_KEY);
                            settings_parts.push(format!("vrf_private_key:{}", NEW_VRF_PRIVATE_KEY));
                        };

                        if leftover {
                            settings_parts.push("unknown_setting:unknown_value".to_string())
                        }

                        let new_settings = settings_parts.join(",");

                        match GenesisStakingSettings::from_str(&new_settings) {
                            Ok(new_genesis_staking_settings) => {
                                assert_eq!(
                                    new_genesis_staking_settings.pool_id().hex_encode(),
                                    expected_values[0],
                                    "Genesis pool Id is incorrect"
                                );

                                assert_eq!(
                                    new_genesis_staking_settings.stake_private_key().hex_encode(),
                                    expected_values[1],
                                    "Genesis stake private key is incorrect"
                                );

                                assert_eq!(
                                    new_genesis_staking_settings.vrf_private_key().hex_encode(),
                                    expected_values[2],
                                    "Genesis VRF private key is incorrect"
                                );
                            }
                            Err(GenesisStakingSettingsInputErrors::UnknownParameter(unknown)) => {
                                assert_eq!(
                                    unknown, "unknown_setting:unknown_value",
                                    "Unknown unknown setting"
                                )
                            }
                            Err(_) => {
                                panic!("Invalid error, handled in other tests");
                            }
                        }
                    }
                }
            }
        }
    }
}
