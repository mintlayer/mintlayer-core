// Copyright (c) 2023 RBB S.r.l
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

use chainstate::StorageCompatibilityCheckError;
use chainstate_storage::{BlockchainStorageRead, ChainstateStorageVersion};
use common::chain::ChainConfig;
use utils::ensure;

pub fn check_storage_compatibility(
    storage: &impl BlockchainStorageRead,
    chain_config: &ChainConfig,
) -> Result<(), StorageCompatibilityCheckError> {
    check_storage_version(storage)?;
    check_magic_bytes(storage, chain_config)?;
    check_chain_type(storage, chain_config)?;

    Ok(())
}

fn check_storage_version(
    storage: &impl BlockchainStorageRead,
) -> Result<(), StorageCompatibilityCheckError> {
    let storage_version = storage
        .get_storage_version()
        .map_err(StorageCompatibilityCheckError::StorageError)?
        .ok_or(StorageCompatibilityCheckError::StorageVersionMissing)?;

    ensure!(
        storage_version == ChainstateStorageVersion::CURRENT,
        StorageCompatibilityCheckError::ChainstateStorageVersionMismatch(
            storage_version,
            ChainstateStorageVersion::CURRENT
        )
    );

    Ok(())
}

fn check_magic_bytes(
    storage: &impl BlockchainStorageRead,
    chain_config: &ChainConfig,
) -> Result<(), StorageCompatibilityCheckError> {
    let storage_magic_bytes = storage
        .get_magic_bytes()
        .map_err(StorageCompatibilityCheckError::StorageError)?
        .ok_or(StorageCompatibilityCheckError::MagicBytesMissing)?;

    ensure!(
        &storage_magic_bytes == chain_config.magic_bytes(),
        StorageCompatibilityCheckError::ChainConfigMagicBytesMismatch(
            storage_magic_bytes,
            chain_config.magic_bytes().to_owned()
        )
    );

    Ok(())
}

fn check_chain_type(
    storage: &impl BlockchainStorageRead,
    chain_config: &ChainConfig,
) -> Result<(), StorageCompatibilityCheckError> {
    let storage_chain_type = storage
        .get_chain_type()
        .map_err(StorageCompatibilityCheckError::StorageError)?
        .ok_or(StorageCompatibilityCheckError::ChainTypeMissing)?;
    let chain_config_type = chain_config.chain_type().name();

    ensure!(
        storage_chain_type == chain_config_type,
        StorageCompatibilityCheckError::ChainTypeMismatch(
            storage_chain_type,
            chain_config_type.to_owned()
        )
    );

    Ok(())
}
