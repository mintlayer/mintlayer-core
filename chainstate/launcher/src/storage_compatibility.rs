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
use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use common::chain::ChainConfig;
use utils::ensure;

const CHAINSTATE_STORAGE_VERSION_UNINITIALIZED: u32 = 0;
const CHAINSTATE_STORAGE_VERSION_V1: u32 = 1;
const CURRENT_CHAINSTATE_STORAGE_VERSION: u32 = CHAINSTATE_STORAGE_VERSION_V1;

pub fn check_storage_compatibility<B: 'static + storage::Backend>(
    storage: &mut chainstate_storage::Store<B>,
    chain_config: &ChainConfig,
) -> Result<(), StorageCompatibilityCheckError> {
    check_storage_version(storage)?;
    check_magic_bytes(storage, chain_config)?;
    check_chain_type(storage, chain_config)?;

    Ok(())
}

fn check_storage_version<B: 'static + storage::Backend>(
    storage: &mut chainstate_storage::Store<B>,
) -> Result<(), StorageCompatibilityCheckError> {
    let storage_version = storage
        .get_storage_version()
        .map_err(StorageCompatibilityCheckError::StorageError)?;

    if storage_version == CHAINSTATE_STORAGE_VERSION_UNINITIALIZED {
        storage
            .set_storage_version(CURRENT_CHAINSTATE_STORAGE_VERSION)
            .map_err(StorageCompatibilityCheckError::StorageError)?;
    } else {
        ensure!(
            storage_version == CURRENT_CHAINSTATE_STORAGE_VERSION,
            StorageCompatibilityCheckError::ChainstateStorageVersionMismatch(
                storage_version,
                CURRENT_CHAINSTATE_STORAGE_VERSION
            )
        );
    }
    Ok(())
}

fn check_magic_bytes<B: 'static + storage::Backend>(
    storage: &mut chainstate_storage::Store<B>,
    chain_config: &ChainConfig,
) -> Result<(), StorageCompatibilityCheckError> {
    let storage_magic_bytes = storage
        .get_magic_bytes()
        .map_err(StorageCompatibilityCheckError::StorageError)?;
    let chain_config_magic_bytes = chain_config.magic_bytes();

    match storage_magic_bytes {
        Some(storage_magic_bytes) => ensure!(
            &storage_magic_bytes == chain_config_magic_bytes,
            StorageCompatibilityCheckError::ChainConfigMagicBytesMismatch(
                storage_magic_bytes,
                chain_config_magic_bytes.to_owned()
            )
        ),
        None => storage
            .set_magic_bytes(chain_config_magic_bytes)
            .map_err(StorageCompatibilityCheckError::StorageError)?,
    };

    Ok(())
}

fn check_chain_type<B: 'static + storage::Backend>(
    storage: &mut chainstate_storage::Store<B>,
    chain_config: &ChainConfig,
) -> Result<(), StorageCompatibilityCheckError> {
    let storage_chain_type =
        storage.get_chain_type().map_err(StorageCompatibilityCheckError::StorageError)?;
    let chain_config_type = chain_config.chain_type().name();

    match storage_chain_type {
        Some(storage_chain_type) => ensure!(
            storage_chain_type == chain_config_type,
            StorageCompatibilityCheckError::ChainTypeMismatch(
                storage_chain_type,
                chain_config_type.to_owned()
            )
        ),
        None => storage
            .set_chain_type(chain_config_type)
            .map_err(StorageCompatibilityCheckError::StorageError)?,
    };

    Ok(())
}
