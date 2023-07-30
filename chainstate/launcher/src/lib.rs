// Copyright (c) 2021-2022 RBB S.r.l
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

//! Tools to set up chainstate together with its storage

mod config;

use std::sync::Arc;

use chainstate::InitializationError;
use chainstate_storage::{BlockchainStorageRead, BlockchainStorageWrite};
use storage_lmdb::resize_callback::MapResizeCallback;
use utils::ensure;

// Some useful reexports
pub use chainstate::{
    chainstate_interface::ChainstateInterface, ChainstateConfig, ChainstateError as Error,
    DefaultTransactionVerificationStrategy,
};
pub use common::chain::ChainConfig;
pub use config::{ChainstateLauncherConfig, StorageBackendConfig};

/// Subdirectory under `datadir` where LMDB chainstate database is placed
pub const SUBDIRECTORY_LMDB: &str = "chainstate-lmdb";

const CHAINSTATE_STORAGE_VERSION_UNINITIALIZED: u32 = 0;
const CHAINSTATE_STORAGE_VERSION_V1: u32 = 1;
const CURRENT_CHAINSTATE_STORAGE_VERSION: u32 = CHAINSTATE_STORAGE_VERSION_V1;

fn make_chainstate_and_storage_impl<B: 'static + storage::Backend>(
    storage_backend: B,
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
) -> Result<Box<dyn ChainstateInterface>, Error> {
    let mut storage = chainstate_storage::Store::new(storage_backend)
        .map_err(|e| Error::FailedToInitializeChainstate(e.into()))?;

    check_storage_version(&mut storage)?;
    check_magic_bytes(&mut storage, chain_config.as_ref())?;
    check_chain_type(&mut storage, chain_config.as_ref())?;

    let chainstate = chainstate::make_chainstate(
        chain_config,
        chainstate_config,
        storage,
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
    )?;
    Ok(chainstate)
}

fn check_storage_version<B: 'static + storage::Backend>(
    storage: &mut chainstate_storage::Store<B>,
) -> Result<(), Error> {
    let storage_version =
        storage.get_storage_version().map_err(InitializationError::StorageError)?;

    if storage_version == CHAINSTATE_STORAGE_VERSION_UNINITIALIZED {
        storage
            .set_storage_version(CURRENT_CHAINSTATE_STORAGE_VERSION)
            .map_err(InitializationError::StorageError)?;
    } else {
        ensure!(
            storage_version == CURRENT_CHAINSTATE_STORAGE_VERSION,
            InitializationError::ChainstateStorageVersionMismatch(
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
) -> Result<(), Error> {
    let storage_magic_bytes =
        storage.get_magic_bytes().map_err(InitializationError::StorageError)?;
    let chain_config_magic_bytes = chain_config.magic_bytes();

    match storage_magic_bytes {
        Some(storage_magic_bytes) => ensure!(
            &storage_magic_bytes == chain_config_magic_bytes,
            InitializationError::ChainConfigMagicBytesMismatch(
                storage_magic_bytes,
                chain_config_magic_bytes.to_owned()
            )
        ),
        None => storage
            .set_magic_bytes(chain_config_magic_bytes)
            .map_err(InitializationError::StorageError)?,
    };

    Ok(())
}

fn check_chain_type<B: 'static + storage::Backend>(
    storage: &mut chainstate_storage::Store<B>,
    chain_config: &ChainConfig,
) -> Result<(), Error> {
    let storage_chain_type = storage.get_chain_type().map_err(InitializationError::StorageError)?;
    let chain_config_type = chain_config.chain_type().name();

    match storage_chain_type {
        Some(storage_chain_type) => ensure!(
            storage_chain_type == chain_config_type,
            InitializationError::ChainTypeMismatch(
                storage_chain_type,
                chain_config_type.to_owned()
            )
        ),
        None => storage
            .set_chain_type(chain_config_type)
            .map_err(InitializationError::StorageError)?,
    };

    Ok(())
}

/// Create chainstate together with its storage
pub fn make_chainstate(
    datadir: &std::path::Path,
    chain_config: Arc<ChainConfig>,
    config: ChainstateLauncherConfig,
) -> Result<Box<dyn ChainstateInterface>, Error> {
    let ChainstateLauncherConfig {
        storage_backend,
        chainstate_config,
    } = config;

    let lmdb_resize_callback = MapResizeCallback::new(Box::new(|resize_info| {
        logging::log::info!("Lmdb resize happened: {:?}", resize_info)
    }));

    // There is some code duplication because `make_chainstate_and_storage_impl` is called with
    // a different set of generic parameters in each case.
    match storage_backend {
        StorageBackendConfig::Lmdb => {
            let storage = storage_lmdb::Lmdb::new(
                datadir.join(SUBDIRECTORY_LMDB),
                Default::default(),
                Default::default(),
                lmdb_resize_callback,
            );
            make_chainstate_and_storage_impl(storage, chain_config, chainstate_config)
        }
        StorageBackendConfig::InMemory => {
            let storage = storage_inmemory::InMemory::new();
            make_chainstate_and_storage_impl(storage, chain_config, chainstate_config)
        }
    }
}
