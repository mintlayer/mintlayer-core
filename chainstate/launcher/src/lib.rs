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
mod storage_compatibility;

use std::sync::Arc;

use chainstate::InitializationError;
use chainstate_storage::Transactional;
use storage_lmdb::resize_callback::MapResizeCallback;

// Some useful reexports
pub use chainstate::{
    chainstate_interface::ChainstateInterface, ChainstateConfig, ChainstateError as Error,
    ChainstateSubsystem, DefaultTransactionVerificationStrategy,
};
pub use common::chain::ChainConfig;
pub use config::{ChainstateLauncherConfig, StorageBackendConfig};

/// Subdirectory under `datadir` where LMDB chainstate database is placed
pub const SUBDIRECTORY_LMDB: &str = "chainstate-lmdb";

pub use storage_compatibility::check_storage_compatibility;

fn make_chainstate_and_storage_impl<B: storage::SharedBackend + 'static>(
    storage_backend: B,
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
) -> Result<ChainstateSubsystem, Error> {
    let storage = chainstate_storage::Store::new(storage_backend, &chain_config)
        .map_err(|e| Error::FailedToInitializeChainstate(e.into()))?;

    let db_tx = storage
        .transaction_ro()
        .map_err(|e| Error::FailedToInitializeChainstate(e.into()))?;

    check_storage_compatibility(&db_tx, chain_config.as_ref())
        .map_err(InitializationError::StorageCompatibilityCheckError)?;
    drop(db_tx);

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

/// Create chainstate together with its storage
pub fn make_chainstate(
    datadir: &std::path::Path,
    chain_config: Arc<ChainConfig>,
    config: ChainstateLauncherConfig,
) -> Result<ChainstateSubsystem, Error> {
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
