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

use tokio::sync::watch;

use chainstate::InitializationError;
use chainstate_storage::{BlockchainStorage, BlockchainStorageBackend, Transactional};
use storage_lmdb::resize_callback::MapResizeCallback;
use utils::set_flag::SetFlag;

// Some useful reexports
pub use chainstate::{
    chainstate_interface::ChainstateInterface, ChainstateConfig, ChainstateError as Error,
    ChainstateSubsystem, DefaultTransactionVerificationStrategy,
};
pub use common::chain::ChainConfig;
pub use config::{ChainstateLauncherConfig, StorageBackendConfig};

pub use storage_compatibility::check_storage_compatibility;

/// Subdirectory under `datadir` where LMDB chainstate database is placed
pub const SUBDIRECTORY_LMDB: &str = "chainstate-lmdb";

pub type ChainstateMaker = Box<
    dyn FnOnce(
            /*shutdown_initiated_rx*/ Option<watch::Receiver<SetFlag>>,
        ) -> Result<ChainstateSubsystem, Error>
        + Send,
>;

/// Return a closure that will make the chainstate given the `shutdown_initiated_rx` parameter.
///
/// Note: the storage is created right away, so the corresponding errors (including compatibility
/// check failures) will cause `create_chainstate_maker` itself to fail and not the returned maker.
pub fn create_chainstate_maker(
    datadir: &std::path::Path,
    chain_config: Arc<ChainConfig>,
    config: ChainstateLauncherConfig,
) -> Result<ChainstateMaker, Error> {
    let ChainstateLauncherConfig {
        storage_backend,
        chainstate_config,
    } = config;

    let maker: ChainstateMaker = match storage_backend {
        StorageBackendConfig::Lmdb => {
            let storage = create_lmdb_storage(datadir, &chain_config)?;

            Box::new(|shutdown_initiated_rx| {
                make_chainstate_impl(
                    storage,
                    chain_config,
                    chainstate_config,
                    shutdown_initiated_rx,
                )
            })
        }
        StorageBackendConfig::InMemory => {
            let storage = create_inmemory_storage(&chain_config)?;

            Box::new(|shutdown_initiated_rx| {
                make_chainstate_impl(
                    storage,
                    chain_config,
                    chainstate_config,
                    shutdown_initiated_rx,
                )
            })
        }
    };

    Ok(maker)
}

fn make_chainstate_impl(
    storage: impl BlockchainStorage + Sync + 'static,
    chain_config: Arc<ChainConfig>,
    chainstate_config: ChainstateConfig,
    shutdown_initiated_rx: Option<watch::Receiver<SetFlag>>,
) -> Result<ChainstateSubsystem, Error> {
    chainstate::make_chainstate(
        chain_config,
        chainstate_config,
        storage,
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
        shutdown_initiated_rx,
    )
}

fn create_lmdb_storage(
    datadir: &std::path::Path,
    chain_config: &ChainConfig,
) -> Result<impl BlockchainStorage, Error> {
    let lmdb_resize_callback = MapResizeCallback::new(Box::new(|resize_info| {
        logging::log::info!("Lmdb resize happened: {:?}", resize_info)
    }));

    let backend = storage_lmdb::Lmdb::new(
        datadir.join(SUBDIRECTORY_LMDB),
        Default::default(),
        Default::default(),
        lmdb_resize_callback,
    );

    create_storage(backend, chain_config)
}

fn create_inmemory_storage(chain_config: &ChainConfig) -> Result<impl BlockchainStorage, Error> {
    create_storage(storage_inmemory::InMemory::new(), chain_config)
}

fn create_storage(
    storage_backend: impl BlockchainStorageBackend + 'static,
    chain_config: &ChainConfig,
) -> Result<impl BlockchainStorage, Error> {
    let storage = chainstate_storage::Store::new(storage_backend, chain_config)
        .map_err(|e| Error::FailedToInitializeChainstate(e.into()))?;

    let db_tx = storage
        .transaction_ro()
        .map_err(|e| Error::FailedToInitializeChainstate(e.into()))?;

    check_storage_compatibility(&db_tx, chain_config)
        .map_err(InitializationError::StorageCompatibilityCheckError)?;

    drop(db_tx);

    Ok(storage)
}
