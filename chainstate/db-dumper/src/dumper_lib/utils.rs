// Copyright (c) 2021-2025 RBB S.r.l
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

use std::{path::PathBuf, sync::Arc};

use chainstate::{
    BlockIndex, ChainstateError, ChainstateSubsystem, DefaultTransactionVerificationStrategy,
};
use chainstate_launcher::check_storage_compatibility;
use chainstate_storage::Transactional as _;
use common::chain::{
    block::{consensus_data::PoSData, ConsensusData},
    ChainConfig,
};
use logging::log;
use storage_lmdb::resize_callback::MapResizeCallback;

use crate::Error;

pub fn write_eol(output: &mut impl std::io::Write) -> Result<(), Error> {
    writeln!(output).map_err(map_output_write_err)
}

pub fn write_comma_if_needed<T>(
    field_idx: usize,
    fields: &[T],
    output: &mut impl std::io::Write,
) -> Result<(), Error> {
    if field_idx + 1 != fields.len() {
        write!(output, ",").map_err(map_output_write_err)?;
    }

    Ok(())
}

pub fn map_output_write_err(err: std::io::Error) -> Error {
    Error::OutputWriteError(err.to_string())
}

pub fn create_chainstate(
    chain_config: Arc<ChainConfig>,
    db_path: PathBuf,
) -> Result<ChainstateSubsystem, Error> {
    let lmdb_resize_callback = MapResizeCallback::new(Box::new(|resize_info| {
        log::warn!("Lmdb resize happened: {:?}", resize_info)
    }));

    let storage_backend = storage_lmdb::Lmdb::new(
        db_path,
        Default::default(),
        Default::default(),
        lmdb_resize_callback,
    )
    .make_read_only();

    let storage = chainstate_storage::Store::from_backend(storage_backend)
        .map_err(|e| ChainstateError::FailedToInitializeChainstate(e.into()))?;

    {
        let db_tx = storage.transaction_ro().map_err(Error::StorageCreationError)?;
        check_storage_compatibility(&db_tx, chain_config.as_ref())?;
    }

    let chainstate = chainstate::make_chainstate(
        chain_config,
        Default::default(),
        storage,
        DefaultTransactionVerificationStrategy::new(),
        None,
        Default::default(),
    )?;

    Ok(chainstate)
}

pub fn get_pos_consensus_data(block_index: &BlockIndex) -> Result<&PoSData, Error> {
    match block_index.block_header().consensus_data() {
        ConsensusData::PoS(data) => Ok(data),
        ConsensusData::None | ConsensusData::PoW(_) => {
            Err(Error::NonPoSConsensusInBlock(*block_index.block_id()))
        }
    }
}
