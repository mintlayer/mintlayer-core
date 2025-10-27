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

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use chainstate::{chainstate_interface::ChainstateInterface, BlockIndex};
use chainstate_types::{BlockStatus, BlockValidationStage};
use common::{
    address::Address,
    chain::{self, config::ChainType, ChainConfig, Genesis},
    primitives::id::WithId,
    Uint256,
};
use logging::log;
use utils::ensure;

use crate::{
    utils::{
        create_chainstate, get_pos_consensus_data, map_output_write_err, write_comma_if_needed,
        write_eol,
    },
    BlockOutputField, Error,
};

// Note: this function will fail if the genesis id in the created chain config doesn't
// match the inferred one (i.e. the parent of the first block, this check is done inside
// Chainstate, search for the `GenesisMismatch` error). This means that Regtest/Signet chains
// with custom geneses are not supported ATM.
// TODO: perhaps we need a way to disable the genesis check in the chainstate.
pub fn dump_blocks_to_file(
    chain_type: ChainType,
    db_path: PathBuf,
    mainchain_only: bool,
    from_height: u64,
    fields: &[BlockOutputField],
    file_path: &Path,
) -> Result<(), Error> {
    let output = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(file_path)
        .map_err(|err| Error::CannotOpenOutputFile {
            error: err.to_string(),
        })?;
    // Note: unbuffered output is very slow.
    let mut output = std::io::BufWriter::new(output);

    let chain_config = Arc::new(chain::config::Builder::new(chain_type).build());
    let chainstate = create_chainstate(chain_config, db_path)?;

    dump_blocks_generic(
        &chainstate,
        mainchain_only,
        from_height,
        fields,
        &mut output,
    )
}

pub fn dump_blocks_generic(
    chainstate: &dyn ChainstateInterface,
    mainchain_only: bool,
    from_height: u64,
    fields: &[BlockOutputField],
    output: &mut impl std::io::Write,
) -> Result<(), Error> {
    if mainchain_only {
        log::info!("Dumping mainchain blocks only");
    } else {
        log::info!("Dumping all blocks");
    }

    let chain_config = chainstate.get_chain_config();

    let blocks_ids = if mainchain_only {
        chainstate.get_mainchain_blocks_list()?
    } else {
        chainstate.get_block_id_tree_as_list()?
    };

    write_header(fields, output)?;
    write_eol(output)?;

    if from_height == 0 {
        write_genesis(chain_config.genesis_block(), fields, output)?;
        write_eol(output)?;
    }

    let mut prev_block_height = 0;
    for (block_id_idx, block_id) in blocks_ids.iter().enumerate() {
        let block_index = chainstate
            .get_block_index_for_any_block(block_id)?
            .ok_or(Error::BlockIndexNotFound(*block_id))?;

        let cur_block_height = block_index.block_height().into_int();
        ensure!(
            cur_block_height == prev_block_height || cur_block_height == prev_block_height + 1,
            Error::UnexpectedBlockOrder {
                cur_block_height,
                prev_block_height
            }
        );

        if cur_block_height >= from_height {
            let is_mainchain =
                mainchain_only || chainstate.is_block_in_main_chain(block_id.into())?;
            let is_mainchain = if is_mainchain {
                IsMainchain::Yes
            } else {
                IsMainchain::No
            };
            write_block(&block_index, is_mainchain, fields, chain_config, output)?;

            if block_id_idx + 1 != blocks_ids.len() {
                write_eol(output)?;
            }
        }

        prev_block_height = cur_block_height;
    }

    Ok(())
}

#[derive(Eq, PartialEq, Debug, Copy, Clone, strum::Display)]
pub enum IsMainchain {
    #[strum(serialize = "y")]
    Yes,

    #[strum(serialize = "n")]
    No,
}

#[derive(Eq, PartialEq, Debug, Copy, Clone, strum::Display, strum::EnumIter)]
pub enum BlockStatusOutput {
    #[strum(serialize = "b")]
    Bad,

    #[strum(serialize = "u")]
    Unchecked,

    #[strum(serialize = "p")]
    PartiallyChecked,

    #[strum(serialize = "g")]
    Good,
}

impl BlockStatusOutput {
    fn from(status: BlockStatus) -> Self {
        if !status.is_ok() {
            Self::Bad
        } else {
            match status.last_valid_stage() {
                BlockValidationStage::Unchecked => Self::Unchecked,
                BlockValidationStage::CheckBlockOk => Self::PartiallyChecked,
                BlockValidationStage::FullyChecked => Self::Good,
            }
        }
    }
}

fn write_header(
    fields: &[BlockOutputField],
    output: &mut impl std::io::Write,
) -> Result<(), Error> {
    for (idx, field) in fields.iter().enumerate() {
        write!(output, "{field}").map_err(map_output_write_err)?;
        write_comma_if_needed(idx, fields, output)?;
    }

    Ok(())
}

fn write_genesis(
    genesis: &WithId<Genesis>,
    fields: &[BlockOutputField],
    output: &mut impl std::io::Write,
) -> Result<(), Error> {
    for (idx, field) in fields.iter().enumerate() {
        match field {
            BlockOutputField::Height => write!(output, "0"),
            BlockOutputField::IsMainchain => write!(output, "{}", IsMainchain::Yes),
            BlockOutputField::Id => write!(output, "{:x}", WithId::id(genesis)),
            BlockOutputField::Timestamp => {
                write!(output, "{}", genesis.timestamp().as_int_seconds())
            }
            BlockOutputField::Status => write!(output, "{}", BlockStatusOutput::Good),
            BlockOutputField::PoolId
            | BlockOutputField::Target
            | BlockOutputField::ChainTrust
            | BlockOutputField::ParentId => write!(output, "-"),
        }
        .map_err(map_output_write_err)?;

        write_comma_if_needed(idx, fields, output)?;
    }

    Ok(())
}

fn write_block(
    block_index: &BlockIndex,
    is_mainchain: IsMainchain,
    fields: &[BlockOutputField],
    chain_config: &ChainConfig,
    output: &mut impl std::io::Write,
) -> Result<(), Error> {
    for (idx, field) in fields.iter().enumerate() {
        match field {
            BlockOutputField::Height => write!(output, "{}", block_index.block_height().into_int()),
            BlockOutputField::IsMainchain => write!(output, "{is_mainchain}"),
            BlockOutputField::Id => write!(output, "{:x}", block_index.block_id()),
            BlockOutputField::Timestamp => {
                write!(output, "{}", block_index.block_timestamp().as_int_seconds())
            }
            BlockOutputField::Status => {
                write!(output, "{}", BlockStatusOutput::from(block_index.status()))
            }
            BlockOutputField::PoolId => {
                let pool_id = get_pos_consensus_data(block_index)?.stake_pool_id();
                let pool_id_str = Address::new(chain_config, *pool_id)
                    .map_err(Error::AddressConstructionError)?
                    .into_string();
                write!(output, "{pool_id_str}")
            }
            BlockOutputField::Target => {
                let compact_target = get_pos_consensus_data(block_index)?.compact_target();
                let target = Uint256::try_from(compact_target)
                    .map_err(|_| Error::BlockCompactTargetUnpackingError(compact_target))?;
                write!(output, "{target:x}")
            }
            BlockOutputField::ChainTrust => write!(output, "{:x}", block_index.chain_trust()),
            BlockOutputField::ParentId => write!(output, "{:x}", block_index.prev_block_id()),
        }
        .map_err(map_output_write_err)?;

        write_comma_if_needed(idx, fields, output)?;
    }

    Ok(())
}
