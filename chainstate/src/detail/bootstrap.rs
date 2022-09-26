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

use std::io::{BufRead, Write};

use chainstate_storage::BlockchainStorageRead;
use chainstate_types::{BlockIndex, PropertyQueryError};
use common::{chain::Block, primitives::id::WithId};
use serialization::{Decode, Encode};

use crate::{BlockError, ChainstateConfig};

use super::{orphan_blocks::OrphanBlocks, query::ChainstateQuery};

const DEFAULT_MIN_IMPORT_BUFFER_SIZE: usize = 1 << 22; // 4 MB
const DEFAULT_MAX_IMPORT_BUFFER_SIZE: usize = 1 << 26; // 64 MB

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    #[error("File error: {0}")]
    File(String),
    #[error("Deserialization error: {0}")]
    Deserialization(#[from] serialization::Error),
    #[error("Block import error: {0}")]
    BlockProcessing(#[from] BlockError),
    #[error("Block import error: {0}")]
    FailedToReadProperty(#[from] PropertyQueryError),
}

impl From<std::io::Error> for BootstrapError {
    fn from(error: std::io::Error) -> Self {
        Self::File(error.to_string())
    }
}

pub fn import_bootstrap_stream<P, S: std::io::Read>(
    expected_magic_bytes: &[u8],
    file_reader: &mut std::io::BufReader<S>,
    process_block_func: &mut P,
    chainstate_config: &ChainstateConfig,
) -> Result<(), BootstrapError>
where
    P: FnMut(WithId<Block>) -> Result<Option<BlockIndex>, BlockError>,
{
    // min: The smallest buffer size, after which another read is triggered from the bootstrap file
    // max: The largest buffer size, after which reading the file is stopped
    // NOTE: both sizes MUST be larger than the largest block in the blockchain + 4 bytes for magic bytes
    let (min_buffer_size, max_buffer_size) =
        chainstate_config.min_max_bootstrap_import_buffer_sizes.unwrap_or((
            DEFAULT_MIN_IMPORT_BUFFER_SIZE,
            DEFAULT_MAX_IMPORT_BUFFER_SIZE,
        ));

    // It's more reasonable to use a VeqDeque, but it's incompatible with the windows() method which is needed to search for magic bytes
    // There's a performance hit behind this, but we don't care. Anyone is free to optimize this.
    let mut buffer_queue = Vec::<u8>::new();

    loop {
        if buffer_queue.len() < min_buffer_size {
            fill_buffer(&mut buffer_queue, file_reader, max_buffer_size)?;
        }

        // locate magic bytes to recognize the start of a block
        let current_pos = buffer_queue
            .windows(expected_magic_bytes.len())
            .position(|window| window == expected_magic_bytes);

        // read the block after the magic bytes
        let block = match current_pos {
            Some(v) => Block::decode(&mut &buffer_queue[v + expected_magic_bytes.len()..])?,
            None => break,
        };
        let block_len = block.encoded_size();
        process_block_func(block.into())?;

        // consume the buffer from the front
        buffer_queue = buffer_queue[expected_magic_bytes.len() + block_len..].to_vec();
    }

    Ok(())
}

fn fill_buffer<S: std::io::Read>(
    buffer_queue: &mut Vec<u8>,
    reader: &mut std::io::BufReader<S>,
    max_buffer_size: usize,
) -> Result<(), BootstrapError> {
    while buffer_queue.len() < max_buffer_size {
        let buf_len = {
            let data = reader.fill_buf()?;
            if data.is_empty() {
                break;
            }
            buffer_queue.extend(data.iter());
            data.len()
        };
        reader.consume(buf_len);
    }

    Ok(())
}

pub fn export_bootstrap_stream<'a, S: BlockchainStorageRead, O: OrphanBlocks>(
    magic_bytes: &[u8],
    writer: &mut std::io::BufWriter<Box<dyn std::io::Write + 'a + Send>>,
    include_orphans: bool,
    query_interface: &ChainstateQuery<'a, S, O>,
) -> Result<(), BootstrapError>
where
{
    let blocks_list = if include_orphans {
        query_interface.get_block_id_tree_as_list()?
    } else {
        query_interface.get_mainchain_blocks_list()?
    };

    for block_id in blocks_list {
        writer.write_all(magic_bytes)?;
        let block = query_interface
            .get_block(block_id)?
            .ok_or(PropertyQueryError::BlockNotFound(block_id))?;
        writer.write_all(&block.encode())?;
    }
    Ok(())
}
