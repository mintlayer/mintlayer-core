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

use std::io::BufRead;

use chainstate_types::BlockIndex;
use common::{chain::Block, primitives::id::WithId};
use serialization::{DecodeAll, Encode};

use crate::BlockError;

#[derive(thiserror::Error, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    #[error("File error: {0}")]
    FileError(String),
    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] serialization::Error),
    #[error("Block import error: {0}")]
    BlockImportError(#[from] BlockError),
}

impl From<std::io::Error> for BootstrapError {
    fn from(error: std::io::Error) -> Self {
        Self::FileError(error.to_string())
    }
}

pub fn import_bootstrap_stream<P, S: std::io::Read>(
    expected_magic_bytes: &[u8],
    file_reader: &mut std::io::BufReader<S>,
    process_block_func: &mut P,
) -> Result<(), BootstrapError>
where
    P: FnMut(WithId<Block>) -> Result<Option<BlockIndex>, BlockError>,
{
    const MIN_BUFFER_SIZE: usize = 1 << 22; // 4 MB

    // It's more reasonable to use a VeqDeque, but it's incompatible with the windows() method which is needed to search for magic bytes
    // There's a performance hit behind this, but we don't care. Anyone is free to optimize this.
    let mut buffer_queue = Vec::<u8>::new();

    loop {
        if buffer_queue.len() < MIN_BUFFER_SIZE {
            fill_buffer(&mut buffer_queue, file_reader)?;
        }

        let current_pos = buffer_queue
            .windows(expected_magic_bytes.len())
            .position(|window| window == expected_magic_bytes);
        let block = match current_pos {
            Some(v) => read_block_at_pos(&buffer_queue[v + expected_magic_bytes.len()..])?,
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
) -> Result<(), BootstrapError> {
    const MAX_BUFFER_SIZE: usize = 1 << 26; // 64 MB

    while buffer_queue.len() < MAX_BUFFER_SIZE {
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

fn read_block_at_pos(buf: &[u8]) -> Result<Block, BootstrapError> {
    let mut buffer = buf;
    let block = Block::decode_all(&mut buffer)?;
    Ok(block)
}
