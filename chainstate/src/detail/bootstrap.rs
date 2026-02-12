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

use strum::IntoEnumIterator;

use chainstate_storage::BlockchainStorageRead;
use chainstate_types::PropertyQueryError;
use common::{
    chain::{
        config::{ChainType, MagicBytes},
        Block, ChainConfig,
    },
    primitives::id::WithId,
};
use serialization::{Decode, DecodeAll as _, Encode};
use utils::ensure;

use crate::BlockError;

use super::{query::ChainstateQuery, tx_verification_strategy::TransactionVerificationStrategy};

// Note: bootstrapping used to have a legacy format, where the file didn't have any header and
// blocks were written one by one, prepended by the chain magic bytes corresponding to the
// appropriate chain. This format is no longer supported, the `BootstrapFileSubHeaderV0` struct
// below refers to version 0 of the new format.

const FILE_MAGIC_BYTES: &[u8; 8] = b"MLBTSTRP";

/// The bootstrap file will always start with this header (SCALE-encoded).
#[derive(Encode, Decode)]
struct BootstrapFileHeader {
    /// This must be equal to FILE_MAGIC_BYTES
    pub file_magic_bytes: [u8; 8],
    /// Magic bytes of the chain this file belongs to.
    pub chain_magic_bytes: MagicBytes,
    /// This specifies the version of the file format and determines what
    /// will go after the header.
    pub file_format_version: u32,
    /// The number of blocks in the file.
    pub blocks_count: u64,
}

const FILE_HEADER_SIZE: usize = 24;

// In format v0, blocks go directly after the header, each block preceded by its length
// represented as a little-endian `u32`.

type BlockSizeType = u32;

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum BootstrapError {
    #[error("Block storage error: `{0}`")]
    StorageError(#[from] chainstate_storage::Error),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(#[from] serialization::Error),

    #[error("Block import error: {0}")]
    BlockProcessing(#[from] BlockError),

    #[error("Property query error: {0}")]
    FailedToReadProperty(#[from] PropertyQueryError),

    // Note: integer conversions shouldn't happen here, so we don't bother including
    // extra info in the error.
    #[error(transparent)]
    TryFromIntError(#[from] std::num::TryFromIntError),

    #[error("Legacy file format no longer supported")]
    LegacyFileFormat,

    #[error("File too small")]
    FileTooSmall,

    #[error("Wrong file format")]
    WrongFileFormat,

    #[error("Bad file format")]
    BadFileFormat,

    #[error("This file belongs to a different chain")]
    WrongChain,

    #[error(
        "This seems to be some future version of bootstrap file that is not supported by this node"
    )]
    UnsupportedFutureFormatVersion,
}

impl From<std::io::Error> for BootstrapError {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error.to_string())
    }
}

/// Import blocks from the provided bootstrap stream.
///
/// `process_block_func` must return true if importing should continue and false if it should
/// stop.
pub fn import_bootstrap_stream<P, S: std::io::Read>(
    chain_config: &ChainConfig,
    file_reader: &mut std::io::BufReader<S>,
    process_block_func: &mut P,
) -> Result<(), BootstrapError>
where
    P: FnMut(WithId<Block>) -> Result<bool, BootstrapError>,
{
    let mut buffer_queue = Vec::<u8>::with_capacity(1024 * 1024);

    let header = {
        fill_buffer(&mut buffer_queue, file_reader, FILE_HEADER_SIZE)?;
        ensure!(
            buffer_queue.len() == FILE_HEADER_SIZE,
            BootstrapError::FileTooSmall
        );
        check_for_legacy_format(&buffer_queue)?;

        BootstrapFileHeader::decode_all(&mut buffer_queue.as_slice())?
    };

    buffer_queue.clear();

    ensure!(
        &header.file_magic_bytes == FILE_MAGIC_BYTES,
        BootstrapError::WrongFileFormat
    );
    ensure!(
        &header.chain_magic_bytes == chain_config.magic_bytes(),
        BootstrapError::WrongChain
    );
    ensure!(
        header.file_format_version == 0,
        BootstrapError::UnsupportedFutureFormatVersion
    );

    for _ in 0..header.blocks_count {
        fill_buffer(&mut buffer_queue, file_reader, size_of::<BlockSizeType>())?;
        ensure!(
            buffer_queue.len() == size_of::<BlockSizeType>(),
            BootstrapError::BadFileFormat
        );
        let block_size = BlockSizeType::from_le_bytes(
            buffer_queue
                .as_slice()
                .try_into()
                .expect("Buffer is known to have the correct size"),
        )
        .try_into()?;
        buffer_queue.clear();

        fill_buffer(&mut buffer_queue, file_reader, block_size)?;
        ensure!(
            buffer_queue.len() == block_size,
            BootstrapError::BadFileFormat
        );

        let block = Block::decode_all(&mut buffer_queue.as_slice())?;
        let should_continue = process_block_func(block.into())?;
        buffer_queue.clear();

        if !should_continue {
            break;
        }
    }

    Ok(())
}

fn check_for_legacy_format(header_bytes: &[u8]) -> Result<(), BootstrapError> {
    // In the legacy format the file starts with magic bytes of the corresponding chain.
    for chain_type in ChainType::iter() {
        if header_bytes.starts_with(&chain_type.magic_bytes().bytes()) {
            return Err(BootstrapError::LegacyFileFormat);
        }
    }
    Ok(())
}

fn fill_buffer<S: std::io::Read>(
    buffer_queue: &mut Vec<u8>,
    reader: &mut std::io::BufReader<S>,
    max_buffer_size: usize,
) -> Result<(), BootstrapError> {
    while buffer_queue.len() < max_buffer_size {
        let data = reader.fill_buf()?;
        if data.is_empty() {
            break;
        }

        let remaining_len = max_buffer_size - buffer_queue.len();
        let len_to_consume = std::cmp::min(remaining_len, data.len());
        buffer_queue.extend_from_slice(&data[..len_to_consume]);
        reader.consume(len_to_consume);
    }

    Ok(())
}

pub fn export_bootstrap_stream<'a, S: BlockchainStorageRead, V: TransactionVerificationStrategy>(
    chain_config: &ChainConfig,
    writer: &mut std::io::BufWriter<Box<dyn Write + Send + 'a>>,
    include_stale_blocks: bool,
    query_interface: &ChainstateQuery<'a, S, V>,
) -> Result<(), BootstrapError>
where
{
    let blocks_list = if include_stale_blocks {
        query_interface.get_block_id_tree_as_list()?
    } else {
        query_interface.get_mainchain_blocks_list()?
    };

    let header = BootstrapFileHeader {
        file_magic_bytes: *FILE_MAGIC_BYTES,
        chain_magic_bytes: *chain_config.magic_bytes(),
        file_format_version: 0,
        blocks_count: blocks_list.len().try_into()?,
    };

    header.encode_to(writer);

    for block_id in blocks_list {
        let encoded_block = query_interface.get_encoded_existing_block(&block_id)?;
        let block_size: BlockSizeType = encoded_block.len().try_into()?;
        writer.write_all(block_size.to_le_bytes().as_slice())?;
        writer.write_all(&encoded_block)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use randomness::Rng as _;
    use test_utils::random::{make_seedable_rng, Seed};

    use super::*;

    // Check that BootstrapFileHeader's encoded size if is always FILE_HEADER_SIZE, no matter the contents.
    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    fn header_encoding_size(#[case] seed: Seed) {
        for _ in 0..100 {
            let mut rng = make_seedable_rng(seed);

            {
                let header = BootstrapFileHeader {
                    file_magic_bytes: rng.gen(),
                    chain_magic_bytes: MagicBytes::new(rng.gen()),
                    file_format_version: rng.gen(),
                    blocks_count: rng.gen(),
                };

                let encoded_size = header.encoded_size();
                assert_eq!(encoded_size, FILE_HEADER_SIZE);
            }
        }
    }
}
