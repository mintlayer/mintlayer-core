// Copyright (c) 2025 RBB S.r.l
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
    collections::BTreeMap,
    path::{Path, PathBuf},
    str::FromStr as _,
};

use common::{
    chain::GenBlock,
    primitives::{BlockHeight, Id, H256},
};
use utils::ensure;

pub fn read_checkpoints_from_csv_file(
    csv_file: &Path,
) -> Result<BTreeMap<BlockHeight, Id<GenBlock>>, CheckpontsFromCsvReadError> {
    let file =
        std::fs::File::open(csv_file).map_err(|err| CheckpontsFromCsvReadError::FileOpenError {
            file: csv_file.to_owned(),
            error: err.to_string(),
        })?;

    read_checkpoints_from_csv(file)
}

pub fn read_checkpoints_from_csv(
    csv: impl std::io::Read,
) -> Result<BTreeMap<BlockHeight, Id<GenBlock>>, CheckpontsFromCsvReadError> {
    // Note: flexible(true) means that lines with different field counts are allowed.
    // Our fields count is fixed to 2 and we only specify this to simplify the tests, where
    // we check for specific errors.
    let mut reader = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(csv);
    let expected_fields_count = 2;

    let mut checkpoints = BTreeMap::new();

    for (record_idx, result) in reader.records().enumerate() {
        let record = result.map_err(|err| CheckpontsFromCsvReadError::RecordReadError {
            error: err.to_string(),
        })?;

        ensure!(
            record.len() == expected_fields_count,
            CheckpontsFromCsvReadError::UnexpectedFieldsCount {
                record_idx,
                actual_fields_count: record.len(),
                expected_fields_count
            }
        );

        let block_height = record
            .get(0)
            .expect("field is known to be present")
            .parse::<u64>()
            .map_err(|_| CheckpontsFromCsvReadError::BadBlockHeight { record_idx })?;

        let block_id = H256::from_str(record.get(1).expect("field is known to be present"))
            .map_err(|_| CheckpontsFromCsvReadError::BadBlockId { record_idx })?;

        let already_existed =
            checkpoints.insert(BlockHeight::new(block_height), Id::new(block_id)).is_some();
        ensure!(
            !already_existed,
            CheckpontsFromCsvReadError::DuplicateCheckpoint {
                height: block_height
            }
        );
    }

    Ok(checkpoints)
}

#[derive(thiserror::Error, Clone, Debug, Eq, PartialEq)]
pub enum CheckpontsFromCsvReadError {
    #[error("Cannon open file '{file}': {error}")]
    FileOpenError { file: PathBuf, error: String },

    #[error("Error reading a record: {error}")]
    RecordReadError { error: String },

    #[error("Unexpected fields count in record {record_idx}: expected {expected_fields_count}, got {actual_fields_count}")]
    UnexpectedFieldsCount {
        record_idx: usize,
        actual_fields_count: usize,
        expected_fields_count: usize,
    },

    #[error("Bad block height in record {record_idx}")]
    BadBlockHeight { record_idx: usize },

    #[error("Bad block id in record {record_idx}")]
    BadBlockId { record_idx: usize },

    #[error("Duplicate checkpoint at height {height}")]
    DuplicateCheckpoint { height: u64 },
}

#[cfg(test)]
mod tests {
    use utils::concatln;

    use super::*;

    #[test]
    fn correct_read() {
        let mk_id = |id_str| Id::new(H256::from_str(id_str).unwrap());
        let data = concatln!(
            "500, C91C3DB7DFDCC296010546EC38F48A557D035DD0B34260BD6C5174709F8A7EB0",
            "1000, 1DCFB22374DA757882EEF26AF2B2D3ABDD1A4887C744346F6413C8D0B51DEBDF",
            "1500, 3F81279C128FF628C8F4055DF89173DDAA6597DAB7636E8B12CA386E7864DFE9"
        );
        let expected_checkpoints = BTreeMap::from([
            (
                BlockHeight::new(500),
                mk_id("C91C3DB7DFDCC296010546EC38F48A557D035DD0B34260BD6C5174709F8A7EB0"),
            ),
            (
                BlockHeight::new(1000),
                mk_id("1DCFB22374DA757882EEF26AF2B2D3ABDD1A4887C744346F6413C8D0B51DEBDF"),
            ),
            (
                BlockHeight::new(1500),
                mk_id("3F81279C128FF628C8F4055DF89173DDAA6597DAB7636E8B12CA386E7864DFE9"),
            ),
        ]);

        let checkpoints = read_checkpoints_from_csv(data.as_bytes()).unwrap();
        assert_eq!(checkpoints, expected_checkpoints);

        // Now write the csv to file and read it via `read_checkpoints_from_csv_file`.
        let temp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), data.as_bytes()).unwrap();
        let checkpoints_from_file = read_checkpoints_from_csv_file(temp_file.path()).unwrap();
        assert_eq!(checkpoints_from_file, expected_checkpoints);
    }

    #[test]
    fn bad_fields_count() {
        let data1 = concatln!(
            "500, C91C3DB7DFDCC296010546EC38F48A557D035DD0B34260BD6C5174709F8A7EB0",
            "1000, 1DCFB22374DA757882EEF26AF2B2D3ABDD1A4887C744346F6413C8D0B51DEBDF, 111",
            "1500, 3F81279C128FF628C8F4055DF89173DDAA6597DAB7636E8B12CA386E7864DFE9"
        );
        let err = read_checkpoints_from_csv(data1.as_bytes()).unwrap_err();
        assert_eq!(
            err,
            CheckpontsFromCsvReadError::UnexpectedFieldsCount {
                record_idx: 1,
                actual_fields_count: 3,
                expected_fields_count: 2
            }
        );

        let data1 = concatln!(
            "500, C91C3DB7DFDCC296010546EC38F48A557D035DD0B34260BD6C5174709F8A7EB0",
            "1000",
            "1500, 3F81279C128FF628C8F4055DF89173DDAA6597DAB7636E8B12CA386E7864DFE9"
        );
        let err = read_checkpoints_from_csv(data1.as_bytes()).unwrap_err();
        assert_eq!(
            err,
            CheckpontsFromCsvReadError::UnexpectedFieldsCount {
                record_idx: 1,
                actual_fields_count: 1,
                expected_fields_count: 2
            }
        );
    }

    #[test]
    fn bad_block_height() {
        let data = concatln!(
            "500, C91C3DB7DFDCC296010546EC38F48A557D035DD0B34260BD6C5174709F8A7EB0",
            "X000, 1DCFB22374DA757882EEF26AF2B2D3ABDD1A4887C744346F6413C8D0B51DEBDF",
            "1500, 3F81279C128FF628C8F4055DF89173DDAA6597DAB7636E8B12CA386E7864DFE9"
        );
        let err = read_checkpoints_from_csv(data.as_bytes()).unwrap_err();
        assert_eq!(
            err,
            CheckpontsFromCsvReadError::BadBlockHeight { record_idx: 1 }
        );
    }

    #[test]
    fn bad_block_id() {
        let data = concatln!(
            "500, C91C3DB7DFDCC296010546EC38F48A557D035DD0B34260BD6C5174709F8A7EB0",
            "1000, XDCFB22374DA757882EEF26AF2B2D3ABDD1A4887C744346F6413C8D0B51DEBDF",
            "1500, 3F81279C128FF628C8F4055DF89173DDAA6597DAB7636E8B12CA386E7864DFE9"
        );
        let err = read_checkpoints_from_csv(data.as_bytes()).unwrap_err();
        assert_eq!(
            err,
            CheckpontsFromCsvReadError::BadBlockId { record_idx: 1 }
        );
    }

    #[test]
    fn duplicate_checkpoint() {
        let data = concatln!(
            "500, C91C3DB7DFDCC296010546EC38F48A557D035DD0B34260BD6C5174709F8A7EB0",
            "500, 1DCFB22374DA757882EEF26AF2B2D3ABDD1A4887C744346F6413C8D0B51DEBDF",
            "1500, 3F81279C128FF628C8F4055DF89173DDAA6597DAB7636E8B12CA386E7864DFE9"
        );
        let err = read_checkpoints_from_csv(data.as_bytes()).unwrap_err();
        assert_eq!(
            err,
            CheckpontsFromCsvReadError::DuplicateCheckpoint { height: 500 }
        );
    }
}
