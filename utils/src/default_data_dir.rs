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

use std::path::PathBuf;

use directories::{BaseDirs, UserDirs};

const DATA_DIR_NAME_WIN_MAC: &str = "Mintlayer";
const DATA_DIR_NAME_NIX: &str = ".mintlayer";

pub fn default_data_dir_common() -> PathBuf {
    // Windows: C:\Users\Username\AppData\Roaming\Mintlayer
    // macOS: ~/Library/Application Support/Mintlayer
    // Unix-like: ~/.mintlayer
    if cfg!(target_os = "macos") || cfg!(target_os = "windows") {
        BaseDirs::new()
            .expect("Unable to get project directory")
            .data_dir()
            .join(DATA_DIR_NAME_WIN_MAC)
    } else {
        UserDirs::new()
            // Expect here is OK because `Parser::parse_from` panics anyway in case of error.
            .expect("Unable to get home directory")
            .home_dir()
            .join(DATA_DIR_NAME_NIX)
    }
}

pub fn default_data_dir_for_chain(chain_name: &str) -> PathBuf {
    default_data_dir_common().join(chain_name)
}

#[derive(thiserror::Error, Debug)]
pub enum PrepareDataDirError {
    #[error("Custom data directory '{0}' does not exist. Please create it or use the default data directory.")]
    DoesNotExist(PathBuf),
    #[error("Failed to create the '{0}' data directory: {1}")]
    CreateFailed(PathBuf, std::io::Error),
}

/// Prepare data directory for the node.
/// Two possibilities:
/// 1. If no data directory is specified, use the default data directory provided by default_data_dir_getter;
///    it doesn't have to exist. It will be automatically created.
/// 2. If a custom data directory is specified, it MUST exist. Otherwise, an error is returned.
pub fn prepare_data_dir<F: Fn() -> PathBuf>(
    default_data_dir_getter: F,
    datadir_path_opt: &Option<PathBuf>,
) -> Result<PathBuf, PrepareDataDirError> {
    let data_dir = match datadir_path_opt {
        Some(data_dir) => {
            if !data_dir.exists() {
                return Err(PrepareDataDirError::DoesNotExist(data_dir.clone()));
            }
            data_dir.clone()
        }
        None => {
            std::fs::create_dir_all(default_data_dir_getter())
                .map_err(|e| PrepareDataDirError::CreateFailed(default_data_dir_getter(), e))?;
            default_data_dir_getter()
        }
    };
    Ok(data_dir)
}
