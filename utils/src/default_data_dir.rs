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
/// 1. If no data directory is specified, use the default data directory provided by default_data_dir_getter.
///    By default, the directory doesn't have to exist; it will be automatically created if it doesn't.
/// 2. If a custom data directory is specified, it's expected to exist by default. An error is returned if it doesn't.
///
/// Additionally, `create_data_dir_if_missing` allows to override the default behavior.
pub fn prepare_data_dir<F: Fn() -> PathBuf>(
    default_data_dir_getter: F,
    datadir_path_opt: Option<&PathBuf>,
    create_data_dir_if_missing: Option<bool>,
) -> Result<PathBuf, PrepareDataDirError> {
    let (data_dir, create_if_missing_default) = match datadir_path_opt {
        Some(data_dir) => (data_dir.clone(), false),
        None => (default_data_dir_getter(), true),
    };

    let create_data_dir_if_missing =
        create_data_dir_if_missing.unwrap_or(create_if_missing_default);

    if !data_dir.exists() {
        if create_data_dir_if_missing {
            std::fs::create_dir_all(data_dir.clone())
                .map_err(|e| PrepareDataDirError::CreateFailed(data_dir.clone(), e))?;
        } else {
            return Err(PrepareDataDirError::DoesNotExist(data_dir.clone()));
        }
    }

    Ok(data_dir)
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};

    use randomness::{make_pseudo_rng, Rng};
    use tempfile::TempDir;

    use super::*;

    fn test_file_data(file_path: &std::path::Path, expected_contents: &[u8]) {
        let mut file = std::fs::File::open(file_path).unwrap();
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).unwrap();
        assert_eq!(buffer, expected_contents);
    }

    #[test]
    fn default_data_dir_preparation() {
        let base_dir = TempDir::new().unwrap();
        let supposed_default_dir = base_dir.path().join("supposed_default");

        let default_data_dir_getter = || supposed_default_dir.clone();

        // Ensure path doesn't exist beforehand
        assert!(!supposed_default_dir.is_dir());

        // The call must fail if create_data_dir_if_missing is explicitly set to false.
        let _err = prepare_data_dir(default_data_dir_getter, None, Some(false)).unwrap_err();

        // With create_data_dir_if_missing equal to None or true, the call must succeed.
        let returned_data_dir1 = prepare_data_dir(default_data_dir_getter, None, None).unwrap();
        let returned_data_dir2 =
            prepare_data_dir(default_data_dir_getter, None, Some(true)).unwrap();
        assert_eq!(returned_data_dir1, returned_data_dir2);

        // The default directory must be returned.
        assert_eq!(
            returned_data_dir1.canonicalize().unwrap(),
            supposed_default_dir.canonicalize().unwrap()
        );

        // We also expect the directory to exist
        assert!(supposed_default_dir.is_dir());

        // Now let's use the data directory
        let file_path = supposed_default_dir.join("SomeFile.txt");
        let file_data: Vec<u8> = (0..1024).map(|_| make_pseudo_rng().gen::<u8>()).collect();
        {
            let mut file = std::fs::File::create(&file_path).unwrap();
            file.write_all(&file_data).unwrap();
        }

        test_file_data(&file_path, &file_data);

        // Now we prepare again, and ensure that our file is unchanged
        let returned_data_dir1 = prepare_data_dir(default_data_dir_getter, None, None).unwrap();
        let returned_data_dir2 =
            prepare_data_dir(default_data_dir_getter, None, Some(true)).unwrap();
        let returned_data_dir3 =
            prepare_data_dir(default_data_dir_getter, None, Some(false)).unwrap();
        assert_eq!(returned_data_dir1, returned_data_dir2);
        assert_eq!(returned_data_dir1, returned_data_dir3);

        // Same path is returned
        assert_eq!(
            returned_data_dir1.canonicalize().unwrap(),
            supposed_default_dir.canonicalize().unwrap()
        );

        test_file_data(&file_path, &file_data);
    }

    #[test]
    fn custom_data_dir_preparation() {
        let base_dir = TempDir::new().unwrap();
        let supposed_default_dir = base_dir.path().join("supposed_default");
        let supposed_custom_dir = base_dir.path().join("supposed_custom");

        let default_data_dir_getter = || supposed_default_dir.clone();

        // Both default and custom directories don't exist beforehand
        assert!(!supposed_default_dir.is_dir());
        assert!(!supposed_custom_dir.is_dir());

        // The calls fail because the directory doesn't exist
        let _err = prepare_data_dir(default_data_dir_getter, Some(&supposed_custom_dir), None)
            .unwrap_err();
        let _err = prepare_data_dir(
            default_data_dir_getter,
            Some(&supposed_custom_dir),
            Some(false),
        )
        .unwrap_err();

        // Nothing has changed after the calls
        assert!(!supposed_default_dir.is_dir());
        assert!(!supposed_custom_dir.is_dir());

        // Now set create_data_dir_if_missing to true, the directory should be created.
        let returned_data_dir = prepare_data_dir(
            default_data_dir_getter,
            Some(&supposed_custom_dir),
            Some(true),
        )
        .unwrap();

        // The custom directory should be returned.
        assert_eq!(
            returned_data_dir.canonicalize().unwrap(),
            supposed_custom_dir.canonicalize().unwrap()
        );

        // The custom directory must exist.
        assert!(!supposed_default_dir.is_dir());
        assert!(supposed_custom_dir.is_dir());

        // Passing None or false for create_data_dir_if_missing now also works, because the directory
        // already exists.
        let returned_data_dir1 =
            prepare_data_dir(default_data_dir_getter, Some(&supposed_custom_dir), None).unwrap();
        let returned_data_dir2 = prepare_data_dir(
            default_data_dir_getter,
            Some(&supposed_custom_dir),
            Some(false),
        )
        .unwrap();
        assert_eq!(returned_data_dir1, returned_data_dir2);

        // The custom directory should be returned.
        assert_eq!(
            returned_data_dir1.canonicalize().unwrap(),
            supposed_custom_dir.canonicalize().unwrap()
        );

        // Last state of directories didn't change
        assert!(!supposed_default_dir.is_dir());
        assert!(supposed_custom_dir.is_dir());

        // Now let's use the data directory
        let file_path = supposed_custom_dir.join("SomeFile.txt");
        let file_data: Vec<u8> = (0..1024).map(|_| make_pseudo_rng().gen::<u8>()).collect();
        {
            let mut file = std::fs::File::create(&file_path).unwrap();
            file.write_all(&file_data).unwrap();
        }

        test_file_data(&file_path, &file_data);

        // Now we prepare again, and ensure that our file is unchanged
        let returned_data_dir1 =
            prepare_data_dir(default_data_dir_getter, Some(&supposed_custom_dir), None).unwrap();
        let returned_data_dir2 = prepare_data_dir(
            default_data_dir_getter,
            Some(&supposed_custom_dir),
            Some(false),
        )
        .unwrap();
        let returned_data_dir3 = prepare_data_dir(
            default_data_dir_getter,
            Some(&supposed_custom_dir),
            Some(true),
        )
        .unwrap();
        assert_eq!(returned_data_dir1, returned_data_dir2);
        assert_eq!(returned_data_dir1, returned_data_dir3);

        // Same path is returned
        assert_eq!(
            returned_data_dir1.canonicalize().unwrap(),
            supposed_custom_dir.canonicalize().unwrap()
        );

        test_file_data(&file_path, &file_data);
    }
}
