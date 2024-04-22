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

use std::{
    io::Write,
    path::{Path, PathBuf},
};

use logging::log;
use randomness::{distributions::DistString, make_true_rng, CryptoRng, Rng};
use utils::cookie::COOKIE_FILENAME;

const COOKIE_PASSWORD_LEN: usize = 32;
const COOKIE_USERNAME: &str = "__cookie__";

// TODO: Add support for hashed passwords (--rpcauth in Bitcoin Core)

pub struct RpcCreds {
    username: String,
    password: String,
    cookie_file: Option<PathBuf>,
}

fn gen_password(rng: &mut (impl Rng + CryptoRng), len: usize) -> String {
    randomness::distributions::Alphanumeric.sample_string(rng, len)
}

fn write_file_atomically(path: &Path, data: &str) -> Result<(), std::io::Error> {
    let path_tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();

    #[cfg(unix)]
    {
        // Prevent other users from reading the file
        use std::os::unix::prelude::OpenOptionsExt;
        options.mode(0o600);
    }

    options.create(true).write(true).open(&path_tmp)?.write_all(data.as_bytes())?;

    std::fs::rename(path_tmp, path)
}

#[derive(thiserror::Error, Debug)]
pub enum RpcCredsError {
    #[error("Cookie file cannot be used with username/password")]
    InvalidCookieFileConfig,
    #[error("Invalid symbol '{0}' in RPC username")]
    InvalidSymbolsInUsername(char),
    #[error("Failed to create cookie file: {0}: {1}")]
    CookieFileIoError(PathBuf, std::io::Error),
    #[error("Both RPC username and password must be set or unset, together")]
    InvalidUsernamePasswordConfig,
}

impl RpcCreds {
    pub fn new(
        data_dir: impl AsRef<Path>,
        username: Option<impl AsRef<str>>,
        password: Option<impl AsRef<str>>,
        cookie_file: Option<impl AsRef<str>>,
    ) -> Result<Self, RpcCredsError> {
        match (username, password) {
            (Some(username), Some(password)) => {
                utils::ensure!(
                    cookie_file.is_none(),
                    RpcCredsError::InvalidCookieFileConfig
                );
                Self::basic(username, password)
            }

            (None, None) => {
                let cookie_file = match cookie_file {
                    Some(cookie_file) => cookie_file.as_ref().into(),
                    None => data_dir.as_ref().join(COOKIE_FILENAME),
                };
                Self::cookie_file(cookie_file)
            }

            _ => Err(RpcCredsError::InvalidUsernamePasswordConfig),
        }
    }

    pub fn cookie_file(cookie_file: PathBuf) -> Result<Self, RpcCredsError> {
        let username = COOKIE_USERNAME.to_owned();
        let password = gen_password(&mut make_true_rng(), COOKIE_PASSWORD_LEN);
        let cookie = format!("{username}:{password}");

        write_file_atomically(&cookie_file, &cookie)
            .map_err(|e| RpcCredsError::CookieFileIoError(cookie_file.clone(), e))?;

        Ok(Self {
            username,
            password,
            cookie_file: Some(cookie_file),
        })
    }

    pub fn basic(
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<Self, RpcCredsError> {
        utils::ensure!(
            username.as_ref().find(':').is_none(),
            RpcCredsError::InvalidSymbolsInUsername(':')
        );
        Ok(Self {
            username: username.as_ref().to_owned(),
            password: password.as_ref().to_owned(),
            cookie_file: None,
        })
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        &self.password
    }
}

impl Drop for RpcCreds {
    fn drop(&mut self) {
        if let Some(cookie_file) = &self.cookie_file {
            let res = std::fs::remove_file(cookie_file);
            if let Err(e) = res {
                log::error!("removing cookie file {cookie_file:?} failed: {e}");
            }
        }
    }
}
