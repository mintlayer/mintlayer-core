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

use crypto::random::{make_true_rng, CryptoRng, Rng};
use logging::log;

const COOKIE_PASSWORD_LEN: usize = 32;
const COOKIE_FILENAME: &str = ".cookie";
const COOKIE_USERNAME: &str = "__cookie__";

// TODO: Add support for hashed passwords (--rpcauth in Bitcoin Core)

pub struct RpcCreds {
    username: String,
    password: String,
    cookie_file: Option<PathBuf>,
}

fn gen_password<R: Rng + CryptoRng>(rng: &mut R, len: usize) -> String {
    rng.sample_iter(&crypto::random::distributions::Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn write_file(path: &Path, data: &str) -> Result<(), std::io::Error> {
    let mut options = std::fs::OpenOptions::new();

    #[cfg(unix)]
    {
        // Prevent other users from reading the file
        use std::os::unix::prelude::OpenOptionsExt;
        options.mode(0o600);
    }

    options.create(true).write(true).open(path)?.write_all(data.as_bytes())
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
        cookie_file: Option<&str>,
    ) -> Result<Self, RpcCredsError> {
        match (username, password) {
            (Some(username), Some(password)) => {
                utils::ensure!(
                    cookie_file.is_none(),
                    RpcCredsError::InvalidCookieFileConfig
                );
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

            (None, None) => {
                let username = COOKIE_USERNAME.to_owned();
                let password = gen_password(&mut make_true_rng(), COOKIE_PASSWORD_LEN);
                let cookie_file = match cookie_file {
                    Some(cookie_file) => cookie_file.into(),
                    None => data_dir.as_ref().join(COOKIE_FILENAME),
                };
                let cookie = format!("{username}:{password}");

                write_file(&cookie_file, &cookie)
                    .map_err(|e| RpcCredsError::CookieFileIoError(cookie_file.clone(), e))?;

                Ok(Self {
                    username,
                    password,
                    cookie_file: Some(cookie_file),
                })
            }

            _ => Err(RpcCredsError::InvalidUsernamePasswordConfig),
        }
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
