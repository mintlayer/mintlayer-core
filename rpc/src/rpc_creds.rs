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

use anyhow::Context;
use crypto::random::{make_true_rng, CryptoRng, Rng};
use logging::log;

const COOKIE_PASSWORD_LEN: usize = 32;
const COOKIE_FILENAME: &str = ".cookie";
const COOKIE_USERNAME: &str = "__cookie__";

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
        use std::os::unix::prelude::OpenOptionsExt;
        options.mode(0o600);
    }

    options.create(true).write(true).open(&path)?.write_all(data.as_bytes())
}

impl RpcCreds {
    pub fn new(
        data_dir: &Path,
        username: Option<&str>,
        password: Option<&str>,
        cookie_file: Option<&str>,
    ) -> anyhow::Result<Self> {
        match (username, password) {
            (Some(username), Some(password)) => Ok(Self {
                username: username.to_owned(),
                password: password.to_owned(),
                cookie_file: None,
            }),

            (None, None) => {
                let username = COOKIE_USERNAME.to_owned();
                let password = gen_password(&mut make_true_rng(), COOKIE_PASSWORD_LEN);
                let cookie_file = match cookie_file {
                    Some(cookie_file) => cookie_file.into(),
                    None => data_dir.join(COOKIE_FILENAME),
                };
                let cookie = format!("{username}:{password}");

                write_file(&cookie_file, &cookie)
                    .with_context(|| format!("Failed to create cookie file {cookie_file:?}"))?;

                Ok(Self {
                    username,
                    password,
                    cookie_file: Some(cookie_file),
                })
            }

            _ => anyhow::bail!("both RPC username and password must be set"),
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
