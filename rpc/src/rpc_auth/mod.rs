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

use std::num::NonZeroUsize;

use anyhow::anyhow;
use base64::Engine;
use crypto::{
    kdf::{argon2::Argon2Config, hash_password, verify_password, KdfConfig, KdfResult},
    random::make_true_rng,
    util::eq::SliceEqualityCheckMethod,
};
use hyper::{Body, Request, Response};
use tower_http::auth::AuthorizeRequest;

#[derive(Clone)]
pub struct RpcAuth {
    username: String,
    password_hash: KdfResult,
}

const RPC_KDF_CONFIG: KdfConfig = KdfConfig::Argon2id {
    config: Argon2Config {
        m_cost_memory_size: 200,
        t_cost_iterations: 10,
        p_cost_parallelism: 2,
    },
    hash_length: match NonZeroUsize::new(32) {
        Some(v) => v,
        None => unreachable!(),
    },
    salt_length: match NonZeroUsize::new(16) {
        Some(v) => v,
        None => unreachable!(),
    },
};

impl RpcAuth {
    pub fn new(username: &str, password: &str) -> Self {
        let password_hash =
            hash_password(&mut make_true_rng(), RPC_KDF_CONFIG, password.as_bytes())
                .expect("hash_password failed unexpectedly");

        Self {
            username: username.to_owned(),
            password_hash,
        }
    }

    fn check_auth<B>(&self, request: &Request<B>) -> anyhow::Result<bool> {
        let header = match request.headers().get(http::header::AUTHORIZATION) {
            Some(v) => v,
            None => return Ok(false),
        };
        let username_password_encoded = header
            .as_bytes()
            .strip_prefix("Basic ".as_bytes())
            .ok_or_else(|| anyhow!("basic authentication expected"))?;
        let username_password = base64::engine::general_purpose::STANDARD
            .decode(username_password_encoded)
            .map_err(|e| anyhow!("base64 decoding of the authorization header failed: {e}"))?;
        let username_password = std::str::from_utf8(username_password.as_slice())
            .map_err(|e| anyhow!("invalid utf8 in the authorization header: {e}"))?;
        let (username, password) = username_password
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid authorization header: ':' not found"))?;
        let password_valid = verify_password(
            password.as_bytes(),
            self.password_hash.clone(),
            SliceEqualityCheckMethod::TimingResistant,
        )
        .map_err(|e| anyhow!("verify_password failed unexpectedly: {e}"))?;
        Ok(username == self.username && password_valid)
    }
}

impl<B> AuthorizeRequest<B> for RpcAuth {
    type ResponseBody = Body;

    fn authorize(&mut self, request: &mut Request<B>) -> Result<(), Response<Self::ResponseBody>> {
        let res = self.check_auth(request);
        match res {
            Ok(true) => Ok(()),
            Ok(false) => Err(Response::builder()
                .status(http::StatusCode::UNAUTHORIZED)
                .header(http::header::WWW_AUTHENTICATE, "Basic")
                .body(Body::empty())
                .expect("must be valid")),
            Err(e) => Err(Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(e.to_string().into())
                .expect("must be valid")),
        }
    }
}
