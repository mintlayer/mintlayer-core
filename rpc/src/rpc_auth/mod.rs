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

use base64::Engine;
use crypto::{
    kdf::{argon2::Argon2Config, hash_password, verify_password, KdfConfig, KdfResult},
    random::make_true_rng,
    util::eq::SliceEqualityCheckMethod,
};
use hyper::{Body, Request, Response};
use logging::log;
use tower_http::validate_request::ValidateRequest;
use utils::const_nz_usize;

/// Custom HTTP authentication layer implementation
///
/// Custom authorization is not really needed, because `tower_http`
/// already supports it (see [`tower_http::auth::RequireAuthorizationLayer::basic`]),
/// but it can simplify things if we want to support hashed passwords.
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
    hash_length: const_nz_usize!(32),
    salt_length: const_nz_usize!(16),
};

#[derive(thiserror::Error, Debug)]
enum CheckError {
    #[error("Basic authentication expected")]
    BasicAuthenticationExpected,
    #[error("Base64 decoding of the authorization header failed: {0}")]
    InvalidBase64(base64::DecodeError),
    #[error("Invalid utf8 in the authorization header: {0}")]
    InvalidUtf8Value(std::str::Utf8Error),
    #[error("Invalid authorization header: ':' not found")]
    ColonNotFound,
    #[error("Unexpected KDF error: {0}")]
    KdfError(crypto::kdf::KdfError),
}

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

    fn check_auth<B>(&self, request: &Request<B>) -> Result<bool, CheckError> {
        let header = match request.headers().get(http::header::AUTHORIZATION) {
            Some(v) => v,
            None => return Ok(false),
        };
        let username_password_encoded = header
            .as_bytes()
            .strip_prefix("Basic ".as_bytes())
            .ok_or(CheckError::BasicAuthenticationExpected)?;
        let username_password = base64::engine::general_purpose::STANDARD
            .decode(username_password_encoded)
            .map_err(CheckError::InvalidBase64)?;
        let username_password = std::str::from_utf8(username_password.as_slice())
            .map_err(CheckError::InvalidUtf8Value)?;
        let (username, password) =
            username_password.split_once(':').ok_or(CheckError::ColonNotFound)?;
        let username_valid = SliceEqualityCheckMethod::timing_resistant_equal(
            self.username.as_bytes(),
            username.as_bytes(),
        );
        let password_valid = verify_password(
            password.as_bytes(),
            &self.password_hash,
            SliceEqualityCheckMethod::TimingResistant,
        )
        .map_err(CheckError::KdfError)?;
        Ok(username_valid && password_valid)
    }
}

impl<B> ValidateRequest<B> for RpcAuth {
    type ResponseBody = Body;

    fn validate(&mut self, request: &mut Request<B>) -> Result<(), Response<Self::ResponseBody>> {
        use jsonrpsee::types;

        let res = self.check_auth(request);
        match res {
            Ok(true) => Ok(()),
            Ok(false) => {
                log::error!("Unauthorized RPC request {:?}", request.uri());
                let status = http::StatusCode::UNAUTHORIZED;
                let err_obj = types::ErrorObject::owned(
                    status.as_u16().into(),
                    status.canonical_reason().unwrap_or_default(),
                    None::<()>,
                );
                let payload = types::ResponsePayload::<()>::error(err_obj);
                let response = types::Response::new(payload, types::Id::Null);
                let body = serde_json::to_string(&response).expect("constant object");

                Err(Response::builder()
                    .status(status)
                    .header(http::header::WWW_AUTHENTICATE, "Basic")
                    .header(http::header::CONTENT_TYPE, "application/json")
                    .body(body.into())
                    .expect("must be valid"))
            }
            Err(e) => {
                log::error!("Invalid RPC request {:?}: {e}", request.uri());
                Err(Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .body(e.to_string().into())
                    .expect("must be valid"))
            }
        }
    }
}

// TODO: Write tests
