// Copyright (c) 2022-2023 RBB S.r.l
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

mod config;
mod error;
mod rpc_auth;
pub mod rpc_creds;

use std::{net::SocketAddr, path::PathBuf};

use base64::Engine;
use http::{header, HeaderValue};
use jsonrpsee::{
    http_client::{transport::HttpBackend, HttpClient, HttpClientBuilder},
    server::{ServerBuilder, ServerHandle},
    ws_client::{WsClient, WsClientBuilder},
};

use logging::log;

pub use config::RpcConfig;
pub use error::{handle_result, Error, Result};

pub use jsonrpsee::{core::server::Methods, proc_macros::rpc};
use rpc_auth::RpcAuth;
use rpc_creds::RpcCreds;
use tower_http::{
    set_header::{MakeHeaderValue, SetRequestHeader, SetRequestHeaderLayer},
    validate_request::ValidateRequestHeaderLayer,
};
use utils::cookie::load_cookie;

#[rpc(server, namespace = "example_server")]
trait RpcInfo {
    #[method(name = "protocol_version")]
    fn protocol_version(&self) -> Result<String>;
}

struct RpcInfo;
impl RpcInfoServer for RpcInfo {
    fn protocol_version(&self) -> Result<String> {
        Ok("version1".into())
    }
}

/// The RPC subsystem builder. Used to populate the RPC server with method handlers.
pub struct Builder {
    http_bind_address: Option<SocketAddr>,
    methods: Methods,
    creds: Option<RpcCreds>,
}

impl Builder {
    /// New builder with no methods. None Option disables http or websocket.
    pub fn new_empty(http_bind_address: Option<SocketAddr>) -> Self {
        let methods = Methods::new();
        Self {
            http_bind_address,
            methods,
            creds: None,
        }
    }

    /// New builder pre-populated with RPC info methods.
    ///
    /// If `creds` is set, basic HTTP authentication is required.
    pub fn new(rpc_config: RpcConfig, creds: Option<RpcCreds>) -> Self {
        let http_bind_address = if *rpc_config.http_enabled {
            Some(*rpc_config.http_bind_address)
        } else {
            None
        };

        Self {
            http_bind_address,
            methods: Methods::new(),
            creds,
        }
        .register(RpcInfo.into_rpc())
    }

    /// Add methods handlers to the RPC server
    pub fn register(mut self, methods: impl Into<Methods>) -> Self {
        self.methods.merge(methods).expect("Duplicate RPC methods");
        self
    }

    /// Build the RPC server and get the RPC object
    pub async fn build(self) -> anyhow::Result<Rpc> {
        Rpc::new(self.http_bind_address.as_ref(), self.methods, self.creds).await
    }
}

/// The RPC subsystem
pub struct Rpc {
    http: Option<(SocketAddr, ServerHandle)>,
    // Stored here to remove the cookie file when the node is stopped
    _creds: Option<RpcCreds>,
}

impl Rpc {
    /// Rpc constructor.
    ///
    /// If `creds` is set, basic HTTP authentication is required.
    async fn new(
        http_bind_addr: Option<&SocketAddr>,
        methods: Methods,
        creds: Option<RpcCreds>,
    ) -> anyhow::Result<Self> {
        let auth_layer = creds.as_ref().map(|creds| {
            ValidateRequestHeaderLayer::custom(RpcAuth::new(creds.username(), creds.password()))
        });

        let middleware = tower::ServiceBuilder::new().layer(tower::util::option_layer(auth_layer));

        let http = match http_bind_addr {
            Some(bind_addr) => {
                let http_server = ServerBuilder::new()
                    .set_middleware(middleware.clone())
                    .http_only()
                    .build(bind_addr)
                    .await?;
                let http_address = http_server.local_addr()?;
                let http_handle = http_server.start(methods.clone())?;
                Some((http_address, http_handle))
            }
            None => None,
        };

        Ok(Self {
            http,
            _creds: creds,
        })
    }

    pub fn http_address(&self) -> Option<&SocketAddr> {
        self.http.as_ref().map(|v| &v.0)
    }
}

#[async_trait::async_trait]
impl subsystem::Subsystem for Rpc {
    type Interface = Self;

    fn interface_ref(&self) -> &Self {
        self
    }

    fn interface_mut(&mut self) -> &mut Self {
        self
    }

    async fn shutdown(self) {
        if let Some(obj) = self.http {
            match obj.1.stop() {
                Ok(()) => obj.1.stopped().await,
                Err(e) => log::error!("Http RPC stop handle acquisition failed: {}", e),
            }
        }
    }
}

#[derive(Clone)]
pub enum RpcAuthData {
    /// No authorization
    None,

    /// Basic authorization
    Basic { username: String, password: String },

    /// Load username and password from cookie file (on every request)
    Cookie { cookie_file_path: PathBuf },
}

impl RpcAuthData {
    pub fn get_header(&self) -> Option<HeaderValue> {
        match &self {
            RpcAuthData::None => None,
            RpcAuthData::Basic { username, password } => {
                Some(make_http_header_value(username, password))
            }
            RpcAuthData::Cookie { cookie_file_path } => {
                let cookie_res = load_cookie(cookie_file_path);
                match cookie_res {
                    Ok((username, password)) => Some(make_http_header_value(&username, &password)),
                    Err(err) => {
                        log::error!("Loading cookie file {cookie_file_path:?} failed: {err}");
                        None
                    }
                }
            }
        }
    }
}

impl<T> MakeHeaderValue<T> for RpcAuthData {
    fn make_header_value(&mut self, _message: &T) -> Option<HeaderValue> {
        self.get_header()
    }
}

pub type RpcHttpClient = HttpClient<SetRequestHeader<HttpBackend, RpcAuthData>>;
pub type RpcWsClient = WsClient;

pub fn new_http_client(host: String, rpc_auth: RpcAuthData) -> Result<RpcHttpClient> {
    let middleware = tower::ServiceBuilder::new().layer(SetRequestHeaderLayer::overriding(
        header::AUTHORIZATION,
        rpc_auth,
    ));

    HttpClientBuilder::default().set_middleware(middleware).build(host)
}

pub async fn new_ws_client(host: String, rpc_auth: RpcAuthData) -> Result<RpcWsClient> {
    let mut headers = http::HeaderMap::new();
    if let Some(header) = rpc_auth.get_header() {
        headers.append(http::header::AUTHORIZATION, header);
    }

    WsClientBuilder::default().set_headers(headers).build(host).await
}

fn make_http_header_value(username: &str, password: &str) -> http::HeaderValue {
    http::HeaderValue::from_str(&format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
    ))
    .expect("Should not fail")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crypto::random::{
        distributions::{Alphanumeric, DistString},
        Rng,
    };
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::rpc_params;
    use rstest::rstest;
    use test_utils::random::{make_seedable_rng, Seed};

    #[rpc(server, namespace = "some_subsystem")]
    pub trait SubsystemRpc {
        #[method(name = "name")]
        fn name(&self) -> Result<String>;

        #[method(name = "add")]
        fn add(&self, a: u64, b: u64) -> Result<u64>;
    }

    pub struct SubsystemRpcImpl;

    impl SubsystemRpcServer for SubsystemRpcImpl {
        fn name(&self) -> Result<String> {
            Ok("sub1".into())
        }

        fn add(&self, a: u64, b: u64) -> Result<u64> {
            Ok(a + b)
        }
    }

    #[rstest]
    #[trace]
    #[case(true)]
    #[case(false)]
    #[tokio::test]
    async fn rpc_server(#[case] http: bool) -> anyhow::Result<()> {
        let rpc_config = RpcConfig {
            http_bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap().into(),
            http_enabled: http.into(),
        };

        let rpc = Builder::new(rpc_config, None)
            .register(SubsystemRpcImpl.into_rpc())
            .build()
            .await?;

        if http {
            let url = format!("http://{}", rpc.http_address().unwrap());
            let client = new_http_client(url, RpcAuthData::None).unwrap();
            let response: Result<String> =
                client.request("example_server_protocol_version", rpc_params!()).await;
            assert_eq!(response.unwrap(), "version1");

            let response: Result<String> =
                client.request("some_subsystem_name", rpc_params!()).await;
            assert_eq!(response.unwrap(), "sub1");

            let response: Result<u64> =
                client.request("some_subsystem_add", rpc_params!(2, 5)).await;
            assert_eq!(response.unwrap(), 7);
        }

        subsystem::Subsystem::shutdown(rpc).await;
        Ok(())
    }

    async fn http_request(rpc: &Rpc, rpc_auth: RpcAuthData) -> anyhow::Result<()> {
        let url = format!("http://{}", rpc.http_address().unwrap());
        let client = new_http_client(url, rpc_auth)?;
        let response: String =
            client.request("example_server_protocol_version", rpc_params!()).await?;
        anyhow::ensure!(response == "version1");
        Ok(())
    }

    fn gen_random_string(rng: &mut impl Rng, not_equal_to: &str) -> String {
        let len = rng.gen_range(1..20);
        loop {
            let val = Alphanumeric.sample_string(rng, len);
            if not_equal_to != val {
                return val;
            }
        }
    }

    #[rstest]
    #[trace]
    #[case(Seed::from_entropy())]
    #[tokio::test]
    async fn rpc_server_auth(#[case] seed: Seed) {
        let mut rng = make_seedable_rng(seed);

        let good_username = gen_random_string(&mut rng, "");
        let good_password = gen_random_string(&mut rng, "");
        let bad_username = gen_random_string(&mut rng, &good_username);
        let bad_password = gen_random_string(&mut rng, &good_password);

        let rpc_config = RpcConfig {
            http_bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap().into(),
            http_enabled: true.into(),
        };

        let data_dir: PathBuf = ".".into();
        let rpc = Builder::new(
            rpc_config,
            Some(
                RpcCreds::new(
                    &data_dir,
                    Some(&good_username),
                    Some(&good_password),
                    Option::<String>::None,
                )
                .unwrap(),
            ),
        )
        .register(SubsystemRpcImpl.into_rpc())
        .build()
        .await
        .unwrap();

        // Valid requests
        http_request(
            &rpc,
            RpcAuthData::Basic {
                username: good_username.clone(),
                password: good_password.clone(),
            },
        )
        .await
        .unwrap();

        // Invalid requests
        http_request(&rpc, RpcAuthData::None).await.unwrap_err();

        http_request(
            &rpc,
            RpcAuthData::Basic {
                username: good_username.clone(),
                password: bad_password.clone(),
            },
        )
        .await
        .unwrap_err();
        http_request(
            &rpc,
            RpcAuthData::Basic {
                username: bad_username.clone(),
                password: good_password.clone(),
            },
        )
        .await
        .unwrap_err();

        subsystem::Subsystem::shutdown(rpc).await;
    }
}
