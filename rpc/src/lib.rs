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

mod error;
mod rpc_auth;
pub mod rpc_creds;
pub mod subscription;

/// Data structures describing an RPC interface
pub use rpc_description as description;
/// A macro to generate RPC interface description for given trait. Has to come before `#[rpc(...)]`
pub use rpc_description_macro::describe;

/// Support types for RPC interfaces
pub use rpc_types as types;

use std::{net::SocketAddr, path::PathBuf};

use base64::Engine;
use http::{header, HeaderValue};
use jsonrpsee::{
    http_client::{transport::HttpBackend, HttpClient, HttpClientBuilder},
    server::{ServerBuilder, ServerHandle},
};

use logging::log;

pub use error::{handle_result, ClientError, Error, RpcCallResult, RpcClientResult, RpcResult};

pub use jsonrpsee::{core::server::Methods, proc_macros::rpc};
use rpc_auth::RpcAuth;
use rpc_creds::RpcCreds;
use tower_http::{
    set_header::{MakeHeaderValue, SetRequestHeader, SetRequestHeaderLayer},
    validate_request::ValidateRequestHeaderLayer,
};
use utils::cookie::load_cookie;

#[cfg(feature = "test-support")]
pub mod test_support {
    pub use jsonrpsee::core::client::{ClientT, Subscription, SubscriptionClientT};
}

/// The RPC subsystem builder. Used to populate the RPC server with method handlers.
pub struct Builder {
    http_bind_address: SocketAddr,
    methods: Methods,
    creds: Option<RpcCreds>,
    method_list_name: Option<&'static str>,
}

impl Builder {
    /// New builder pre-populated with RPC info methods.
    ///
    /// If `creds` is set, basic HTTP authentication is required.
    pub fn new(http_bind_address: SocketAddr, creds: Option<RpcCreds>) -> Self {
        Self {
            http_bind_address,
            methods: Methods::new(),
            creds,
            method_list_name: None,
        }
    }

    /// Add methods handlers to the RPC server
    pub fn register(mut self, methods: impl Into<Methods>) -> Self {
        self.methods.merge(methods).expect("Duplicate RPC methods");
        self
    }

    /// Add a method that lists all methods
    pub fn with_method_list(mut self, method_name: &'static str) -> Self {
        self.method_list_name = Some(method_name);
        self
    }

    /// Build the RPC server and get the RPC object
    pub async fn build(mut self) -> anyhow::Result<Rpc> {
        if let Some(method_list_name) = self.method_list_name {
            let module = Self::create_method_list_module(&self.methods, method_list_name)?;
            self.methods.merge(module)?;
        }

        Rpc::new(&self.http_bind_address, self.methods, self.creds).await
    }

    /// Create an RPC module that contains a method to query the names of RPC methods
    fn create_method_list_module(
        methods: &Methods,
        method_list_name: &'static str,
    ) -> Result<jsonrpsee::RpcModule<()>, jsonrpsee::server::RegisterMethodError> {
        let method_names = {
            let mut method_names: Vec<_> =
                std::iter::once(method_list_name).chain(methods.method_names()).collect();
            method_names.sort_unstable();
            method_names
        };

        let mut module = jsonrpsee::RpcModule::new(());
        module.register_method(method_list_name, move |_params, &()| method_names.clone())?;
        Ok(module)
    }
}

/// The RPC subsystem
#[derive(Clone)]
pub struct Rpc {
    http: (SocketAddr, ServerHandle),
    // Stored here to remove the cookie file when the node is stopped
    _creds: Option<RpcCreds>,
}

impl Rpc {
    /// Rpc constructor.
    ///
    /// If `creds` is set, basic HTTP authentication is required.
    async fn new(
        http_bind_addr: &SocketAddr,
        methods: Methods,
        creds: Option<RpcCreds>,
    ) -> anyhow::Result<Self> {
        let auth_layer = creds.as_ref().map(|creds| {
            ValidateRequestHeaderLayer::custom(RpcAuth::new(creds.username(), creds.password()))
        });

        let middleware = tower::ServiceBuilder::new().layer(tower::util::option_layer(auth_layer));

        let http = {
            let http_server = ServerBuilder::new()
                .set_http_middleware(middleware.clone())
                .build(http_bind_addr)
                .await
                .inspect_err(|_| {
                    logging::log::error!("\n\nError: Failed to bind RPC to address {http_bind_addr}; the port is probably reserved by another application. Assuming the node is not already running, either pick another port (bind address) or disable RPC.\n");
                })?;
            let http_address = http_server.local_addr()?;
            let http_handle = http_server.start(methods.clone());
            (http_address, http_handle)
        };

        Ok(Self {
            http,
            _creds: creds,
        })
    }

    pub fn http_address(&self) -> &SocketAddr {
        &self.http.0
    }

    pub async fn shutdown(self) {
        match self.http.1.stop() {
            Ok(()) => self.http.1.stopped().await,
            Err(e) => log::error!("Http RPC stop handle acquisition failed: {}", e),
        }
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
        self.shutdown().await
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

pub fn new_http_client(
    host: impl AsRef<str>,
    rpc_auth: RpcAuthData,
) -> RpcClientResult<RpcHttpClient> {
    let middleware = tower::ServiceBuilder::new().layer(SetRequestHeaderLayer::overriding(
        header::AUTHORIZATION,
        rpc_auth,
    ));

    HttpClientBuilder::default().set_http_middleware(middleware).build(host)
}

pub type RpcWsClient = jsonrpsee::ws_client::WsClient;

pub async fn new_ws_client(
    host: impl AsRef<str>,
    rpc_auth: RpcAuthData,
) -> RpcClientResult<RpcWsClient> {
    let headers = rpc_auth
        .get_header()
        .map(|header_val| http::HeaderMap::from_iter([(header::AUTHORIZATION, header_val)]))
        .unwrap_or_default();

    jsonrpsee::ws_client::WsClientBuilder::new()
        .set_headers(headers)
        .build(host)
        .await
}

fn make_http_header_value(username: &str, password: &str) -> http::HeaderValue {
    let creds = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
    http::HeaderValue::from_str(&format!("Basic {creds}")).expect("Should not fail")
}
