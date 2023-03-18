// Copyright (c) 2022 RBB S.r.l
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

use std::net::SocketAddr;

use jsonrpsee::server::{ServerBuilder, ServerHandle};

use logging::log;

pub use config::RpcConfig;
pub use jsonrpsee::core::server::rpc_module::Methods;
pub use jsonrpsee::core::Error;
pub use jsonrpsee::proc_macros::rpc;

mod config;

/// The Result type with RPC-specific error.
pub type Result<T> = core::result::Result<T, Error>;

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
    ws_bind_address: Option<SocketAddr>,
    methods: Methods,
}

impl Builder {
    /// New builder with no methods. None Option disables http or websocket.
    pub fn new_empty(
        http_bind_address: Option<SocketAddr>,
        ws_bind_address: Option<SocketAddr>,
    ) -> Self {
        let methods = Methods::new();
        Self {
            http_bind_address,
            ws_bind_address,
            methods,
        }
    }

    /// New builder pre-populated with RPC info methods
    pub fn new(rpc_config: RpcConfig) -> Self {
        let http_bind_address = if *rpc_config.http_enabled {
            Some(*rpc_config.http_bind_address)
        } else {
            None
        };

        let ws_bind_address = if *rpc_config.ws_enabled {
            Some(*rpc_config.ws_bind_address)
        } else {
            None
        };

        Self::new_empty(http_bind_address, ws_bind_address).register(RpcInfo.into_rpc())
    }

    /// Add methods handlers to the RPC server
    pub fn register(mut self, methods: impl Into<Methods>) -> Self {
        self.methods.merge(methods).expect("Duplicate RPC methods");
        self
    }

    /// Build the RPC server and get the RPC object
    pub async fn build(self) -> anyhow::Result<Rpc> {
        Rpc::new(
            self.http_bind_address.as_ref(),
            self.ws_bind_address.as_ref(),
            self.methods,
        )
        .await
    }
}

/// The RPC subsystem
pub struct Rpc {
    http: Option<(SocketAddr, ServerHandle)>,
    websocket: Option<(SocketAddr, ServerHandle)>,
}

impl Rpc {
    async fn new(
        http_bind_addr: Option<&SocketAddr>,
        ws_bind_addr: Option<&SocketAddr>,
        methods: Methods,
    ) -> anyhow::Result<Self> {
        let http = match http_bind_addr {
            Some(bind_addr) => {
                let http_server = ServerBuilder::default().http_only().build(bind_addr).await?;
                let http_address = http_server.local_addr()?;
                let http_handle = http_server.start(methods.clone())?;
                Some((http_address, http_handle))
            }
            None => None,
        };

        let websocket = match ws_bind_addr {
            Some(bind_addr) => {
                let ws_server = ServerBuilder::default().ws_only().build(bind_addr).await?;
                let ws_address = ws_server.local_addr()?;
                let ws_handle = ws_server.start(methods)?;
                Some((ws_address, ws_handle))
            }
            None => None,
        };

        Ok(Self { http, websocket })
    }

    pub fn http_address(&self) -> Option<&SocketAddr> {
        self.http.as_ref().map(|v| &v.0)
    }

    pub fn websocket_address(&self) -> Option<&SocketAddr> {
        self.websocket.as_ref().map(|v| &v.0)
    }
}

#[async_trait::async_trait]
impl subsystem::Subsystem for Rpc {
    async fn shutdown(self) {
        if let Some(obj) = self.http {
            match obj.1.stop() {
                Ok(_) => (),
                Err(e) => log::error!("Http RPC stop handle acquisition failed: {}", e),
            }
        }
        if let Some(obj) = self.websocket {
            match obj.1.stop() {
                Ok(_) => (),
                Err(e) => log::error!("Websocket RPC stop handle acquisition failed: {}", e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;
    use jsonrpsee::ws_client::WsClientBuilder;

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

    #[tokio::test]
    async fn rpc_server_http() -> anyhow::Result<()> {
        let rpc_config = RpcConfig {
            http_bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap().into(),
            http_enabled: true.into(),
            ws_bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap().into(),
            ws_enabled: false.into(),
        };
        let rpc = Builder::new(rpc_config).register(SubsystemRpcImpl.into_rpc()).build().await?;

        let url = format!("http://{}", rpc.http_address().unwrap());
        let client = HttpClientBuilder::default().build(url)?;
        let response: Result<String> =
            client.request("example_server_protocol_version", rpc_params!()).await;
        assert_eq!(response.unwrap(), "version1");

        let response: Result<String> = client.request("some_subsystem_name", rpc_params!()).await;
        assert_eq!(response.unwrap(), "sub1");

        let response: Result<u64> = client.request("some_subsystem_add", rpc_params!(2, 5)).await;
        assert_eq!(response.unwrap(), 7);

        subsystem::Subsystem::shutdown(rpc).await;
        Ok(())
    }

    #[tokio::test]
    async fn rpc_server_websocket() -> anyhow::Result<()> {
        let rpc_config = RpcConfig {
            http_bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap().into(),
            http_enabled: false.into(),
            ws_bind_address: "127.0.0.1:0".parse::<SocketAddr>().unwrap().into(),
            ws_enabled: true.into(),
        };
        let rpc = Builder::new(rpc_config).register(SubsystemRpcImpl.into_rpc()).build().await?;

        let url = format!("ws://{}", rpc.websocket_address().unwrap());
        let client = WsClientBuilder::default().build(url).await?;
        let response: Result<String> =
            client.request("example_server_protocol_version", rpc_params!()).await;
        assert_eq!(response.unwrap(), "version1");

        let response: Result<String> = client.request("some_subsystem_name", rpc_params!()).await;
        assert_eq!(response.unwrap(), "sub1");

        let response: Result<u64> = client.request("some_subsystem_add", rpc_params!(2, 5)).await;
        assert_eq!(response.unwrap(), 7);

        subsystem::Subsystem::shutdown(rpc).await;
        Ok(())
    }

    #[tokio::test]
    async fn rpc_server_http_and_websocket() -> anyhow::Result<()> {
        let rpc_config = RpcConfig {
            http_bind_address: "127.0.0.1:3032".parse::<SocketAddr>().unwrap().into(),
            http_enabled: true.into(),
            ws_bind_address: "127.0.0.1:3033".parse::<SocketAddr>().unwrap().into(),
            ws_enabled: true.into(),
        };

        let rpc = Builder::new(rpc_config).register(SubsystemRpcImpl.into_rpc()).build().await?;

        {
            let url = format!("http://{}", rpc.http_address().unwrap());
            let client = HttpClientBuilder::default().build(url)?;
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

        {
            let url = format!("ws://{}", rpc.websocket_address().unwrap());
            let client = WsClientBuilder::default().build(url).await?;
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
}
