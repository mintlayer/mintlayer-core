// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::net::SocketAddr;

use jsonrpsee::http_server::{HttpServerBuilder, HttpServerHandle};

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
    fn protocol_version(&self) -> crate::Result<String>;
}

struct RpcInfo;
impl RpcInfoServer for RpcInfo {
    fn protocol_version(&self) -> crate::Result<String> {
        Ok("version1".into())
    }
}

/// The RPC subsystem builder. Used to populate the RPC server with method handlers.
pub struct Builder {
    address: SocketAddr,
    methods: Methods,
}

impl Builder {
    /// New builder with no methods
    pub fn new_empty(address: SocketAddr) -> Self {
        let methods = Methods::new();
        Self { address, methods }
    }

    /// New builder pre-populated with RPC info methods
    pub fn new(rpc_config: RpcConfig) -> Self {
        Self::new_empty(rpc_config.bind_address).register(RpcInfo.into_rpc())
    }

    /// Add methods handlers to the RPC server
    pub fn register(mut self, methods: impl Into<Methods>) -> Self {
        self.methods.merge(methods).expect("Duplicate RPC methods");
        self
    }

    /// Build the RPC server and get the RPC object
    pub async fn build(self) -> anyhow::Result<Rpc> {
        Rpc::new(&self.address, self.methods).await
    }
}

/// The RPC subsystem
pub struct Rpc {
    address: SocketAddr,
    handle: HttpServerHandle,
}

impl Rpc {
    async fn new(addr: &SocketAddr, methods: Methods) -> anyhow::Result<Self> {
        let server = HttpServerBuilder::default().build(addr).await?;
        let address = server.local_addr()?;
        let handle = server.start(methods)?;
        Ok(Self { address, handle })
    }

    pub fn address(&self) -> &SocketAddr {
        &self.address
    }
}

#[async_trait::async_trait]
impl subsystem::Subsystem for Rpc {
    async fn shutdown(self) {
        match self.handle.stop() {
            Ok(stop) => stop.await.unwrap_or_else(|e| log::error!("RPC join error: {}", e)),
            Err(e) => log::error!("RPC stop handle acquisition failed: {}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;

    #[rpc(server, namespace = "some_subsystem")]
    pub trait SubsystemRpc {
        #[method(name = "name")]
        fn name(&self) -> crate::Result<String>;

        #[method(name = "add")]
        fn add(&self, a: u64, b: u64) -> crate::Result<u64>;
    }

    pub struct SubsystemRpcImpl;

    impl SubsystemRpcServer for SubsystemRpcImpl {
        fn name(&self) -> crate::Result<String> {
            Ok("sub1".into())
        }

        fn add(&self, a: u64, b: u64) -> crate::Result<u64> {
            Ok(a + b)
        }
    }

    #[tokio::test]
    async fn rpc_server() -> anyhow::Result<()> {
        let rpc_config = RpcConfig {
            bind_address: "127.0.0.1:3030".parse().unwrap(),
        };
        let rpc = Builder::new(rpc_config).register(SubsystemRpcImpl.into_rpc()).build().await?;

        let url = format!("http://{}", rpc.address());
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
}
