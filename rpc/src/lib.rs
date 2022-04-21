use jsonrpsee::core::server::rpc_module::Methods;
use std::net::SocketAddr;

use jsonrpsee::core::Error;
use jsonrpsee::http_server::HttpServerBuilder;
use jsonrpsee::http_server::HttpServerHandle;
use jsonrpsee::proc_macros::rpc;

#[rpc(server, namespace = "example_server")]
pub trait Rpc {
    #[method(name = "protocol_version")]
    fn protocol_version(&self) -> Result<String, Error>;
}

struct RpcImpl;
impl RpcServer for RpcImpl {
    fn protocol_version(&self) -> Result<String, Error> {
        Ok("version1".into())
    }
}

pub async fn start(addr: &SocketAddr) -> anyhow::Result<(SocketAddr, HttpServerHandle)> {
    let methods = Methods::from(RpcImpl.into_rpc());
    // TODO the methdods from the different subsystem will be aggregated here

    start_with_methods(addr, methods).await
}

async fn start_with_methods(
    addr: &SocketAddr,
    methods: Methods,
) -> anyhow::Result<(SocketAddr, HttpServerHandle)> {
    let server = HttpServerBuilder::default().build(addr).await?;
    let addr = server.local_addr()?;
    let handle = server.start(methods)?;
    Ok((addr, handle))
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
        fn name(&self) -> Result<String, Error>;

        #[method(name = "add")]
        fn add(&self, a: u64, b: u64) -> Result<u64, Error>;
    }

    pub struct SubsystemRpcImpl;

    impl SubsystemRpcServer for SubsystemRpcImpl {
        fn name(&self) -> Result<String, Error> {
            Ok("sub1".into())
        }

        fn add(&self, a: u64, b: u64) -> Result<u64, Error> {
            Ok(a + b)
        }
    }

    #[tokio::test]
    async fn rpc_server() -> anyhow::Result<()> {
        let mut methods = Methods::from(RpcImpl.into_rpc());
        methods.merge(SubsystemRpcImpl.into_rpc())?;
        let (server_addr, _handle) =
            start_with_methods(&"127.0.0.1:3030".parse().unwrap(), methods).await.unwrap();

        let url = format!("http://{}", server_addr);
        let client = HttpClientBuilder::default().build(url)?;
        let response: Result<String, _> =
            client.request("example_server_protocol_version", rpc_params!()).await;
        assert_eq!(response.unwrap(), "version1");

        let response: Result<String, _> =
            client.request("some_subsystem_name", rpc_params!()).await;
        assert_eq!(response.unwrap(), "sub1");

        let response: Result<u64, _> =
            client.request("some_subsystem_add", rpc_params!(2, 5)).await;
        assert_eq!(response.unwrap(), 7);
        Ok(())
    }
}
