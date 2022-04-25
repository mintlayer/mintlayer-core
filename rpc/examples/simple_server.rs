use rpc::start_with_methods;

use jsonrpsee::core::server::rpc_module::Methods;
use jsonrpsee::core::Error;
use jsonrpsee::proc_macros::rpc;

// How to run this example
//
// From within the rpc directory:
// cargo run --example simple_server
//
// And then, from another terminal window:
//
// create a file `add_request.json` cointaining:
//
// {"jsonrpc": "2.0", "id": 2, "method": "some_subsystem_add", "params": {"a": 4, "b": 42}}
//
// and run
//
// curl -d @absolute/path/to/add_request.json -H "Content-Type: application/json" http://localhost:3030
//
// The output should be
// {"jsonrpc":"2.0","result":46,"id":2 }

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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let methods = Methods::from(SubsystemRpcImpl.into_rpc());
    let (_server_addr, handle) =
        start_with_methods(&"127.0.0.1:3030".parse().unwrap(), methods).await.unwrap();
    handle.await;
    Ok(())
}
