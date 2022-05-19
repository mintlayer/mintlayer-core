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

struct SomeSubsystem(u64);

impl subsystem::Subsystem for SomeSubsystem {}

impl SomeSubsystem {
    fn bump(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }
}

type SomeSubsystemHandle = subsystem::Handle<SomeSubsystem>;

#[rpc::rpc(server, namespace = "some_subsystem")]
pub trait SomeSubsystemRpc {
    #[method(name = "name")]
    fn name(&self) -> rpc::Result<String>;

    #[method(name = "add")]
    fn add(&self, a: u64, b: u64) -> rpc::Result<u64>;

    #[method(name = "bump")]
    async fn bump(&self) -> rpc::Result<u64>;
}

#[async_trait::async_trait]
impl SomeSubsystemRpcServer for SomeSubsystemHandle {
    fn name(&self) -> rpc::Result<String> {
        Ok("sub1".into())
    }

    fn add(&self, a: u64, b: u64) -> rpc::Result<u64> {
        Ok(a + b)
    }

    async fn bump(&self) -> rpc::Result<u64> {
        self.call_mut(SomeSubsystem::bump).await.map_err(rpc::Error::to_call_error)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init_logging::<&std::path::Path>(None);

    let mut app = subsystem::Manager::new("rpc-example");
    app.install_signal_handlers();
    let some_subsystem = app.add_subsystem("some_subsys", SomeSubsystem(0));
    let _rpc_subsystem = app.add_subsystem(
        "rpc",
        rpc::Builder::new("127.0.0.1:3030".parse().expect("address parse error"))
            .register(some_subsystem.clone().into_rpc())
            .build()
            .await?,
    );

    app.main().await;
    Ok(())
}
