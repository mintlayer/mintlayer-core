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

// How to run this example
//
// From within the rpc directory:
// cargo run --example simple_server
//
// And then, from another terminal window:
//
// create a file `add_request.json` containing:
//
// {"jsonrpc": "2.0", "id": 2, "method": "some_subsystem_add", "params": {"a": 4, "b": 42}}
//
// and run
//
// curl -d @absolute/path/to/add_request.json -H "Content-Type: application/json" http://localhost:3030
//
// The output should be
// {"jsonrpc":"2.0","result":46,"id":2 }

use std::net::SocketAddr;

struct SomeSubsystem(u64);

impl SomeSubsystem {
    fn bump(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }
}

type SomeSubsystemHandle = subsystem::Handle<SomeSubsystem>;

/// This is a random testing RPC interface
#[rpc::describe]
#[rpc::rpc(server, namespace = "some_subsystem")]
pub trait SomeSubsystemRpc {
    #[method(name = "name")]
    fn name(&self) -> rpc::RpcResult<String>;

    #[method(name = "add")]
    fn add(&self, a: u64, b: u64) -> rpc::RpcResult<u64>;

    #[method(name = "bump")]
    async fn bump(&self) -> rpc::RpcResult<u64>;
}

#[async_trait::async_trait]
impl SomeSubsystemRpcServer for SomeSubsystemHandle {
    fn name(&self) -> rpc::RpcResult<String> {
        Ok("sub1".into())
    }

    fn add(&self, a: u64, b: u64) -> rpc::RpcResult<u64> {
        Ok(a + b)
    }

    async fn bump(&self) -> rpc::RpcResult<u64> {
        rpc::handle_result(self.call_mut(SomeSubsystem::bump).await)
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init_logging();

    let config = subsystem::ManagerConfig::new("rpc-example").enable_signal_handlers();
    let mut app = subsystem::Manager::new_with_config(config);
    let some_subsystem = app.add_direct_subsystem("some_subsystem", SomeSubsystem(0));
    let http_bind_address = "127.0.0.1:0".parse::<SocketAddr>().expect("Cannot fail");
    let _rpc_subsystem = app.add_subsystem(
        "rpc",
        rpc::Builder::new(http_bind_address, None)
            .register(some_subsystem.clone().into_rpc())
            .build()
            .await?,
    );

    app.main().await;
    Ok(())
}
