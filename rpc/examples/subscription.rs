// Copyright (c) 2024 RBB S.r.l
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

use logging::log;

#[rpc::rpc(server)]
trait UsefulStuff {
    #[subscription(name = "subscribe_ticker", item = u64)]
    async fn subscribe_ticker(&self, interval: u32) -> rpc::subscription::Reply;
}

struct MyRpc;

#[async_trait::async_trait]
impl UsefulStuffServer for MyRpc {
    async fn subscribe_ticker(
        &self,
        pending: rpc::subscription::Pending,
        interval: u32,
    ) -> rpc::subscription::Reply {
        let interval = std::time::Duration::from_millis(interval as u64);
        log::info!("New ticker subscription with interval {interval:?}");

        let sub = rpc::subscription::accept(pending).await?;
        log::debug!("Subscription {:?} accepted", sub.subscription_id());

        for i in 0u64.. {
            tokio::time::sleep(interval).await;
            log::debug!("Sending {i} to subscription {:?}", sub.subscription_id());
            sub.send(&i).await?;
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logging::init_logging();

    log::debug!("Starting an RPC server");
    let rpc_server = rpc::Builder::new("127.0.0.1:0".parse().unwrap(), None)
        .with_method_list("methods")
        .register(MyRpc.into_rpc())
        .build()
        .await
        .unwrap();

    log::info!("RPC server address: {}", rpc_server.http_address());

    let mut manager = subsystem::Manager::new("test");
    let _ = manager.add_subsystem("rpc", rpc_server);
    manager.main().await;

    Ok(())
}
