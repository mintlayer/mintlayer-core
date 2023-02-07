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

use std::sync::Arc;

use clap::Parser;
use config::DnsServerConfig;
use crawler::{storage_impl::DnsServerStorageImpl, Crawler};
use p2p::net::default_backend::{
    transport::{NoiseEncryptionAdapter, NoiseTcpTransport, TcpTransportSocket},
    DefaultNetworkingService,
};
use tokio::sync::mpsc;

mod config;
mod crawler;
mod error;
mod server;

fn make_p2p_transport() -> NoiseTcpTransport {
    let stream_adapter = NoiseEncryptionAdapter::gen_new();
    let base_transport = TcpTransportSocket::new();
    NoiseTcpTransport::new(stream_adapter, base_transport)
}

async fn run(config: Arc<DnsServerConfig>) -> Result<void::Void, error::DnsServerError> {
    let (command_tx, command_rx) = mpsc::unbounded_channel();

    let chain_config = if config.testnet {
        Arc::new(common::chain::config::create_testnet())
    } else {
        Arc::new(common::chain::config::create_mainnet())
    };

    let p2p_config = Default::default();

    let transport = make_p2p_transport();

    let storage = DnsServerStorageImpl::new(storage_lmdb::Lmdb::new(
        config.datadir.clone().into(),
        Default::default(),
        Default::default(),
        Default::default(),
    ))?;

    let crawler = Crawler::<DefaultNetworkingService<_>, _>::new(
        Arc::clone(&config),
        chain_config,
        p2p_config,
        transport,
        storage,
        command_tx,
    )
    .await?;

    let server = server::Server::new(config, command_rx).await?;

    // Spawn for better parallelism
    let crawler_task = tokio::spawn(crawler.run());
    let server_task = tokio::spawn(server.run());

    tokio::select! {
        res = crawler_task => {
            res.expect("crawler should not panic")
        },
        res = server_task => {
            res.expect("server should not panic")
        },
    }
}

#[tokio::main]
async fn main() {
    let config = Arc::new(DnsServerConfig::parse());

    let result = run(config).await;

    if let Err(err) = result {
        eprintln!("DnsServer failed: {err:?}");
        std::process::exit(1)
    }
}
