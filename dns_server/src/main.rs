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
use crawler::{storage_impl::DnsServerStorageImpl, Crawler, CrawlerConfig};
use p2p::{
    config::P2pConfig,
    net::{
        default_backend::{
            transport::{NoiseEncryptionAdapter, NoiseTcpTransport, TcpTransportSocket},
            DefaultNetworkingService,
        },
        NetworkingService,
    },
};
use tokio::sync::mpsc;

mod config;
mod crawler;
mod dns_server;
mod error;

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

    let p2p_config = Arc::new(P2pConfig {
        bind_addresses: Vec::new(),
        added_nodes: Vec::new(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        node_type: Default::default(),
        allow_discover_private_ips: Default::default(),
    });

    let transport = make_p2p_transport();

    let (conn, sync) = DefaultNetworkingService::<NoiseTcpTransport>::start(
        transport,
        vec![],
        Arc::clone(&chain_config),
        Arc::clone(&p2p_config),
    )
    .await?;

    let storage = DnsServerStorageImpl::new(storage_lmdb::Lmdb::new(
        config.datadir.clone().into(),
        Default::default(),
        Default::default(),
        Default::default(),
    ))?;

    let crawler_config = CrawlerConfig {
        add_node: config.add_node.clone(),
        network: *chain_config.magic_bytes(),
        p2p_port: chain_config.p2p_port(),
    };

    let mut crawler = Crawler::<DefaultNetworkingService<_>, _>::new(
        crawler_config,
        conn,
        sync,
        storage,
        command_tx,
    )?;

    let server = dns_server::DnsServer::new(config, command_rx).await?;

    // Spawn for better parallelism
    let crawler_task = tokio::spawn(async move { crawler.run().await });
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
