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

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use futures::future::BoxFuture;
use tokio::net::TcpStream;
use tokio_socks::tcp::Socks5Stream;

use crate::{
    error::{DialError, P2pError},
    net::default_backend::transport::{PeerStream, TransportListener, TransportSocket},
    Result,
};

// TODO: Add tests. A typical way to test this is to create a forwarding proxy with a socks interface
// that can test that things sent through the proxy are delivered to the other end.

#[derive(Debug)]
pub struct Socks5TransportSocket {
    proxy: Arc<String>,
}

impl Socks5TransportSocket {
    pub fn new(proxy: &str) -> Self {
        Self {
            proxy: Arc::new(proxy.to_owned()),
        }
    }
}

#[async_trait]
impl TransportSocket for Socks5TransportSocket {
    type Address = SocketAddr;
    type BannableAddress = IpAddr;
    type Listener = Socks5TransportListener;
    type Stream = Socks5TransportStream;

    async fn bind(&self, addresses: Vec<Self::Address>) -> Result<Self::Listener> {
        Socks5TransportListener::new(addresses)
    }

    fn connect(&self, address: Self::Address) -> BoxFuture<'static, Result<Self::Stream>> {
        let proxy = Arc::clone(&self.proxy);
        Box::pin(async move {
            let socket = TcpStream::connect(proxy.as_str()).await.map_err(|e| {
                DialError::ProxyError(format!("Connection to the SOCKS5 proxy failed: {e}"))
            })?;

            let stream = Socks5Stream::connect_with_socket(socket, address)
                .await
                .map_err(|e| DialError::ProxyError(format!("Unexpected SOCKS5 error: {e}")))?;

            Ok(stream)
        })
    }
}

pub struct Socks5TransportListener {}

impl Socks5TransportListener {
    fn new(addresses: Vec<SocketAddr>) -> Result<Self> {
        utils::ensure!(
            addresses.is_empty(),
            P2pError::InvalidConfigurationValue(
                "Listening with socks5 proxy not implemented".to_owned()
            ),
        );
        Ok(Self {})
    }
}

#[async_trait]
impl TransportListener<Socks5TransportStream, SocketAddr> for Socks5TransportListener {
    async fn accept(&mut self) -> Result<(Socks5TransportStream, SocketAddr)> {
        std::future::pending().await
    }

    fn local_addresses(&self) -> Result<Vec<SocketAddr>> {
        Ok(Vec::new())
    }
}

pub type Socks5TransportStream = Socks5Stream<TcpStream>;

impl PeerStream for Socks5TransportStream {}
