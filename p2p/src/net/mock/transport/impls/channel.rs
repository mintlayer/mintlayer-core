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

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU32, Ordering},
        Mutex,
    },
};

use async_trait::async_trait;
use futures::future::BoxFuture;
use once_cell::sync::Lazy;
use tokio::{
    io::DuplexStream,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot::{self, Sender},
    },
};

use crate::{
    error::DialError,
    net::{
        mock::transport::{
            traits::TransportAddress, PeerStream, TransportListener, TransportSocket,
        },
        AsBannableAddress,
    },
    types::peer_address::{PeerAddress, PeerAddressIp4},
    P2pError, Result,
};

type Address = u32;

impl TransportAddress for Address {
    fn as_peer_address(&self) -> PeerAddress {
        PeerAddress::Ip4(PeerAddressIp4 {
            // Address of the first "host" will be 0.0.0.1
            ip: std::net::Ipv4Addr::from(*self).into(),
            // There is only one "port" in MockChannelTransport per "host", use arbitrary value
            port: 10000,
        })
    }

    fn from_peer_address(_address: &PeerAddress) -> Option<Self> {
        None
    }
}

/// Zero address has special meaning: bind to a free address.
const ZERO_ADDRESS: Address = 0;

// How much bytes is allowed for write (without reading on the other side).
const MAX_BUF_SIZE: usize = 10 * 1024 * 1024;

type IncomingConnection = (Address, Sender<DuplexStream>);

static CONNECTIONS: Lazy<Mutex<BTreeMap<Address, UnboundedSender<IncomingConnection>>>> =
    Lazy::new(Default::default);

static NEXT_ADDRESS: AtomicU32 = AtomicU32::new(1);

// Creating new transport is like attaching new "host" to the network.
// New unique address is registered for the new "host".
// Unlike TCP only one active bind is allowed at any moment to keep things simple
// (so there is only one port per host).
#[derive(Debug)]
pub struct MockChannelTransport {
    local_address: Address,
}

impl MockChannelTransport {
    pub fn new() -> Self {
        let local_address = NEXT_ADDRESS.fetch_add(1, Ordering::Relaxed);
        MockChannelTransport { local_address }
    }
}

#[async_trait]
impl TransportSocket for MockChannelTransport {
    type Address = Address;
    type BannableAddress = Address;
    type Listener = MockChannelListener;
    type Stream = ChannelMockStream;

    async fn bind(&self, addresses: Vec<Self::Address>) -> Result<Self::Listener> {
        // It's not possible to bind to random address
        for address in addresses.iter() {
            if *address != ZERO_ADDRESS && *address != self.local_address {
                return Err(P2pError::DialError(DialError::IoError(
                    std::io::ErrorKind::AddrNotAvailable,
                )));
            };
        }

        let mut connections = CONNECTIONS.lock().expect("Connections mutex is poisoned");

        if connections.contains_key(&self.local_address) {
            return Err(P2pError::DialError(DialError::IoError(
                std::io::ErrorKind::AddrInUse,
            )));
        }

        let (sender, receiver) = unbounded_channel();

        let old_entry = connections.insert(self.local_address, sender);
        assert!(old_entry.is_none());

        Ok(Self::Listener {
            address: self.local_address,
            receiver,
        })
    }

    fn connect(&self, address: Self::Address) -> BoxFuture<'static, crate::Result<Self::Stream>> {
        // A connection can only be established to a known address.
        assert_ne!(ZERO_ADDRESS, address);

        let local_address = self.local_address;

        Box::pin(async move {
            let server_sender = CONNECTIONS
                .lock()
                .expect("Connections mutex is poisoned")
                .get(&address)
                .ok_or(P2pError::DialError(DialError::NoAddresses))?
                .clone();

            let (connect_sender, connect_receiver) = oneshot::channel();
            server_sender
                .send((local_address, connect_sender))
                .map_err(|_| P2pError::DialError(DialError::NoAddresses))?;

            let channel = connect_receiver.await.map_err(|_| P2pError::ChannelClosed)?;

            Ok(channel)
        })
    }
}

pub struct MockChannelListener {
    address: Address,
    receiver: UnboundedReceiver<IncomingConnection>,
}

#[async_trait]
impl TransportListener<ChannelMockStream, Address> for MockChannelListener {
    async fn accept(&mut self) -> Result<(ChannelMockStream, Address)> {
        let (remote_address, response_sender) =
            self.receiver.recv().await.ok_or(P2pError::ChannelClosed)?;

        let (server, client) = tokio::io::duplex(MAX_BUF_SIZE);

        response_sender.send(client).map_err(|_| P2pError::ChannelClosed)?;

        Ok((server, remote_address))
    }

    fn local_addresses(&self) -> Result<Vec<Address>> {
        Ok(vec![self.address])
    }
}

impl Drop for MockChannelListener {
    fn drop(&mut self) {
        let old_entry =
            CONNECTIONS.lock().expect("Connections mutex is poisoned").remove(&self.address);
        assert!(old_entry.is_some());
    }
}

pub type ChannelMockStream = tokio::io::DuplexStream;

impl PeerStream for ChannelMockStream {}

impl AsBannableAddress for Address {
    type BannableAddress = Address;

    fn as_bannable(&self) -> Self::BannableAddress {
        *self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        message::{BlockListRequest, Request},
        mock::{
            transport::BufferedTranscoder,
            types::{Message, MockRequestId},
        },
    };

    #[tokio::test]
    async fn send_recv() {
        let transport = MockChannelTransport::new();
        let address = ZERO_ADDRESS;
        let mut server = transport.bind(vec![address]).await.unwrap();
        let peer_fut = transport.connect(server.local_addresses().unwrap()[0]);

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let server_stream = server_res.unwrap().0;
        let peer_stream = peer_res.unwrap();

        let request_id = MockRequestId::new(1337u64);
        let request = Request::BlockListRequest(BlockListRequest::new(vec![]));
        let mut peer_stream = BufferedTranscoder::new(peer_stream);
        peer_stream
            .send(Message::Request {
                request_id,
                request: request.clone(),
            })
            .await
            .unwrap();

        let mut server_stream = BufferedTranscoder::new(server_stream);
        assert_eq!(
            server_stream.recv().await.unwrap(),
            Message::Request {
                request_id,
                request,
            }
        );
    }
}
