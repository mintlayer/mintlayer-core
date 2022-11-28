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

use std::{collections::BTreeMap, io, pin::Pin, sync::Mutex};

use async_trait::async_trait;
use once_cell::sync::Lazy;
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream},
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        oneshot::{self, Sender},
    },
};

use crate::{
    error::DialError,
    net::{
        mock::transport::{MockListener, MockStream, MockTransport},
        AsBannableAddress, IsBannableAddress,
    },
    P2pError, Result,
};

// We need something that implements StreamKey, IdentityStreamKey from tcp::adapter works as well.
use super::tcp::adapter::identity::IdentityStreamKey;

type Address = u64;

/// Zero address has special meaning: bind to a free address.
const ZERO_ADDRESS: Address = 0;

static CONNECTIONS: Lazy<Mutex<BTreeMap<Address, UnboundedSender<Sender<DuplexStream>>>>> =
    Lazy::new(Default::default);

#[derive(Debug)]
pub struct ChannelMockTransport {}

#[async_trait]
impl MockTransport for ChannelMockTransport {
    type Address = Address;
    type BannableAddress = Address;
    type Listener = ChannelMockListener;
    type Stream = ChannelMockStream;

    async fn bind(
        _stream_key: &<<Self as MockTransport>::Stream as MockStream>::StreamKey,
        address: Self::Address,
    ) -> Result<Self::Listener> {
        let mut connections = CONNECTIONS.lock().expect("Connections mutex is poisoned");

        let address = if address == ZERO_ADDRESS {
            connections.iter().next_back().map_or(1, |(&a, _)| a + 1)
        } else {
            address
        };

        if connections.contains_key(&address) {
            return Err(P2pError::DialError(DialError::IoError(
                std::io::ErrorKind::AddrInUse,
            )));
        }

        let (sender, receiver) = unbounded_channel();
        assert!(connections.insert(address, sender).is_none());

        Ok(Self::Listener { address, receiver })
    }

    async fn connect(
        _stream_key: &<<Self as MockTransport>::Stream as MockStream>::StreamKey,
        address: Self::Address,
    ) -> Result<Self::Stream> {
        // A connection can only be established to a known address.
        assert_ne!(ZERO_ADDRESS, address);

        let server_sender = CONNECTIONS
            .lock()
            .expect("Connections mutex is poisoned")
            .get(&address)
            .ok_or(P2pError::DialError(DialError::NoAddresses))?
            .clone();
        let (connect_sender, connect_receiver) = oneshot::channel();
        server_sender
            .send(connect_sender)
            .map_err(|_| P2pError::DialError(DialError::NoAddresses))?;
        let channel = connect_receiver.await.map_err(|_| P2pError::ChannelClosed)?;

        Ok(Self::Stream { channel })
    }
}

pub struct ChannelMockListener {
    address: Address,
    receiver: UnboundedReceiver<Sender<DuplexStream>>,
}

#[async_trait]
impl MockListener<ChannelMockStream, Address> for ChannelMockListener {
    async fn accept(&mut self) -> Result<(ChannelMockStream, Address)> {
        let response_sender = self.receiver.recv().await.ok_or(P2pError::ChannelClosed)?;

        let (server, client) = tokio::io::duplex(10 * 1024 * 1024);
        response_sender.send(client).map_err(|_| P2pError::ChannelClosed)?;

        Ok((ChannelMockStream { channel: server }, self.address))
    }

    fn local_address(&self) -> Result<Address> {
        Ok(self.address)
    }
}

impl Drop for ChannelMockListener {
    fn drop(&mut self) {
        assert!(CONNECTIONS
            .lock()
            .expect("Connections mutex is poisoned")
            .remove(&self.address)
            .is_some());
    }
}

pub struct ChannelMockStream {
    channel: tokio::io::DuplexStream,
}

impl AsyncRead for ChannelMockStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.channel).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChannelMockStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, io::Error>> {
        Pin::new(&mut self.channel).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), io::Error>> {
        Pin::new(&mut self.channel).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), io::Error>> {
        Pin::new(&mut self.channel).poll_shutdown(cx)
    }
}

#[async_trait]
impl MockStream for ChannelMockStream {
    // TODO(PR): Replace ChannelMockStream with plain DuplexStream
    type StreamKey = IdentityStreamKey;
}

impl AsBannableAddress for Address {
    type BannableAddress = Address;

    fn as_bannable(&self) -> Self::BannableAddress {
        *self
    }
}

impl IsBannableAddress for Address {
    fn is_bannable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        message::{BlockListRequest, Request},
        mock::{
            transport::{EncoderDecoderWithBuf, StreamKey},
            types::{Message, MockRequestId},
        },
    };

    #[tokio::test]
    async fn send_recv() {
        let address = 0;
        let mut server = ChannelMockTransport::bind(&IdentityStreamKey::gen_new(), address)
            .await
            .unwrap();
        let client_key = IdentityStreamKey::gen_new();
        let peer_fut = ChannelMockTransport::connect(&client_key, server.local_address().unwrap());

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let server_stream = server_res.unwrap().0;
        let peer_stream = peer_res.unwrap();

        let request_id = MockRequestId::new(1337u64);
        let request = Request::BlockListRequest(BlockListRequest::new(vec![]));
        let mut peer_stream = EncoderDecoderWithBuf::new(peer_stream);
        peer_stream
            .send(Message::Request {
                request_id,
                request: request.clone(),
            })
            .await
            .unwrap();

        let mut server_stream = EncoderDecoderWithBuf::new(server_stream);
        assert_eq!(
            server_stream.recv().await.unwrap().unwrap(),
            Message::Request {
                request_id,
                request,
            }
        );
    }
}
