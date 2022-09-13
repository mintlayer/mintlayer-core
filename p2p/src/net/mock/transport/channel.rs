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

use std::{collections::BTreeMap, io, sync::Mutex};

use async_trait::async_trait;
use once_cell::sync::Lazy;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot::{self, Sender},
};

use crate::{
    error::DialError,
    net::mock::{
        transport::{MockListener, MockStream, MockTransport},
        types::Message,
    },
    P2pError, Result,
};

type Address = u64;
type MessageSender = UnboundedSender<Message>;
type MessageReceiver = UnboundedReceiver<Message>;
type AcceptResponse = (MessageSender, MessageReceiver);

/// Zero address has special meaning: bind to a free address.
const ZERO_ADDRESS: Address = 0;

static CONNECTIONS: Lazy<Mutex<BTreeMap<Address, UnboundedSender<Sender<AcceptResponse>>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

#[derive(Debug)]
pub struct ChannelMockTransport {}

#[async_trait]
impl MockTransport for ChannelMockTransport {
    type Address = Address;
    type Listener = ChannelMockListener;
    type Stream = ChannelMockStream;

    async fn bind(address: Self::Address) -> Result<Self::Listener> {
        let mut connections = CONNECTIONS.lock().expect("Connections mutex is poisoned");

        let address = if address == ZERO_ADDRESS {
            connections.iter().next_back().map_or(1, |(&a, _)| a + 1)
        } else {
            address
        };

        let (sender, receiver) = unbounded_channel();
        assert!(connections.insert(address, sender).is_none());

        Ok(Self::Listener { address, receiver })
    }

    async fn connect(address: Self::Address) -> Result<Self::Stream> {
        // A connection can only be established to a known address.
        debug_assert_ne!(ZERO_ADDRESS, address);

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
        let (sender, receiver) = connect_receiver.await.map_err(|_| P2pError::ChannelClosed)?;

        Ok(Self::Stream { sender, receiver })
    }
}

pub struct ChannelMockListener {
    address: Address,
    receiver: UnboundedReceiver<Sender<AcceptResponse>>,
}

#[async_trait]
impl MockListener<ChannelMockStream, Address> for ChannelMockListener {
    async fn accept(&mut self) -> Result<(ChannelMockStream, Address)> {
        let response_sender = self.receiver.recv().await.ok_or(P2pError::ChannelClosed)?;

        let (server_sender, server_receiver) = unbounded_channel();
        let (peer_sender, peer_receiver) = unbounded_channel();
        response_sender
            .send((peer_sender, server_receiver))
            .map_err(|_| P2pError::ChannelClosed)?;

        Ok((
            ChannelMockStream {
                sender: server_sender,
                receiver: peer_receiver,
            },
            self.address,
        ))
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
    sender: MessageSender,
    receiver: MessageReceiver,
}

#[async_trait]
impl MockStream for ChannelMockStream {
    async fn send(&mut self, msg: Message) -> Result<()> {
        self.sender.send(msg).map_err(|_| P2pError::ChannelClosed)
    }

    async fn recv(&mut self) -> Result<Option<Message>> {
        // To preserve the TCP implementation behaviour, return the `UnexpectedEof` error when
        // the channel is closed.
        self.receiver
            .recv()
            .await
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof).into())
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        message::{BlockListRequest, Request},
        mock::types::MockRequestId,
    };

    #[tokio::test]
    async fn send_recv() {
        let address = 0;
        let mut server = ChannelMockTransport::bind(address).await.unwrap();
        let peer_fut = ChannelMockTransport::connect(server.local_address().unwrap());

        let (server_res, peer_res) = tokio::join!(server.accept(), peer_fut);
        let mut server_stream = server_res.unwrap().0;
        let mut peer_stream = peer_res.unwrap();

        let msg = Message::Request {
            request_id: MockRequestId::new(1337u64),
            request: Request::BlockListRequest(BlockListRequest::new(vec![])),
        };
        peer_stream.send(msg.clone()).await.unwrap();

        assert_eq!(server_stream.recv().await.unwrap().unwrap(), msg);
    }
}
