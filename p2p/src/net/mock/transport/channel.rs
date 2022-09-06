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

use async_trait::async_trait;
use once_cell::sync::Lazy;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    oneshot,
};

use crate::{
    net::mock::{
        transport::{MockListener, MockStream, MockTransport},
        types::Message,
    },
    Result,
};

static NETWORK_HANDLE: Lazy<UnboundedSender<SocketCommand>> = Lazy::new(handle_connections);

struct SocketCommand {
    address: u64,
    response: oneshot::Sender<()>,
    command: SocketCommandType,
}

enum SocketCommandType {
    Connect,
    Bind,
}

#[derive(Debug)]
pub struct ChannelMockTransport {}

#[async_trait]
impl MockTransport for ChannelMockTransport {
    type Address = u64;
    type Listener = ChannelMockListener;
    type Stream = ChannelMockStream;

    async fn bind(address: Self::Address) -> Result<Self::Listener> {
        let tx: UnboundedSender<SocketCommand> = NETWORK_HANDLE.clone();
        // TODO: FIXME:
        todo!();
    }

    async fn connect(address: Self::Address) -> Result<Self::Stream> {
        // TODO: FIXME:
        todo!();
    }
}

pub struct ChannelMockListener {}

#[async_trait]
impl MockListener<ChannelMockStream, u64> for ChannelMockListener {
    async fn accept(&mut self) -> Result<(ChannelMockStream, u64)> {
        // TODO: FIXME:
        todo!();
    }

    fn local_address(&self) -> Result<u64> {
        todo!();
    }
}

pub struct ChannelMockStream {}

#[async_trait]
impl MockStream for ChannelMockStream {
    async fn send(&mut self, msg: Message) -> Result<()> {
        // TODO: FIXME:
        todo!();
    }

    async fn recv(&mut self) -> Result<Option<Message>> {
        // TODO: FIXME:
        todo!();
    }
}

fn handle_connections() -> UnboundedSender<SocketCommand> {
    let (tx, mut rx): (
        UnboundedSender<SocketCommand>,
        UnboundedReceiver<SocketCommand>,
    ) = unbounded_channel();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(cmd) => match cmd.command {
                    SocketCommandType::Connect => {
                        // TODO: check if peer with `address` has connected
                    }
                    SocketCommandType::Bind => {
                        // TODO: check if `address` is free and if it is, bind this peer to that address
                    }
                },
                None => break,
            }
        }
    });
    tx
}

// TODO: FIXME: Add a test for connections map.
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
