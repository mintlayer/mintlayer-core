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

use crate::net::mock::{
    transport::{Connection, MakeAddress, Transport},
    types::Message,
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

pub struct MakeChannelAddress {}

impl MakeAddress for MakeChannelAddress {
    type Address = u64;

    fn make_address() -> Self::Address {
        todo!()
    }
}

#[derive(Debug)]
pub struct ChannelTransport {}

#[async_trait]
impl Transport for ChannelTransport {
    type Connection = ChannelConnection;
    type Address = u64;

    async fn bind(address: Self::Address) -> Result<Self::Connection, super::Error> {
        let tx: UnboundedSender<SocketCommand> = NETWORK_HANDLE.clone();
        // TODO: FIXME:
        todo!();
    }

    async fn connect(address: Self::Address) -> Result<Self::Connection, super::Error> {
        // TODO: FIXME:
        todo!();
    }
}

pub struct ChannelConnection {}

#[async_trait]
impl Connection<ChannelTransport> for ChannelConnection {
    type Stream = ();

    async fn accept(&mut self) -> Result<(Self::Stream, u64), super::Error> {
        // TODO: FIXME:
        todo!();
    }

    async fn send(&mut self, msg: Message) -> Result<(), super::Error> {
        // TODO: FIXME:
        todo!();
    }

    async fn recv(&mut self) -> Result<Option<Message>, super::Error> {
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
