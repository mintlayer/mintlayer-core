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

use once_cell::sync::Lazy;
use tokio::sync::mpsc;

use crate::net::mock::{types::Message, SocketService, TransportService};

static NETWORK_HANDLE: Lazy<mpsc::UnboundedSender<SocketCommand>> = Lazy::new(|| {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Some(cmd) => match cmd {
                    SocketCommand::Connect(address) => {
                        // TODO: check if peer with `address` has connected
                    }
                    SocketCommand::Bind(address) => {
                        // TODO: check if `address` is free and if it is, bind this peer to that address
                    }
                },
                None => {
                    panic!("TODO")
                }
            }
        }
    });
    tx
});

enum SocketCommand {
    Connect(u64),
    Bind(u64),
}

#[derive(Debug)]
pub struct ChannelService {}

pub struct ChannelSocket {}

#[async_trait::async_trait]
impl TransportService for ChannelService {
    type Socket = ChannelSocket;
    type Address = u64;

    async fn bind(address: Self::Address) -> crate::Result<Self::Socket> {
        let tx: mpsc::UnboundedSender<SocketCommand> = NETWORK_HANDLE.clone();
        // TODO: FIXME:
        todo!();
    }

    async fn connect(address: Self::Address) -> crate::Result<Self::Socket> {
        // TODO: FIXME:
        todo!();
    }
}

#[async_trait::async_trait]
impl SocketService<ChannelService> for ChannelSocket {
    async fn accept(&mut self) -> crate::Result<(ChannelSocket, u64)> {
        // TODO: FIXME:
        todo!();
    }

    async fn connect(&mut self) -> crate::Result<ChannelSocket> {
        // TODO: FIXME:
        todo!();
    }

    async fn send(&mut self, msg: Message) -> Result<(), std::io::Error> {
        // TODO: FIXME:
        todo!();
    }

    async fn recv(&mut self) -> Result<Option<Message>, std::io::Error> {
        // TODO: FIXME:
        todo!();
    }

    fn local_addr(&self) -> crate::Result<u64> {
        // TODO: FIXME:
        todo!();
    }
}
