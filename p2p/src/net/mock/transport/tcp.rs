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

use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::net::TcpListener;

use crate::net::mock::{
    transport::{SocketService, TransportService},
    types::Message,
};

pub struct TcpService {}

#[async_trait]
impl TransportService for TcpService {
    type Socket = TcpSocket;
    type Address = SocketAddr;

    async fn bind(address: Self::Address) -> crate::Result<Self::Socket> {
        todo!()
    }

    async fn connect(address: Self::Address) -> crate::Result<Self::Socket> {
        todo!()
    }
}

struct TcpSocket {}

#[async_trait]
impl SocketService<TcpService> for TcpSocket {
    async fn accept(&mut self) -> crate::Result<(TcpService::Socket, TcpService::Address)> {
        todo!()
    }

    async fn connect(&mut self) -> crate::Result<TcpService::Socket> {
        todo!()
    }

    async fn send(&mut self, msg: Message) -> Result<(), std::io::Error> {
        todo!()
    }

    async fn recv(&mut self) -> Result<Option<Message>, std::io::Error> {
        todo!()
    }

    fn local_addr(&self) -> crate::Result<TcpService::Address> {
        todo!()
    }
}
