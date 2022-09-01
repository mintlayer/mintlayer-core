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
use tokio::net::{TcpListener, TcpStream};

use crate::net::mock::{
    transport::{Connection, MakeAddress, Transport},
    types::Message,
};

pub struct MakeTcpAddress {}

impl MakeAddress for MakeTcpAddress {
    type Address = SocketAddr;

    fn make_address() -> Self::Address {
        "[::1]:0".parse().unwrap()
    }
}

#[derive(Debug)]
pub struct TcpTransport {}

#[async_trait]
impl Transport for TcpTransport {
    type Connection = TcpConnection;
    type Address = SocketAddr;

    async fn bind(address: Self::Address) -> Result<Self::Connection, super::Error> {
        // TODO: FIX error handling
        //Ok(TcpListener::bind(address).await.unwrap())
        todo!()
    }

    async fn connect(address: Self::Address) -> Result<Self::Connection, super::Error> {
        //TcpStream::connect(address)
        todo!()
    }
}

pub struct TcpConnection {}

#[async_trait]
impl Connection<TcpTransport> for TcpConnection {
    type Stream = ();

    async fn accept(&mut self) -> Result<(Self::Stream, SocketAddr), super::Error> {
        todo!()
    }

    async fn send(&mut self, msg: Message) -> Result<(), super::Error> {
        todo!()
    }

    async fn recv(&mut self) -> Result<Option<Message>, super::Error> {
        todo!()
    }
}
