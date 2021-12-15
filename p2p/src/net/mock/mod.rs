// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): A. Altonen
#![allow(dead_code, unused_variables, unused_imports)]
use crate::error::{self, P2pError};
use crate::net::{NetworkService, SocketService};
use crate::peer::Peer;
use async_trait::async_trait;
use parity_scale_codec::{Decode, Encode};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

mod tests;

/// This file provides a mock implementation of the network service.
/// It implements the `NetworkService` trait on top of `tokio::net::TcpListener`

#[derive(Debug)]
pub struct MockService {
    /// Local node's TCP socket for listening to incoming connections
    socket: TcpListener,

    /// Address the local node has bind itself to
    addr: SocketAddr,
}

#[derive(Debug)]
pub struct MockSocket {
    socket: TcpStream,
}

#[async_trait]
impl NetworkService for MockService {
    type Address = SocketAddr;
    type Socket = MockSocket;

    async fn new(addr: Self::Address) -> error::Result<Self> {
        Ok(Self {
            addr: addr,
            socket: TcpListener::bind(addr).await?,
        })
    }

    async fn connect(&mut self, addr: Self::Address) -> error::Result<Self::Socket> {
        if self.addr == addr {
            return Err(P2pError::SocketError(Error::new(
                ErrorKind::Other,
                "Connection to local node prohibited!",
            )));
        }

        Ok(MockSocket {
            socket: TcpStream::connect(addr).await?,
        })
    }

    async fn accept(&mut self) -> error::Result<Self::Socket> {
        // 0 is `TcpStream`, 1 is `SocketAddr`
        Ok(MockSocket {
            socket: self.socket.accept().await?.0,
        })
    }

    async fn publish<T>(&mut self, topic: &'static str, data: &T)
    where
        T: Sync + Send + Encode,
    {
        todo!();
    }

    async fn subscribe<T>(&mut self, topic: &'static str, tx: tokio::sync::mpsc::Sender<T>)
    where
        T: Send + Sync + Decode,
    {
        todo!();
    }
}

#[async_trait]
impl SocketService for MockSocket {
    async fn send<T>(&mut self, data: &T) -> error::Result<()>
    where
        T: Sync + Send + Encode,
    {
        match self.socket.write(&data.encode()).await? {
            0 => Err(P2pError::PeerDisconnected),
            _ => Ok(()),
        }
    }

    async fn recv<T>(&mut self) -> error::Result<T>
    where
        T: Decode,
    {
        let mut data = vec![0u8; 1024 * 1024];

        match self.socket.read(&mut data).await? {
            0 => Err(P2pError::PeerDisconnected),
            _ => Decode::decode(&mut &data[..]).map_err(|e| e.into()),
        }
    }
}
