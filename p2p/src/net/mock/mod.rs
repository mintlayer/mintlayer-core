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
use crate::error::P2pError;
use crate::peer::Peer;
use crate::net::{NetworkService, PeerService};
use async_trait::async_trait;
use parity_scale_codec::{Decode, Encode};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// This file provides a mock implementation of the network service.
/// It implements the `NetworkService` trait on top of `tokio::net::TcpListener`

pub struct MockService {
    /// Local node's TCP socket for listening to incoming connections
    socket: TcpListener,
}

#[async_trait]
impl NetworkService for MockService {
    type Address = SocketAddr;
    type Socket = TcpStream;

    async fn new(addr: Self::Address) -> Result<Self, P2pError> {
        todo!();
    }

    async fn connect(&mut self, addr: Self::Address) -> Result<Self::Socket, P2pError> {
        todo!();
    }

    async fn accept(&mut self) -> Result<Self::Socket, P2pError> {
        todo!();
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
impl PeerService for Peer {
    async fn send<T>(&mut self, data: &T) -> Result<(), P2pError>
    where
        T: Sync + Send + Encode,
    {
        todo!();
    }

    async fn recv<T>(&mut self) -> Result<T, P2pError>
    where
        T: Decode,
    {
        todo!();
    }
}
