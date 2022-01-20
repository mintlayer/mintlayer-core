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
use crate::{
    error,
    net::{NetworkService, SocketService},
};
use async_trait::async_trait;
use libp2p::Multiaddr;
use parity_scale_codec::{Decode, Encode};

/// This file provides the libp2p implementation of the network service.

#[derive(Debug)]
pub struct Libp2pService {}

#[derive(Debug)]
pub struct Libp2pSocket {}

#[async_trait]
impl NetworkService for Libp2pService {
    type Address = Multiaddr;
    type Socket = Libp2pSocket;

    async fn new(_addr: Self::Address) -> error::Result<Self> {
        todo!();
    }

    async fn connect(&mut self, _addr: Self::Address) -> error::Result<Self::Socket> {
        todo!();
    }

    async fn accept(&mut self) -> error::Result<Self::Socket> {
        todo!();
    }

    async fn publish<T>(&mut self, _topic: &'static str, _data: &T)
    where
        T: Sync + Send + Encode,
    {
        todo!();
    }

    async fn subscribe<T>(&mut self, _topic: &'static str, _tx: tokio::sync::mpsc::Sender<T>)
    where
        T: Send + Sync + Decode,
    {
        todo!();
    }
}

#[async_trait]
impl SocketService for Libp2pSocket {
    async fn send<T>(&mut self, _data: &T) -> error::Result<()>
    where
        T: Sync + Send + Encode,
    {
        todo!();
    }

    async fn recv<T>(&mut self) -> error::Result<T>
    where
        T: Decode,
    {
        todo!();
    }
}
