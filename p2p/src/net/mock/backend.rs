// Copyright (c) 2022 RBB S.r.l
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
use crate::{
    error::{self, P2pError},
    net::mock::types,
    net::{NetworkService, PubSubTopic},
};
use async_trait::async_trait;
use futures::FutureExt;
// use futures_timer::Delay;
use logging::log;
use parity_scale_codec::{Decode, Encode};
use std::{
    collections::HashMap,
    io::{Error, ErrorKind},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
};

pub struct Backend {
    /// Socket address of the backend
    addr: SocketAddr,

    /// Socket for listening to incoming connections
    socket: TcpListener,

    /// RX channel for receiving commands from the frontend
    cmd_rx: mpsc::Receiver<types::Command>,

    /// TX channel for sending events to the frontend
    conn_tx: mpsc::Sender<types::ConnectivityEvent>,

    /// TX channel for sending events to the frontend
    _flood_tx: mpsc::Sender<types::FloodsubEvent>,

    /// Timeout for outbound operations
    timeout: std::time::Duration,
}

impl Backend {
    pub fn new(
        addr: SocketAddr,
        socket: TcpListener,
        cmd_rx: mpsc::Receiver<types::Command>,
        conn_tx: mpsc::Sender<types::ConnectivityEvent>,
        _flood_tx: mpsc::Sender<types::FloodsubEvent>,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            addr,
            socket,
            cmd_rx,
            conn_tx,
            _flood_tx,
            timeout,
        }
    }

    pub async fn run(&mut self) -> error::Result<()> {
        loop {
            tokio::select! {
                event = self.socket.accept() => match event {
                    Ok(socket) => self.conn_tx.send(types::ConnectivityEvent::IncomingConnection {
                        peer_id: socket.1,
                        socket: socket.0,
                    }).await?,
                    Err(e) => {
                        log::error!("accept() failed: {:?}", e);
                        return Err(P2pError::SocketError(e.kind()));
                    }
                },
                event = self.cmd_rx.recv().fuse() => match event.ok_or(P2pError::ChannelClosed)? {
                    types::Command::Connect { addr, response } => {
                        if self.addr == addr {
                            let _ = response.send(Err(P2pError::SocketError(ErrorKind::AddrNotAvailable)));
                            continue;
                        }

                        tokio::select! {
                            _ = tokio::time::sleep(self.timeout) => {
                                let _ = response.send(Err(
                                    P2pError::SocketError(std::io::ErrorKind::ConnectionRefused))
                                );
                            }
                            res = TcpStream::connect(addr) => match res {
                                Ok(socket) => { let _ = response.send(Ok(socket)); },
                                Err(e) => { let _ = response.send(Err(e.into())); },
                            }
                        }
                    }
                }
            }
        }
    }
}
