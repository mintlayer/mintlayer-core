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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::P2pError;
    use crate::net::mock::{MockService, NetworkService, SocketService};
    use crate::peer::Peer;
    use parity_scale_codec::{Decode, Encode};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::select;

    #[derive(Debug, Encode, Decode, PartialEq, Eq)]
    struct Transaction {
        hash: u64,
        value: u128,
    }

    #[tokio::test]
    async fn test_new() {
        let srv_ipv4 = MockService::new("127.0.0.1:5555".parse().unwrap()).await;
        assert_eq!(srv_ipv4.is_ok(), true);

        // address already in use
        let err = MockService::new("127.0.0.1:5555".parse().unwrap()).await;
        assert_eq!(err.is_err(), true);

        // bind to IPv6 localhost
        let srv_ipv6 = MockService::new("[::1]:5555".parse().unwrap()).await;
        assert_eq!(srv_ipv6.is_ok(), true);

        // address already in use
        let s_ipv6 = MockService::new("[::1]:5555".parse().unwrap()).await;
        assert_eq!(err.is_err(), true);
    }

    #[tokio::test]
    async fn test_connect() {
        use tokio::net::TcpListener;

        // create `TcpListener`, spawn a task, and start accepting connections
        let addr: SocketAddr = "127.0.0.1:6666".parse().unwrap();
        let server = TcpListener::bind(addr).await.unwrap();

        tokio::spawn(async move {
            loop {
                if let Ok(_) = server.accept().await {}
            }
        });

        // create service that is used for testing `connect()`
        let srv = MockService::new("127.0.0.1:7777".parse().unwrap()).await;
        assert_eq!(srv.is_ok(), true);
        let mut srv = srv.unwrap();

        // try to connect to self, should fail
        let res = srv.connect("127.0.0.1:7777".parse().unwrap()).await;
        assert_eq!(res.is_err(), true);

        // try to connect to an address that (hopefully)
        // doesn't have a `TcpListener` running, should fail
        let res = srv.connect("127.0.0.1:1".parse().unwrap()).await;
        assert_eq!(res.is_err(), true);

        // try to connect to the `TcpListener` that was spawned above, should succeeed
        let res = srv.connect("127.0.0.1:6666".parse().unwrap()).await;
        assert_eq!(res.is_ok(), true);
    }

    #[tokio::test]
    async fn test_accept() {
        // create service that is used for testing `accept()`
        let addr: SocketAddr = "[::1]:9999".parse().unwrap();
        let mut srv = MockService::new("[::1]:9999".parse().unwrap()).await.unwrap();

        let (acc, con) = tokio::join!(srv.accept(), TcpStream::connect(addr));
        assert_eq!(acc.is_ok(), true);
        assert_eq!(con.is_ok(), true);

        // TODO: is there any sensible way to make `accept()` fail?
    }

    #[tokio::test]
    async fn test_peer_send() {
        let addr: SocketAddr = "[::1]:11112".parse().unwrap();
        let mut server = MockService::new(addr).await.unwrap();
        let remote_fut = TcpStream::connect(addr);

        let (server_res, remote_res) = tokio::join!(server.accept(), remote_fut);
        assert_eq!(server_res.is_ok(), true);
        assert_eq!(remote_res.is_ok(), true);

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut peer = Peer::<MockService>::new(1u128, server_res.unwrap(), tx, rx);
        let mut socket = remote_res.unwrap();

        // try to send data that implements `Encode + Decode`
        // and verify that it was received correctly
        let tx = Transaction {
            hash: 12345u64,
            value: 67890u128,
        };

        let mut buf = vec![0u8; 256];
        let (server_res, peer_res) = tokio::join!(socket.read(&mut buf), peer.socket.send(&tx));

        assert_eq!(peer_res.is_ok(), true);
        assert_eq!(server_res.is_ok(), true);
        assert_eq!(Decode::decode(&mut &buf[..]), Ok(tx));
    }

    #[tokio::test]
    async fn test_peer_recv() {
        // create a `MockService`, connect to it with a `TcpStream` and exchange data
        let addr: SocketAddr = "[::1]:11113".parse().unwrap();
        let mut server = MockService::new(addr).await.unwrap();
        let remote_fut = TcpStream::connect(addr);

        let (server_res, remote_res) = tokio::join!(server.accept(), remote_fut);
        assert_eq!(server_res.is_ok(), true);
        assert_eq!(remote_res.is_ok(), true);

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut peer = Peer::<MockService>::new(1u128, server_res.unwrap(), tx, rx);
        let mut socket = remote_res.unwrap();

        // send data and decode it successfully
        let tx = Transaction {
            hash: 12345u64,
            value: 67890u128,
        };
        let encoded = tx.encode();

        let (socket_res, peer_res): (_, Result<Transaction, _>) =
            tokio::join!(socket.write(&encoded), peer.socket.recv());
        assert_eq!(socket_res.is_ok(), true);
        assert_eq!(peer_res.is_ok(), true);
        assert_eq!(peer_res.unwrap(), tx);
    }
}
