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
use futures::future::BoxFuture;

use crate::{
    net::mock::{
        peer::Role,
        transport::{
            impls::stream_adapter::{
                traits::StreamAdapter, wrapped_transport::utils::HandshakeFut,
            },
            TransportListener, TransportSocket,
        },
    },
    Result,
};

// TODO: Move this constant to some configuration + should be used
// to initialize a const member in AdaptedListener
// (a better suggestion is OK based on research)
pub const MAX_CONCURRENT_HANDSHAKES: usize = 100;

/// A listener (acceptor) object that handles new incoming connections, and does any required handshakes
pub struct AdaptedListener<S: StreamAdapter<T::Stream>, T: TransportSocket> {
    pub stream_adapter: S,
    pub listener: T::Listener,
    #[allow(clippy::type_complexity)]
    pub handshakes: Vec<(BoxFuture<'static, Result<S::Stream>>, T::Address)>,
}

#[async_trait]
impl<S: StreamAdapter<T::Stream>, T: TransportSocket> TransportListener<S::Stream, T::Address>
    for AdaptedListener<S, T>
{
    async fn accept(&mut self) -> Result<(S::Stream, T::Address)> {
        loop {
            let accept_new = self.handshakes.len() < MAX_CONCURRENT_HANDSHAKES;
            tokio::select! {
                handshake_res = HandshakeFut::<S, T>(&mut self.handshakes) => {
                    match handshake_res {
                        Ok(handshake) => return Ok(handshake),
                        Err(err) => {
                            logging::log::warn!("handshake failed: {}", err);
                            continue;
                        },
                    }
                }
                accept_res = self.listener.accept(), if accept_new => {
                    match accept_res {
                        Ok((base, addr)) => {
                            // Store active handshakes because accept must be cancel safe
                            let handshake = self.stream_adapter.handshake(base, Role::Inbound);
                            self.handshakes.push((handshake, addr));
                        },
                        Err(err) => {
                            logging::log::error!("accept failed unexpectedly: {}", err);
                            return Err(err);
                        },
                    }
                }
            }
        }
    }

    fn local_address(&self) -> Result<T::Address> {
        self.listener.local_address()
    }
}
