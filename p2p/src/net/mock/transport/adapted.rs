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

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::{sync::mpsc::UnboundedReceiver, time::timeout};

use crate::{error::P2pError, net::mock::peer::Role, Result};

use super::{MockListener, MockTransport, StreamAdapter};

// How much time is allowed to spend setting up (optionally) encrypted stream.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct AdaptedMockTransport<S, T> {
    stream_adapter: Arc<S>,
    base_transport: T,
}

#[async_trait]
impl<S: StreamAdapter<T::Stream>, T: MockTransport> MockTransport for AdaptedMockTransport<S, T> {
    type Address = T::Address;
    type BannableAddress = T::BannableAddress;
    type Listener = AdaptedListener<S, T>;
    type Stream = S::Stream;

    fn new() -> Self {
        let base_transport = T::new();
        let stream_adapter = Arc::new(S::new());
        Self {
            stream_adapter,
            base_transport,
        }
    }

    async fn bind(&self, address: Self::Address) -> Result<Self::Listener> {
        AdaptedListener::start(
            &self.base_transport,
            Arc::clone(&self.stream_adapter),
            address,
        )
        .await
    }

    async fn connect(&self, address: Self::Address) -> Result<Self::Stream> {
        let base = self.base_transport.connect(address).await?;
        let stream = self.stream_adapter.handshake(base, Role::Outbound).await?;
        Ok(stream)
    }
}

pub struct AdaptedListener<S: StreamAdapter<T::Stream>, T: MockTransport> {
    receiver: UnboundedReceiver<(S::Stream, T::Address)>,
    local_address: T::Address,
    join_handle: tokio::task::JoinHandle<()>,
}

impl<S: StreamAdapter<T::Stream>, T: MockTransport> AdaptedListener<S, T> {
    async fn start(transport: &T, stream_adapter: Arc<S>, address: T::Address) -> Result<Self> {
        let mut listener = transport.bind(address).await?;
        let local_address = listener.local_address()?;
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();

        // Process new connections in background because MockListener::accept must be cancel safe.
        let join_handle = tokio::spawn(async move {
            loop {
                let (base, addr) = match listener.accept().await {
                    Ok(stream) => stream,
                    Err(err) => {
                        logging::log::error!("TCP accept failed unexpectedly: {}", err);
                        return;
                    }
                };
                let sender = sender.clone();
                let stream_adapter_copy = Arc::clone(&stream_adapter);
                tokio::spawn(async move {
                    let res = timeout(
                        HANDSHAKE_TIMEOUT,
                        stream_adapter_copy.handshake(base, Role::Inbound),
                    )
                    .await;
                    let socket = match res {
                        Ok(Ok(socket)) => socket,
                        Ok(Err(err)) => {
                            logging::log::warn!("encryption handshake failed: {}", err);
                            return;
                        }
                        Err(err) => {
                            logging::log::warn!("encryption handshake timed out: {}", err);
                            return;
                        }
                    };
                    // It's not an error if the channel is already closed
                    _ = sender.send((socket, addr));
                });
            }
        });

        Ok(Self {
            receiver,
            local_address,
            join_handle,
        })
    }
}

impl<S: StreamAdapter<T::Stream>, T: MockTransport> Drop for AdaptedListener<S, T> {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

#[async_trait]
impl<S: StreamAdapter<T::Stream>, T: MockTransport> MockListener<S::Stream, T::Address>
    for AdaptedListener<S, T>
{
    async fn accept(&mut self) -> Result<(S::Stream, T::Address)> {
        self.receiver.recv().await.ok_or(P2pError::ChannelClosed)
    }

    fn local_address(&self) -> Result<T::Address> {
        Ok(self.local_address.clone())
    }
}
