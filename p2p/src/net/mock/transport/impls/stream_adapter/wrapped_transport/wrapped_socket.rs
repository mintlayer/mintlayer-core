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

use crate::net::mock::{
    peer::Role,
    transport::{impls::stream_adapter::traits::StreamAdapter, TransportSocket},
};

use super::wrapped_listener::AdaptedListener;

use crate::Result;

/// Transport layer that wraps a lower-level transport layer (can be seen like an onion with multiple layer)
/// Simplest version of this can be seen as a tcp transport layer, with an Identity stream_adapter. That would
/// be equivalent to the tcp transport layer with nothing done to it.
/// More layers can be added on top of this, with this struct, where we add encryption on top.
#[derive(Debug)]
pub struct WrappedTransportSocket<S, T> {
    pub stream_adapter: S,
    pub base_transport: T,
}

#[async_trait]
impl<S: StreamAdapter<T::Stream>, T: TransportSocket> TransportSocket
    for WrappedTransportSocket<S, T>
{
    type Address = T::Address;
    type BannableAddress = T::BannableAddress;
    type Listener = AdaptedListener<S, T>;
    type Stream = S::Stream;

    fn new() -> Self {
        let base_transport = T::new();
        let stream_adapter = S::new();
        Self {
            stream_adapter,
            base_transport,
        }
    }

    async fn bind(&self, address: Self::Address) -> Result<Self::Listener> {
        let stream_adapter = S::new();
        let listener = self.base_transport.bind(address).await?;
        Ok(AdaptedListener {
            listener,
            stream_adapter,
            handshakes: Vec::new(),
        })
    }

    async fn connect(&self, address: Self::Address) -> Result<Self::Stream> {
        // Not cancel safe!
        let base = self.base_transport.connect(address).await?;
        let stream = self.stream_adapter.handshake(base, Role::Outbound).await?;
        Ok(stream)
    }
}
