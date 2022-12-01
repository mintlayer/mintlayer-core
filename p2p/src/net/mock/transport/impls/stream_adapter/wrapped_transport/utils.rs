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

use crate::net::mock::transport::{impls::stream_adapter::traits::StreamAdapter, TransportSocket};

use std::{pin::Pin, task::Poll};

use futures::{future::BoxFuture, Future};

use crate::Result;

// Helper future used to drive handshakes concurrently.
// It works like FuturesUnordered but instead returning Poll::Ready(None) if empty it will return Poll::Pending.
pub struct HandshakeFut<'a, S: StreamAdapter<T::Stream>, T: TransportSocket>(
    #[allow(clippy::type_complexity)]
    pub  &'a mut Vec<(BoxFuture<'static, Result<S::Stream>>, T::Address)>,
);

impl<'a, S: StreamAdapter<T::Stream>, T: TransportSocket> Future for HandshakeFut<'a, S, T> {
    type Output = Result<(S::Stream, T::Address)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        for i in 0..self.0.len() {
            if let Poll::Ready(res) = Future::poll(self.0[i].0.as_mut(), cx) {
                let (_, addr) = self.0.swap_remove(i);
                return Poll::Ready(res.map(|stream| (stream, addr)));
            }
        }

        Poll::Pending
    }
}
