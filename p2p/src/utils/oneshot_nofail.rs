// Copyright (c) 2023 RBB S.r.l
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

//! Simple wrapper for the `tokio::sync::oneshot` channel
//! that does not return an error if the receiver is disconnected.
//!
//! The wrapper could be used when sending to a closed channel is not considered an error
//! (for example, when the async receiver was canceled for some reason).

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::sync::oneshot;

#[derive(Debug)]
pub struct Sender<T>(oneshot::Sender<T>);

impl<T> Sender<T> {
    pub fn send(self, t: T) {
        let _ = self.0.send(t);
    }
}

#[derive(Debug)]
pub struct Receiver<T>(oneshot::Receiver<T>);

impl<T> Future for Receiver<T> {
    type Output = Result<T, oneshot::error::RecvError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = oneshot::channel();
    (Sender(sender), Receiver(receiver))
}
