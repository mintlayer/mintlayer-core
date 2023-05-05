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

//! A wrapper for the `tokio::sync::mpsc` channel with an interface adapted for the shutdown flag
//! checking.
//!
//! Both `send` and `recv` methods take the shutdown flag as an additional argument. These methods
//! panic if the opposite side of the channel is closed.

use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::mpsc::{self, error::SendError};

#[derive(Debug)]
pub struct UnboundedSender<T> {
    name: &'static str,
    sender: mpsc::UnboundedSender<T>,
}

impl<T> UnboundedSender<T> {
    /// Sends a value to the channel. Returns `SendError` if the opposite side of the channels is
    /// closed and the shutdown is in progress, panics otherwise.
    pub fn send(&self, val: T, shutdown: &AtomicBool) -> Result<(), SendError<T>> {
        match self.sender.send(val) {
            Ok(()) => Ok(()),
            Err(e) => {
                if shutdown.load(Ordering::Acquire) {
                    Ok(())
                } else {
                    panic!("{} sender has been closed unexpectedly", self.name);
                }
            }
        }
    }
}

impl<T> Clone for UnboundedSender<T> {
    fn clone(&self) -> Self {
        Self {
            name: self.name,
            sender: self.sender.clone(),
        }
    }
}

#[derive(Debug)]
pub struct UnboundedReceiver<T> {
    name: &'static str,
    receiver: mpsc::UnboundedReceiver<T>,
}

impl<T> UnboundedReceiver<T> {
    /// Receives a value from the channel. Returns `None` if the opposite side of the channel is
    /// closed and the shutdown is in progress, panics otherwise.
    pub async fn recv(&mut self, shutdown: &AtomicBool) -> Option<T> {
        match self.receiver.recv().await {
            Some(val) => Some(val),
            None => {
                if shutdown.load(Ordering::Acquire) {
                    None
                } else {
                    panic!("{} receiver has been closed unexpectedly", self.name);
                }
            }
        }
    }
}

pub fn unbounded_channel<T>(name: &'static str) -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let sender = UnboundedSender { name, sender };
    let receiver = UnboundedReceiver { name, receiver };
    (sender, receiver)
}
