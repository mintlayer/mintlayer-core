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
pub struct Sender<T> {
    name: &'static str,
    sender: mpsc::Sender<T>,
}

impl<T> Sender<T> {
    /// Sends a value to the channel. Returns `SendError` if the opposite side of the channels is
    /// closed and the shutdown is in progress, panics otherwise.
    pub async fn send(&self, val: T, shutdown: &AtomicBool) -> Result<(), SendError<T>> {
        match self.sender.send(val).await {
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

#[derive(Debug)]
pub struct Receiver<T> {
    name: &'static str,
    receiver: mpsc::Receiver<T>,
}

impl<T> Sender<T> {
    /// Receives a value from the channel. Returns `None` if the opposite side of the channel is
    /// closed and the shutdown is in progress, panics otherwise.
    pub async fn recv(&mut self, shutdown: &AtomicBool) -> Option<T> {
        match self.0.recv().await {
            Some(val) => val,
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

pub fn channel<T>(name: &'static str) -> (Sender<T>, Receiver<T>) {
    let (sender, receiver) = mpsc::channel();
    let sender = Sender { name, sender };
    let receiver = Receiver { name, receiver };
    (sender, receiver)
}
