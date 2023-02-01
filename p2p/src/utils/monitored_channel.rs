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

//! Simple wrapper for unbounded channel with monitoring.
//!
//! It will print a warning to the log if the queue grows above the limit.
//! Channel name, check period and limit can be customised using the Builder.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Weak,
    },
    time::Duration,
};

use tokio::sync::mpsc::{
    self,
    error::{SendError, TryRecvError},
};

pub struct UnboundedSender<T> {
    sender: mpsc::UnboundedSender<T>,
    send_count: Arc<AtomicU64>,
}

impl<T> Clone for UnboundedSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            send_count: self.send_count.clone(),
        }
    }
}

pub struct UnboundedReceiver<T> {
    receiver: mpsc::UnboundedReceiver<T>,
    recv_count: Arc<AtomicU64>,
}

impl<T> UnboundedSender<T> {
    pub fn send(&self, message: T) -> Result<(), SendError<T>> {
        // Incrementing the counter if sending fails is OK
        self.send_count.fetch_add(1, Ordering::Relaxed);
        self.sender.send(message)
    }
}

impl<T> UnboundedReceiver<T> {
    pub fn try_recv(&mut self) -> Result<T, TryRecvError> {
        let res = self.receiver.try_recv();
        if res.is_ok() {
            self.recv_count.fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    pub async fn recv(&mut self) -> Option<T> {
        let res = self.receiver.recv().await;
        if res.is_some() {
            self.recv_count.fetch_add(1, Ordering::Relaxed);
        }
        res
    }
}

pub struct Builder {
    name: String,
    check_period: Duration,
    warn_limit: u64,
}

impl Builder {
    fn new() -> Self {
        Self {
            name: "-".to_owned(),
            check_period: Duration::from_secs(60),
            warn_limit: 100,
        }
    }

    pub fn with_name(self, name: String) -> Self {
        Self { name, ..self }
    }

    pub fn with_check_period(self, check_period: Duration) -> Self {
        Self {
            check_period,
            ..self
        }
    }

    pub fn with_warn_limit(self, warn_limit: u64) -> Self {
        Self { warn_limit, ..self }
    }

    pub fn build<T>(self) -> (UnboundedSender<T>, UnboundedReceiver<T>) {
        unbounded_channel_from_builder(self)
    }
}

fn unbounded_channel_from_builder<T>(
    builder: Builder,
) -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    let (sender, receiver) = mpsc::unbounded_channel();
    let (send_count, recv_count) = Default::default();

    let send_count_copy: Arc<AtomicU64> = Arc::clone(&send_count);
    let recv_count_weak: Weak<AtomicU64> = Arc::downgrade(&recv_count);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(builder.check_period).await;
            let recv_count = match recv_count_weak.upgrade() {
                Some(send_count) => send_count,
                None => return,
            };
            let recv_count = recv_count.load(Ordering::Relaxed);
            let send_count = send_count_copy.load(Ordering::Relaxed);
            let queue = send_count.saturating_sub(recv_count);
            // It should also be easy to add send and receive rates
            if queue > builder.warn_limit {
                logging::log::warn!("channel {} grows to {}", builder.name, queue);
            }
        }
    });

    (
        UnboundedSender { sender, send_count },
        UnboundedReceiver {
            receiver,
            recv_count,
        },
    )
}

pub fn builder() -> Builder {
    Builder::new()
}

pub fn unbounded_channel<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    builder().build()
}
