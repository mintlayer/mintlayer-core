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

/// A wrapper around [`tokio::sync::broadcast::Sender`] that only allows subscribing to the
/// messages but not sending them.
#[derive(Debug, Clone)]
pub struct Topic<T>(tokio::sync::broadcast::Sender<T>);

impl<T> Topic<T> {
    /// Creates a new [`tokio::sync::broadcast::Receiver`] handle that will receive values sent
    /// after this call to subscribe.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<T> {
        self.0.subscribe()
    }
}

impl<T> From<tokio::sync::broadcast::Sender<T>> for Topic<T> {
    fn from(sender: tokio::sync::broadcast::Sender<T>) -> Self {
        Self(sender)
    }
}
