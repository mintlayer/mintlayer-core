// Copyright (c) 2026 RBB S.r.l
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

use tokio::sync::mpsc;

/// A wrapper that imitates `UnboundedSender<T>`, while actually sending `(Id, T)`.
pub struct MpscUnboundedSenderWithId<Id: Clone, T> {
    id: Id,
    sender: mpsc::UnboundedSender<(Id, T)>,
}

impl<Id: Clone, T> MpscUnboundedSenderWithId<Id, T> {
    pub fn new(id: Id, sender: mpsc::UnboundedSender<(Id, T)>) -> Self {
        Self { id, sender }
    }

    pub fn send(&self, message: T) -> Result<(), mpsc::error::SendError<T>> {
        self.sender
            .send((self.id.clone(), message))
            .map_err(|err| mpsc::error::SendError(err.0.1))
    }

    pub async fn closed(&self) {
        self.sender.closed().await
    }

    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}
