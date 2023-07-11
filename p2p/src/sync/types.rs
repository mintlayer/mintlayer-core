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

use std::time::Duration;

use common::{chain::Transaction, primitives::Id};
use tokio::sync::oneshot;

use crate::{types::peer_id::PeerId, utils::oneshot_nofail};

/// Activity with a peer.
#[derive(Debug)]
pub enum PeerActivity {
    /// Node is pending for further actions with a peer.
    Pending,
    /// Node has sent a header list request to a peer and is expecting a header list response.
    ExpectingHeaderList {
        /// A time when the header list request was sent.
        time: Duration,
    },
    /// Node has sent a block list request to a peer and is expecting block responses.
    ExpectingBlocks {
        /// A time when either the block list request was sent or last block response was received.
        time: Duration,
    },
}

#[derive(Debug)]
pub enum PeerEvent {
    Disconnected(PeerId),
}

#[derive(Debug)]
pub enum RequestTrackerEvent {
    /// Try to request a transaction from a peer. Note that only a single transaction request can
    /// be in flight at a time. The tracker will handle synchronization and peer-communication.
    RequestTransactionPermit(TransactionPermitRequest),

    /// Notify the tracker that a transaction request was completed (either succeeded or failed).
    CompleteTransaction(CompleteTransaction),
}

#[derive(Debug)]
pub struct TransactionPermitRequest {
    pub peer_id: PeerId,
    pub tx_id: Id<Transaction>,
    pub allow_tx: oneshot_nofail::Sender<oneshot::Receiver<()>>,
}

#[derive(Debug)]
pub struct CompleteTransaction {
    pub peer_id: PeerId,
    pub tx_id: Id<Transaction>,
    pub result: Result<(), TransactionRequestError>,
}

#[derive(thiserror::Error, Debug)]
pub enum TransactionRequestError {
    #[error("Timed out waiting for transaction response")]
    Timeout,
}

#[derive(Debug)]
pub enum TransactionAction {
    Proceed(Id<Transaction>),
    Cancel(Id<Transaction>),
}
