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

mod known_transactions;

use chainstate::ban_score::BanScore;
use logging::log;
use mempool::error::{Error as MempoolError, MempoolPolicyError};
use p2p_types::PeerId;
use tokio::sync::mpsc::UnboundedSender;

use crate::{
    error::{P2pError, PeerError},
    utils::oneshot_nofail,
    PeerManagerEvent, Result,
};

pub use known_transactions::KnownTransactions;

/// Handles a result of message processing.
///
/// There are three possible types of errors:
/// - Fatal errors will be propagated by this function effectively stopping the peer event loop.
/// - Non-fatal errors aren't propagated, but the peer score will be increased by the
///   "ban score" value of the given error.
/// - Ignored errors aren't propagated and don't affect the peer score.
pub async fn handle_result(
    peer_manager_sender: &UnboundedSender<PeerManagerEvent>,
    peer_id: PeerId,
    result: Result<()>,
) -> Result<()> {
    let error = match result {
        Ok(()) => return Ok(()),
        Err(e) => e,
    };

    match error {
        // Due to the fact that p2p is split into several tasks, it is possible to send a
        // request/response after a peer is disconnected, but before receiving the disconnect
        // event. Therefore this error can be safely ignored.
        P2pError::PeerError(PeerError::PeerDoesntExist) => Ok(()),
        // The special handling of these mempool errors is not really necessary, because their ban score is 0
        P2pError::MempoolError(MempoolError::Policy(
            MempoolPolicyError::MempoolFull | MempoolPolicyError::TransactionAlreadyInMempool,
        )) => Ok(()),

        // A protocol error - increase the ban score of a peer if needed.
        e @ (P2pError::ProtocolError(_)
        | P2pError::MempoolError(_)
        | P2pError::ChainstateError(_)) => {
            let ban_score = e.ban_score();
            if ban_score > 0 {
                log::info!(
                    "[peer id = {}] Adjusting peer's score by {}: {:?}",
                    peer_id,
                    ban_score,
                    e,
                );

                let (sender, receiver) = oneshot_nofail::channel();
                peer_manager_sender.send(PeerManagerEvent::AdjustPeerScore(
                    peer_id, ban_score, sender,
                ))?;
                receiver.await?.or_else(|e| match e {
                    P2pError::PeerError(PeerError::PeerDoesntExist) => Ok(()),
                    e => Err(e),
                })
            } else {
                log::debug!(
                    "[peer id = {}] Ignoring an error with the ban score of 0: {:?}",
                    peer_id,
                    e,
                );
                Ok(())
            }
        }

        // Some of these errors aren't technically fatal,
        // but they shouldn't occur in the sync manager.
        e @ (P2pError::DialError(_)
        | P2pError::ConversionError(_)
        | P2pError::PeerError(_)
        | P2pError::NoiseHandshakeError(_)
        | P2pError::InvalidConfigurationValue(_)
        | P2pError::MessageCodecError(_)) => panic!("Unexpected error {e:?}"),

        // Fatal errors, simply propagate them to stop the sync manager.
        // Note/TODO: due to how error types are currently organized, a storage error can
        // "hide" in other error types. E.g. ChainstateError can contain a BlockError, which
        // can contain a storage error (both directly and through other error types such as
        // PropertyQueryError). Also, MempoolError may contain ChainstateError through
        // TxValidationError. I.e. the code above may silently consume a fatal error,
        // leaving this struct in some intermediate state. Because of this, a malfunctioning
        // node may see its peers as behaving incorrectly and ban them eventually.
        e @ (P2pError::ChannelClosed
        | P2pError::SubsystemFailure
        | P2pError::StorageFailure(_)
        | P2pError::InvalidStorageState(_)) => Err(e),
    }
}
