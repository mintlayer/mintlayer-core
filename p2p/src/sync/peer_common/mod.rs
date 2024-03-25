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

use chainstate::{ban_score::BanScore, chainstate_interface::ChainstateInterface};
use common::{chain::GenBlock, primitives::Id, Uint256};
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
pub async fn handle_message_processing_result(
    peer_mgr_event_sender: &UnboundedSender<PeerManagerEvent>,
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
        P2pError::MempoolError(MempoolError::Policy(MempoolPolicyError::MempoolFull)) => Ok(()),

        // A protocol error - increase the ban score of a peer if needed.
        e @ (P2pError::ProtocolError(_)
        | P2pError::MempoolError(_)
        | P2pError::ChainstateError(_)
        | P2pError::SyncError(_)) => {
            let ban_score = e.ban_score();
            if ban_score > 0 {
                log::info!(
                    "[peer id = {}] Adjusting peer's score by {}: {:?}",
                    peer_id,
                    ban_score,
                    e,
                );

                let (sender, receiver) = oneshot_nofail::channel();
                peer_mgr_event_sender.send(PeerManagerEvent::AdjustPeerScore(
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
        | P2pError::PeerError(_)
        | P2pError::NoiseHandshakeError(_)
        | P2pError::InvalidConfigurationValue(_)
        | P2pError::MessageCodecError(_)
        | P2pError::ConnectionValidationFailed(_)) => panic!("Unexpected error {e:?}"),

        // Fatal errors, simply propagate them to stop the sync manager.
        // Note: due to how error types are currently organized, a storage error can
        // "hide" in other error types. E.g. ChainstateError can contain a BlockError, which
        // can contain a storage error (both directly and through other error types such as
        // PropertyQueryError). Also, MempoolError may contain ChainstateError through
        // TxValidationError. I.e. the code above may silently consume a fatal error,
        // leaving this struct in some intermediate state. Because of this, a malfunctioning
        // node may see its peers as behaving incorrectly; but since we only discourage
        // on misbehavior and not ban, this shouldn't be a big problem.
        e @ (P2pError::ChannelClosed
        | P2pError::SubsystemFailure
        | P2pError::StorageFailure(_)
        | P2pError::InvalidStorageState(_)
        | P2pError::PeerDbStorageVersionMismatch {
            expected_version: _,
            actual_version: _,
        }) => Err(e),
    }
}

/// This function is used to update peers_best_block_that_we_have.
/// The "better" block is the one that is on the main chain and has a higher chain-trust.
/// In the case of a tie, new_block_id is preferred.
pub fn choose_peers_best_block(
    chainstate: &dyn ChainstateInterface,
    old_block_id: Option<Id<GenBlock>>,
    new_block_id: Option<Id<GenBlock>>,
) -> Result<Option<Id<GenBlock>>> {
    match (old_block_id, new_block_id) {
        (None, None) => Ok(None),
        (Some(id), None) | (None, Some(id)) => Ok(Some(id)),
        (Some(old_id), Some(new_id)) => {
            let old_block_chain_trust = chainstate
                .get_gen_block_index(&old_id)?
                .map_or(Uint256::ZERO, |idx| idx.chain_trust());
            let new_block_chain_trust = chainstate
                .get_gen_block_index(&new_id)?
                .map_or(Uint256::ZERO, |idx| idx.chain_trust());
            if new_block_chain_trust >= old_block_chain_trust {
                Ok(Some(new_id))
            } else {
                Ok(Some(old_id))
            }
        }
    }
}
