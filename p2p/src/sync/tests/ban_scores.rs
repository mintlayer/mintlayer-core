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

use chainstate::{ban_score::BanScore, BlockError, ChainstateError, CheckBlockError};
use common::primitives::{Id, H256};
use consensus::{ConsensusPoSError, ConsensusVerificationError};
use mempool::error::{MempoolPolicyError, TxValidationError};
use tokio::sync::mpsc::unbounded_channel;

use crate::{
    error::{P2pError, PeerError, ProtocolError},
    net::default_backend::{transport::TcpTransportSocket, DefaultNetworkingService},
    sync::peer::Peer,
    types::peer_id::PeerId,
};

#[test]
fn ban_scores() {
    // Test that ChainstateError p2p errors are reported correctly
    // (there was a bug where the NoKernel error had a score of 20).
    assert_eq!(
        P2pError::ChainstateError(ChainstateError::ProcessBlockError(
            BlockError::CheckBlockFailed(CheckBlockError::ConsensusVerificationFailed(
                ConsensusVerificationError::PoSError(ConsensusPoSError::NoKernel),
            )),
        ))
        .ban_score(),
        100
    );
}

#[tokio::test]
async fn peer_handle_result() {
    let (peer_manager_sender, mut peer_manager_receiver) = unbounded_channel();
    tokio::spawn(async move {
        while let Some(event) = peer_manager_receiver.recv().await {
            match event {
                crate::PeerManagerEvent::AdjustPeerScore(_, _, score) => {
                    score.send(Ok(()));
                }
                e => unreachable!("Unexpected event: {e:?}"),
            }
        }
    });

    // Test that the non-fatal errors are converted to Ok
    for err in [
        P2pError::PeerError(PeerError::PeerDoesntExist),
        P2pError::ProtocolError(ProtocolError::DisconnectedHeaders),
        P2pError::ChainstateError(ChainstateError::ProcessBlockError(
            BlockError::BlockAlreadyProcessed(Id::new(H256::zero())),
        )),
        P2pError::MempoolError(mempool::error::Error::Policy(
            MempoolPolicyError::MempoolFull,
        )),
        P2pError::MempoolError(mempool::error::Error::Validity(TxValidationError::TipMoved)),
    ] {
        let handle_res = Peer::<DefaultNetworkingService<TcpTransportSocket>>::handle_result(
            &peer_manager_sender,
            PeerId::new(),
            Err(err),
        )
        .await;
        assert_eq!(handle_res, Ok(()));
    }
}
