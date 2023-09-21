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

use tokio::sync::mpsc::unbounded_channel;

use chainstate::{ban_score::BanScore, BlockError, BlockSource, ChainstateError, CheckBlockError};
use chainstate_test_framework::{empty_witness, TestFramework, TransactionBuilder};
use common::{
    chain::{output_value::OutputValue, OutPointSourceId, TxInput, TxOutput},
    primitives::{Amount, Id, Idable, H256},
};
use consensus::{ConsensusPoSError, ConsensusVerificationError};
use crypto::random::Rng;
use mempool::error::{MempoolPolicyError, TxValidationError};
use test_utils::random::{make_seedable_rng, Seed};

use crate::{
    error::{P2pError, PeerError, ProtocolError},
    message::{HeaderList, SyncMessage},
    sync::{peer_common, tests::helpers::TestNode},
    testing_utils::for_each_protocol_version,
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
    logging::spawn_in_current_span(async move {
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
        let handle_res = peer_common::handle_message_processing_result(
            &peer_manager_sender,
            PeerId::new(),
            Err(err),
        )
        .await;
        assert_eq!(handle_res, Ok(()));
    }
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn receive_header_with_invalid_parent_block(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        // Create and process an invalid block. It is invalid because an included transaction does not
        // have any inputs and outputs. We deliberately ignore the processing error.
        let invalid_tx = TransactionBuilder::new().build();
        let invalid_parent_block =
            tf.make_block_builder().with_transactions(vec![invalid_tx]).build();
        let invalid_parent_block_id = invalid_parent_block.get_id();
        tf.process_block(invalid_parent_block, BlockSource::Local).unwrap_err();

        // Create a valid block linked to the invalid parent block. Do not process it. Its header will
        // be received from a peer instead.
        let valid_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(
                rng.gen_range(100_000..200_000),
            ))))
            .build();
        let valid_child_block = tf
            .make_block_builder()
            .with_transactions(vec![valid_tx])
            .with_parent(invalid_parent_block_id.into())
            .build();

        // Connect a peer and have it send the child header. Ensure the peer's ban score is increased.
        let mut node = TestNode::builder(protocol_version)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer_id = PeerId::new();
        node.connect_peer(peer_id, protocol_version).await;

        node.send_message(
            peer_id,
            SyncMessage::HeaderList(HeaderList::new(vec![valid_child_block.header().clone()])),
        )
        .await;

        let (adjusted_peer_id, ban_score_delta) = node.adjust_peer_score_event().await;
        assert_eq!(adjusted_peer_id, peer_id);
        assert_eq!(ban_score_delta, 100);

        node.join_subsystem_manager().await;
    })
    .await;
}
