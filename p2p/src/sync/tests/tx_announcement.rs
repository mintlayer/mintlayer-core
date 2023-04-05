// Copyright (c) 2022 RBB S.r.l
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

use std::sync::Arc;

use chainstate::ban_score::BanScore;
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        config::create_unit_test_config, signature::inputsig::InputWitness, tokens::OutputValue,
        GenBlock, OutPointSourceId, SignedTransaction, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id},
};
use mempool::error::{Error as MempoolError, TxValidationError};
use p2p_test_utils::start_subsystems_with_chainstate;
use test_utils::random::Seed;

use crate::{
    config::NodeType,
    error::ProtocolError,
    message::{Announcement, SyncMessage, TransactionResponse},
    sync::tests::helpers::SyncManagerHandle,
    testing_utils::test_p2p_config,
    types::peer_id::PeerId,
    P2pConfig, P2pError,
};

#[tokio::test]
#[should_panic = "Received a message from unknown peer"]
async fn nonexistent_peer() {
    let mut handle = SyncManagerHandle::builder().build().await;

    let peer = PeerId::new();

    let tx = Transaction::new(0x00, vec![], vec![], 0x01).unwrap();
    let tx = SignedTransaction::new(tx, vec![]).unwrap();
    handle.make_announcement(peer, Announcement::Transaction(tx.serialized_hash()));

    handle.resume_panic().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn invalid_transaction(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config));

    let p2p_config = Arc::new(test_p2p_config());
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let tx = Transaction::new(0x00, vec![], vec![], 0x01).unwrap();
    let tx = SignedTransaction::new(tx, vec![]).unwrap();
    handle.make_announcement(peer, Announcement::Transaction(tx.serialized_hash()));

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::TransactionRequest(tx.serialized_hash())
    );

    handle.send_message(
        peer,
        SyncMessage::TransactionResponse(TransactionResponse::Found(tx)),
    );

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::MempoolError(MempoolError::TxValidationError(TxValidationError::NoInputs))
            .ban_score()
    );
    handle.assert_no_event().await;
}

// Transaction announcements are ignored during the initial block download, but it isn't considered
// an error or misbehavior.
#[tokio::test]
async fn initial_block_download() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let tx = transaction(chain_config.genesis_block_id());
    handle.make_announcement(peer, Announcement::Transaction(tx.serialized_hash()));

    handle.assert_no_event().await;
    handle.assert_no_peer_manager_event().await;
    handle.assert_no_error().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn no_transaction_service(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config));

    let p2p_config = Arc::new(P2pConfig {
        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        max_inbound_connections: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        node_type: NodeType::BlocksOnly.into(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: "test".try_into().unwrap(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
    });
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let tx = transaction(chain_config.genesis_block_id());
    handle.make_announcement(peer, Announcement::Transaction(tx.serialized_hash()));

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::UnexpectedMessage("")).ban_score()
    );
    handle.assert_no_event().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn too_many_announcements(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config));

    let p2p_config = Arc::new(P2pConfig {
        bind_addresses: Default::default(),
        socks5_proxy: Default::default(),
        disable_noise: Default::default(),
        boot_nodes: Default::default(),
        reserved_nodes: Default::default(),
        max_inbound_connections: Default::default(),
        ban_threshold: Default::default(),
        ban_duration: Default::default(),
        outbound_connection_timeout: Default::default(),
        ping_check_period: Default::default(),
        ping_timeout: Default::default(),
        node_type: NodeType::Full.into(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: "test".try_into().unwrap(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: 0.into(),
    });
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let tx = transaction(chain_config.genesis_block_id());
    handle.make_announcement(peer, Announcement::Transaction(tx.serialized_hash()));

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::TransactionAnnouncementLimitExceeded(0)).ban_score()
    );
    handle.assert_no_event().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn duplicated_announcement(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config));

    let p2p_config = Arc::new(test_p2p_config());
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let tx = transaction(chain_config.genesis_block_id());
    handle.make_announcement(peer, Announcement::Transaction(tx.serialized_hash()));

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::TransactionRequest(tx.serialized_hash())
    );

    handle.make_announcement(peer, Announcement::Transaction(tx.serialized_hash()));

    let (adjusted_peer, score) = handle.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::DuplicatedTransactionAnnouncement(
            tx.serialized_hash()
        ))
        .ban_score()
    );
    handle.assert_no_event().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test]
async fn valid_transaction(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();
    let (chainstate, mempool) =
        start_subsystems_with_chainstate(tf.into_chainstate(), Arc::clone(&chain_config));

    let p2p_config = Arc::new(test_p2p_config());
    let mut handle = SyncManagerHandle::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_subsystems(chainstate, mempool)
        .build()
        .await;

    let peer = PeerId::new();
    handle.connect_peer(peer).await;

    let tx = transaction(chain_config.genesis_block_id());
    handle.make_announcement(peer, Announcement::Transaction(tx.serialized_hash()));

    let (sent_to, message) = handle.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::TransactionRequest(tx.serialized_hash())
    );

    handle.send_message(
        peer,
        SyncMessage::TransactionResponse(TransactionResponse::Found(tx.clone())),
    );

    assert_eq!(
        Announcement::Transaction(tx.serialized_hash()),
        handle.announcement().await
    );
}

/// Creates a simple transaction.
fn transaction(out_point: Id<GenBlock>) -> SignedTransaction {
    let tx = Transaction::new(
        0x00,
        vec![TxInput::new(OutPointSourceId::from(out_point), 0)],
        vec![TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(1)))],
        0x01,
    )
    .unwrap();
    SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap()
}
