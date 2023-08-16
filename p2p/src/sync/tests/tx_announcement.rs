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
        config::create_unit_test_config, output_value::OutputValue,
        signature::inputsig::InputWitness, GenBlock, OutPointSourceId, SignedTransaction,
        Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, Idable},
};
use mempool::{
    error::{Error as MempoolError, MempoolPolicyError},
    TxOrigin,
};
use test_utils::random::Seed;

use crate::{
    config::NodeType,
    error::ProtocolError,
    message::{SyncMessage, TransactionResponse},
    sync::tests::helpers::TestNode,
    testing_utils::test_p2p_config,
    types::peer_id::PeerId,
    P2pConfig, P2pError,
};

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_transaction(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();

    let p2p_config = Arc::new(test_p2p_config());
    let mut node = TestNode::builder()
        .with_chain_config(chain_config)
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let tx = Transaction::new(0x00, vec![], vec![]).unwrap();
    let tx = SignedTransaction::new(tx, vec![]).unwrap();
    node.send_message(peer, SyncMessage::NewTransaction(tx.transaction().get_id()))
        .await;

    let (sent_to, message) = node.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::TransactionRequest(tx.transaction().get_id())
    );

    node.send_message(
        peer,
        SyncMessage::TransactionResponse(TransactionResponse::Found(tx)),
    )
    .await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::MempoolError(MempoolError::Policy(MempoolPolicyError::NoInputs)).ban_score()
    );
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

// Transaction announcements are ignored during the initial block download, but it isn't considered
// an error or misbehavior.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_block_download() {
    let chain_config = Arc::new(create_unit_test_config());
    let mut node = TestNode::builder().with_chain_config(Arc::clone(&chain_config)).build().await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let tx = transaction(chain_config.genesis_block_id());
    node.send_message(peer, SyncMessage::NewTransaction(tx.transaction().get_id()))
        .await;

    node.assert_no_event().await;
    node.assert_no_peer_manager_event().await;
    node.assert_no_error().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_transaction_service(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();

    let p2p_config = Arc::new(P2pConfig {
        node_type: NodeType::BlocksOnly.into(),

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
        max_clock_diff: Default::default(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: "test".try_into().unwrap(),
        max_message_size: Default::default(),
        max_peer_tx_announcements: Default::default(),
        max_singular_unconnected_headers: Default::default(),
        sync_stalling_timeout: Default::default(),
    });
    let mut node = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let tx = transaction(chain_config.genesis_block_id());
    node.send_message(peer, SyncMessage::NewTransaction(tx.transaction().get_id()))
        .await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::UnexpectedMessage("".to_owned())).ban_score()
    );
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn too_many_announcements(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();

    let p2p_config = Arc::new(P2pConfig {
        node_type: NodeType::Full.into(),
        max_peer_tx_announcements: 0.into(),

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
        max_clock_diff: Default::default(),
        allow_discover_private_ips: Default::default(),
        msg_header_count_limit: Default::default(),
        msg_max_locator_count: Default::default(),
        max_request_blocks_count: Default::default(),
        user_agent: "test".try_into().unwrap(),
        max_message_size: Default::default(),
        max_singular_unconnected_headers: Default::default(),
        sync_stalling_timeout: Default::default(),
    });
    let mut node = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let tx = transaction(chain_config.genesis_block_id());
    node.send_message(peer, SyncMessage::NewTransaction(tx.transaction().get_id()))
        .await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::TransactionAnnouncementLimitExceeded(0)).ban_score()
    );
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicated_announcement(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();

    let p2p_config = Arc::new(test_p2p_config());
    let mut node = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let tx = transaction(chain_config.genesis_block_id());
    node.send_message(peer, SyncMessage::NewTransaction(tx.transaction().get_id()))
        .await;

    let (sent_to, message) = node.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::TransactionRequest(tx.transaction().get_id())
    );

    node.send_message(peer, SyncMessage::NewTransaction(tx.transaction().get_id()))
        .await;

    let (adjusted_peer, score) = node.adjust_peer_score_event().await;
    assert_eq!(peer, adjusted_peer);
    assert_eq!(
        score,
        P2pError::ProtocolError(ProtocolError::DuplicatedTransactionAnnouncement(
            tx.transaction().get_id()
        ))
        .ban_score()
    );
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_transaction(#[case] seed: Seed) {
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();

    let p2p_config = Arc::new(test_p2p_config());
    let mut node = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let tx = transaction(chain_config.genesis_block_id());
    node.send_message(peer, SyncMessage::NewTransaction(tx.transaction().get_id()))
        .await;

    let (sent_to, message) = node.message().await;
    assert_eq!(peer, sent_to);
    assert_eq!(
        message,
        SyncMessage::TransactionRequest(tx.transaction().get_id())
    );

    node.send_message(
        peer,
        SyncMessage::TransactionResponse(TransactionResponse::Found(tx.clone())),
    )
    .await;

    // There should be no `NewTransaction` message because the transaction is already known
    node.assert_no_event().await;

    node.join_subsystem_manager().await;
}

#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_sequence_via_orphan_pool(#[case] seed: Seed) {
    logging::init_logging(None::<&str>);
    let mut rng = test_utils::random::make_seedable_rng(seed);

    let chain_config = Arc::new(create_unit_test_config());
    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.as_ref().clone())
        .build();
    // Process a block to finish the initial block download.
    tf.make_block_builder().build_and_process().unwrap().unwrap();

    let p2p_config = Arc::new(test_p2p_config());
    let mut node = TestNode::builder()
        .with_chain_config(Arc::clone(&chain_config))
        .with_p2p_config(Arc::clone(&p2p_config))
        .with_chainstate(tf.into_chainstate())
        .build()
        .await;

    let peer = PeerId::new();
    node.connect_peer(peer).await;

    let mut txs = std::collections::BTreeMap::<Id<Transaction>, _>::new();

    let tx0 = Transaction::new(
        0x00,
        vec![TxInput::from_utxo(chain_config.genesis_block_id().into(), 0)],
        vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(100_000_000)),
            common::chain::Destination::AnyoneCanSpend,
        )],
    )
    .unwrap();
    let tx0 = SignedTransaction::new(tx0, vec![InputWitness::NoSignature(None)]).unwrap();
    let tx0_id = tx0.transaction().get_id();
    txs.insert(tx0_id, tx0.clone());

    let tx1 = Transaction::new(
        0x00,
        vec![TxInput::from_utxo(tx0.transaction().get_id().into(), 0)],
        vec![TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(90_000_000)))],
    )
    .unwrap();
    let tx1 = SignedTransaction::new(tx1, vec![InputWitness::NoSignature(None)]).unwrap();
    let tx1_id = tx1.transaction().get_id();
    txs.insert(tx1_id, tx1.clone());

    let res = node
        .mempool()
        .call_mut(|m| m.add_transaction(tx1, TxOrigin::LocalP2p))
        .await
        .unwrap();
    assert_eq!(res, Ok(mempool::TxStatus::InOrphanPool));

    // The transaction should be held up in the orphan pool for now, so we don't expect it to be
    // propagated at this point
    assert_eq!(node.try_message(), None);

    let res = node
        .mempool()
        .call_mut(|m| m.add_transaction(tx0, TxOrigin::LocalP2p))
        .await
        .unwrap();
    assert_eq!(res, Ok(mempool::TxStatus::InMempool));

    for tid in txs.keys() {
        logging::log::error!("Tx: {tid:?}");
    }

    // Now the orphan has been resolved, both transactions should be announced.
    for _ in 0..2 {
        let (_peer, msg) = node.message().await;
        logging::log::error!("Msg new: {msg:?}");
        let tx_id = match msg {
            SyncMessage::NewTransaction(tx_id) => tx_id,
            msg => panic!("Unexpected message {msg:?}"),
        };

        let _expected_tx = txs.remove(&tx_id).expect("An existing transaction");
    }

    // A small sanity check that we have sent all transactions
    assert!(txs.is_empty());

    node.join_subsystem_manager().await;
}

/// Creates a simple transaction.
fn transaction(out_point: Id<GenBlock>) -> SignedTransaction {
    let tx = Transaction::new(
        0x00,
        vec![TxInput::from_utxo(OutPointSourceId::from(out_point), 0)],
        vec![TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(1)))],
    )
    .unwrap();
    SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap()
}
