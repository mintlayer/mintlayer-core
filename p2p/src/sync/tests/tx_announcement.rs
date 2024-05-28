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

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use chainstate::{ban_score::BanScore, BlockSource};
use chainstate_test_framework::{anyonecanspend_address, TestFramework};
use common::{
    chain::{
        config::create_unit_test_config, output_value::OutputValue,
        signature::inputsig::InputWitness, timelock::OutputTimeLock, GenBlock, OutPointSourceId,
        SignedTransaction, Transaction, TxInput, TxOutput,
    },
    primitives::{Amount, Id, Idable},
};
use mempool::{
    error::{Error as MempoolError, MempoolPolicyError},
    tx_origin::RemoteTxOrigin,
    FeeRate, MempoolConfig,
};
use serialization::Encode;
use test_utils::{random::Seed, BasicTestTimeGetter};

use crate::{
    config::NodeType,
    error::ProtocolError,
    message::{TransactionResponse, TransactionSyncMessage},
    protocol::ProtocolConfig,
    sync::{
        peer::requested_transactions::REQUESTED_TX_EXPIRY_PERIOD,
        tests::helpers::{PeerManagerEventDesc, SyncManagerNotification, TestNode},
    },
    test_helpers::{for_each_protocol_version, test_p2p_config},
    types::peer_id::PeerId,
    P2pConfig, P2pError,
};

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_transaction(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Process a block to finish the initial block download.
        tf.make_block_builder().build_and_process(&mut rng).unwrap().unwrap();

        let p2p_config = Arc::new(test_p2p_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(chain_config)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let tx = Transaction::new(0x00, vec![], vec![]).unwrap();
        let tx = SignedTransaction::new(tx, vec![]).unwrap();
        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(
            tx.transaction().get_id(),
        ))
        .await;

        let (sent_to, message) = node.get_sent_transaction_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        assert_eq!(
            message,
            TransactionSyncMessage::TransactionRequest(tx.transaction().get_id())
        );

        peer.send_transaction_sync_message(TransactionSyncMessage::TransactionResponse(
            TransactionResponse::Found(tx),
        ))
        .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::MempoolError(MempoolError::Policy(MempoolPolicyError::NoInputs)).ban_score()
        );
        node.assert_no_sync_message().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// Transaction announcements are ignored during the initial block download, but it isn't considered
// an error or misbehavior.
#[tracing::instrument]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_block_download() {
    for_each_protocol_version(|protocol_version| async move {
        let chain_config = Arc::new(create_unit_test_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let tx = transaction(chain_config.genesis_block_id());
        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(
            tx.transaction().get_id(),
        ))
        .await;

        node.assert_no_sync_message().await;
        node.assert_no_peer_manager_event().await;
        node.assert_no_error().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_transaction_service(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Process a block to finish the initial block download.
        tf.make_block_builder().build_and_process(&mut rng).unwrap().unwrap();

        let p2p_config = Arc::new(P2pConfig {
            node_type: NodeType::BlocksOnly.into(),

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            whitelisted_addresses: Default::default(),
            ban_config: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            max_clock_diff: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: "test".try_into().unwrap(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
        });
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let tx = transaction(chain_config.genesis_block_id());
        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(
            tx.transaction().get_id(),
        ))
        .await;

        let (adjusted_peer, score) = node.receive_adjust_peer_score_event().await;
        assert_eq!(peer.get_id(), adjusted_peer);
        assert_eq!(
            score,
            P2pError::ProtocolError(ProtocolError::UnexpectedMessage("".to_owned())).ban_score()
        );
        node.assert_no_sync_message().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn too_many_announcements(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .with_time_getter(time_getter.get_time_getter())
            .build();
        // Process a block to finish the initial block download.
        tf.make_block_builder().build_and_process(&mut rng).unwrap().unwrap();

        let p2p_config = Arc::new(P2pConfig {
            protocol_config: ProtocolConfig {
                max_peer_tx_announcements: 1.into(),

                msg_header_count_limit: Default::default(),
                max_request_blocks_count: Default::default(),
                max_addr_list_response_address_count: Default::default(),
                msg_max_locator_count: Default::default(),
                max_message_size: Default::default(),
            },

            bind_addresses: Default::default(),
            socks5_proxy: Default::default(),
            disable_noise: Default::default(),
            boot_nodes: Default::default(),
            reserved_nodes: Default::default(),
            whitelisted_addresses: Default::default(),
            ban_config: Default::default(),
            outbound_connection_timeout: Default::default(),
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            peer_handshake_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: "test".try_into().unwrap(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
        });
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .with_time_getter(time_getter.get_time_getter())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        // Respond to node's initial header request (made inside connect_peer)
        peer.send_headers(vec![]).await;

        let tx1 = transaction_with_amount(chain_config.genesis_block_id(), 1);
        let tx1_id = tx1.transaction().get_id();
        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(tx1_id))
            .await;

        let (sent_to, message) = node.get_sent_transaction_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(message, TransactionSyncMessage::TransactionRequest(tx1_id));

        // Do not respond to the tx request, make another announcement
        let tx2 = transaction_with_amount(chain_config.genesis_block_id(), 2);
        let tx2_id = tx2.transaction().get_id();
        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(tx2_id))
            .await;

        // The peer should not be punished.
        node.assert_no_peer_manager_event().await;
        // Still, the node shouldn't react to this announcement.
        node.assert_no_sync_message().await;

        // Advance time to make the previously ignored tx request expire.
        logging::log::debug!("Advancing current time");
        time_getter.advance_time(REQUESTED_TX_EXPIRY_PERIOD + Duration::from_secs(1));

        // Make sure that the Peer task has an opportunity to handle expired requests.
        node.clear_notifications().await;
        node.wait_for_notification(SyncManagerNotification::NewTxSyncManagerMainLoopIteration {
            peer_id: peer.get_id(),
        })
        .await;

        // Announce the same tx
        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(tx2_id))
            .await;

        // Still no punishment
        node.assert_no_peer_manager_event().await;

        // Now the request is sent.
        let (sent_to, message) = node.get_sent_transaction_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(message, TransactionSyncMessage::TransactionRequest(tx2_id));

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicated_announcement(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Process a block to finish the initial block download.
        tf.make_block_builder().build_and_process(&mut rng).unwrap().unwrap();

        let p2p_config = Arc::new(test_p2p_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let tx = transaction(chain_config.genesis_block_id());
        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(
            tx.transaction().get_id(),
        ))
        .await;

        let (sent_to, message) = node.get_sent_transaction_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        assert_eq!(
            message,
            TransactionSyncMessage::TransactionRequest(tx.transaction().get_id())
        );

        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(
            tx.transaction().get_id(),
        ))
        .await;

        // The peer should not be punished for sending duplicate announcements.
        node.assert_no_peer_manager_event().await;
        // Still, the node shouldn't react to this announcement.
        node.assert_no_sync_message().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_transaction(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Process a block to finish the initial block download.
        tf.make_block_builder().build_and_process(&mut rng).unwrap().unwrap();

        let p2p_config = Arc::new(test_p2p_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let tx = transaction(chain_config.genesis_block_id());
        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(
            tx.transaction().get_id(),
        ))
        .await;

        let (sent_to, message) = node.get_sent_transaction_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        assert_eq!(
            message,
            TransactionSyncMessage::TransactionRequest(tx.transaction().get_id())
        );

        peer.send_transaction_sync_message(TransactionSyncMessage::TransactionResponse(
            TransactionResponse::Found(tx.clone()),
        ))
        .await;

        // There should be no `NewTransaction` message because the transaction is already known
        node.assert_no_sync_message().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

// Check that a transaction with a fee below the minimum doesn't get into the mempool but
// the peer is still not punished for it.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn valid_transaction_with_fee_below_minimum(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let mut tf = TestFramework::builder(&mut rng).build();

        let min_fee_rate = FeeRate::from_amount_per_kb(Amount::from_atoms(1000));
        let new_block_reward_amount = Amount::from_atoms(1_000_000);

        let new_block_reward = vec![TxOutput::LockThenTransfer(
            OutputValue::Coin(new_block_reward_amount),
            anyonecanspend_address(),
            OutputTimeLock::ForBlockCount(0),
        )];
        let block1 = tf.make_block_builder().with_reward(new_block_reward.clone()).build(&mut rng);
        let block1_id = block1.get_id();
        tf.process_block(block1, BlockSource::Local).unwrap();
        let block2 = tf.make_block_builder().with_reward(new_block_reward.clone()).build(&mut rng);
        let block2_id = block2.get_id();
        tf.process_block(block2, BlockSource::Local).unwrap();

        let p2p_config = Arc::new(test_p2p_config());
        let mempool_config = MempoolConfig {
            min_tx_relay_fee_rate: min_fee_rate.into(),
        };
        let mut node = TestNode::builder(protocol_version)
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_mempool_config(mempool_config)
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let estimated_tx_size =
            transaction_with_amount(block1_id.into(), new_block_reward_amount.into_atoms())
                .encoded_size();
        let min_tx_fee = min_fee_rate.compute_fee(estimated_tx_size).unwrap().into_atoms();

        // tx1's fee is below the minimum
        let tx1 = transaction_with_amount(
            block1_id.into(),
            new_block_reward_amount.into_atoms() - min_tx_fee / 2,
        );
        let tx1_id = tx1.transaction().get_id();
        // tx2's fee is exactly the minimal one.
        let tx2 = transaction_with_amount(
            block2_id.into(),
            new_block_reward_amount.into_atoms() - min_tx_fee,
        );
        let tx2_id = tx2.transaction().get_id();

        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(tx1_id))
            .await;
        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(tx2_id))
            .await;

        let (sent_to, message) = node.get_sent_transaction_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        assert_eq!(message, TransactionSyncMessage::TransactionRequest(tx1_id));
        let (sent_to, message) = node.get_sent_transaction_sync_message().await;
        assert_eq!(peer.get_id(), sent_to);
        assert_eq!(message, TransactionSyncMessage::TransactionRequest(tx2_id));

        peer.send_transaction_sync_message(TransactionSyncMessage::TransactionResponse(
            TransactionResponse::Found(tx1.clone()),
        ))
        .await;
        peer.send_transaction_sync_message(TransactionSyncMessage::TransactionResponse(
            TransactionResponse::Found(tx2.clone()),
        ))
        .await;

        // Wait for tx2 to be propagated; both of the txs will have been handled by this moment.
        node.receive_peer_manager_events(BTreeSet::from_iter(
            [PeerManagerEventDesc::NewValidTransactionReceived {
                peer_id: peer.get_id(),
                txid: tx2_id,
            }]
            .into_iter(),
        ))
        .await;

        let tx1_in_mempool =
            node.mempool().call(move |m| m.contains_transaction(&tx1_id)).await.unwrap();
        let tx2_in_mempool =
            node.mempool().call(move |m| m.contains_transaction(&tx2_id)).await.unwrap();

        assert!(!tx1_in_mempool);
        assert!(tx2_in_mempool);

        node.assert_no_sync_message().await;
        // Expect no other peer manager events, such as the propagation of tx1 or peer banning.
        node.assert_no_peer_manager_event().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_sequence_via_orphan_pool(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = test_utils::random::make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();
        // Process a block to finish the initial block download.
        tf.make_block_builder().build_and_process(&mut rng).unwrap().unwrap();

        let p2p_config = Arc::new(test_p2p_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_mempool_config(MempoolConfig {
                min_tx_relay_fee_rate: FeeRate::from_amount_per_kb(Amount::from_atoms(100_000_000))
                    .into(),
            })
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;
        let peer_id = peer.get_id();

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

        let origin = RemoteTxOrigin::new(peer_id);
        let options0 = mempool::TxOptions::default_for(origin.into());
        let options1 = options0.clone();

        let res = node
            .mempool()
            .call_mut(move |m| m.add_transaction_remote(tx1, origin, options0))
            .await
            .unwrap();
        assert_eq!(res, Ok(mempool::TxStatus::InOrphanPool));

        // The transaction should be held up in the orphan pool for now, so we don't expect it to be
        // propagated at this point
        assert_eq!(node.try_get_sent_block_sync_message(), None);

        let res = node
            .mempool()
            .call_mut(move |m| m.add_transaction_remote(tx0, origin, options1))
            .await
            .unwrap();
        assert_eq!(res, Ok(mempool::TxStatus::InMempool));

        for tid in txs.keys() {
            logging::log::error!("Tx: {tid:?}");
        }

        // Now the orphan has been resolved, both transactions should be announced.
        for _ in 0..2 {
            let (_peer, msg) = node.get_sent_transaction_sync_message().await;
            logging::log::error!("Msg new: {msg:?}");
            let tx_id = match msg {
                TransactionSyncMessage::NewTransaction(tx_id) => tx_id,
                msg => panic!("Unexpected message {msg:?}"),
            };

            let _expected_tx = txs.remove(&tx_id).expect("An existing transaction");
        }

        // A small sanity check that we have sent all transactions
        assert!(txs.is_empty());

        node.join_subsystem_manager().await;
    })
    .await;
}

/// Creates a simple transaction.
fn transaction_with_amount(out_point: Id<GenBlock>, amount_atoms: u128) -> SignedTransaction {
    let tx = Transaction::new(
        0x00,
        vec![TxInput::from_utxo(OutPointSourceId::from(out_point), 0)],
        vec![TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(amount_atoms)))],
    )
    .unwrap();
    SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap()
}

fn transaction(out_point: Id<GenBlock>) -> SignedTransaction {
    transaction_with_amount(out_point, 1)
}
