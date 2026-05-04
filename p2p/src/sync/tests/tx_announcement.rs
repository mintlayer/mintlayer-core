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
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness,
    helpers::{make_simple_coin_tx, split_utxo},
    TestFramework, TransactionBuilder,
};
use common::{
    chain::{
        config::create_unit_test_config, output_value::OutputValue,
        signature::inputsig::InputWitness, timelock::OutputTimeLock, GenBlock, OutPointSourceId,
        SignedTransaction, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, Id, Idable},
};
use mempool::{
    error::{Error as MempoolError, MempoolPolicyError},
    tx_origin::{LocalTxOrigin, RemoteTxOrigin},
    FeeRate, MempoolConfig, TxOptions,
};
use randomness::{CryptoRng, RngExt as _, SliceRandom};
use serialization::Encode;
use test_utils::{
    assert_matches_return_val,
    random::{make_seedable_rng, Seed},
    BasicTestTimeGetter,
};

use crate::{
    config::NodeType,
    error::ProtocolError,
    message::{TransactionResponse, TransactionSyncMessage},
    protocol::ProtocolConfig,
    sync::{
        peer::requested_transactions::REQUESTED_TX_EXPIRY_PERIOD,
        peer::transaction_manager::TX_RELAY_DELAY_INTERVAL_OUTBOUND,
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
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn initial_block_download(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let tx = transaction(&mut rng, chain_config.genesis_block_id());
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
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            max_clock_diff: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: "test".try_into().unwrap(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            protocol_config: Default::default(),
            backend_timeouts: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
        });
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer = node.connect_peer(PeerId::new(), protocol_version).await;

        let tx = transaction(&mut rng, chain_config.genesis_block_id());
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
            ping_check_period: Default::default(),
            ping_timeout: Default::default(),
            max_clock_diff: Default::default(),
            node_type: Default::default(),
            allow_discover_private_ips: Default::default(),
            user_agent: "test".try_into().unwrap(),
            sync_stalling_timeout: Default::default(),
            peer_manager_config: Default::default(),
            backend_timeouts: Default::default(),
            custom_disconnection_reason_for_banning: Default::default(),
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

        let tx1 = transaction_with_amount(&mut rng, chain_config.genesis_block_id(), 1);
        let tx1_id = tx1.transaction().get_id();
        peer.send_transaction_sync_message(TransactionSyncMessage::NewTransaction(tx1_id))
            .await;

        let (sent_to, message) = node.get_sent_transaction_sync_message().await;
        assert_eq!(sent_to, peer.get_id());
        assert_eq!(message, TransactionSyncMessage::TransactionRequest(tx1_id));

        // Do not respond to the tx request, make another announcement
        let tx2 = transaction_with_amount(&mut rng, chain_config.genesis_block_id(), 2);
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
        node.wait_for_notification(
            SyncManagerNotification::TxSyncManagerMainLoopIterationCompleted {
                peer_id: peer.get_id(),
            },
        )
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

        let tx = transaction(&mut rng, chain_config.genesis_block_id());
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

        let tx = transaction(&mut rng, chain_config.genesis_block_id());
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

        let estimated_tx_size = transaction_with_amount(
            &mut rng,
            block1_id.into(),
            new_block_reward_amount.into_atoms(),
        )
        .encoded_size();
        let min_tx_fee = min_fee_rate.compute_fee(estimated_tx_size).unwrap().into_atoms();

        // tx1's fee is below the minimum
        let tx1 = transaction_with_amount(
            &mut rng,
            block1_id.into(),
            new_block_reward_amount.into_atoms() - min_tx_fee / 2,
        );
        let tx1_id = tx1.transaction().get_id();
        // tx2's fee is exactly the minimal one.
        let tx2 = transaction_with_amount(
            &mut rng,
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
        node.assert_no_sent_transaction_sync_message().await;

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

// When an duplicate tx is added to the mempool, it should be re-broadcast to peers if it has
// local origin and not re-broadcast if it's remote.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebroadcast_transaction(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        use mempool::tx_origin::LocalTxOrigin;

        let mut rng = make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .build();

        // This will process a block to finish the initial block download and also create utxos
        // to spend.
        let fund_tx_id: Id<Transaction> = split_utxo(
            &mut rng,
            &mut tf,
            UtxoOutPoint::new(chain_config.genesis_block_id().into(), 0),
            2,
        )
        .into();

        let p2p_config = Arc::new(test_p2p_config());
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_chainstate(tf.into_chainstate())
            .build()
            .await;

        let peer1_id = PeerId::new();
        let peer2_id = PeerId::new();
        let another_peer_id = PeerId::new();

        // Peer1 connects
        let _peer1 = node.connect_peer(peer1_id, protocol_version).await;

        let local_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(fund_tx_id.into(), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100_000_000)),
                common::chain::Destination::AnyoneCanSpend,
            ))
            .build();
        let local_tx_id = local_tx.transaction().get_id();

        let remote_tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_utxo(fund_tx_id.into(), 1),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(100_000_000)),
                common::chain::Destination::AnyoneCanSpend,
            ))
            .build();
        let remote_tx_id = remote_tx.transaction().get_id();

        let local_tx_origin = LocalTxOrigin::P2p;
        let local_tx_options = TxOptions::default_for(local_tx_origin.into());

        let remote_tx_origin = RemoteTxOrigin::new(another_peer_id);
        let remote_tx_options = TxOptions::default_for(remote_tx_origin.clone().into());

        // Add the local tx. The node should send a NewTransaction message to peer1.
        {
            let local_tx = local_tx.clone();
            let local_tx_options = local_tx_options.clone();
            let status = node
                .mempool()
                .call_mut(move |m| {
                    m.add_transaction_local(local_tx, local_tx_origin, local_tx_options)
                })
                .await
                .unwrap()
                .unwrap();
            assert_eq!(status, mempool::TransactionDuplicateStatus::New);

            let (peer_id, msg) = node.get_sent_transaction_sync_message().await;
            assert_eq!(peer_id, peer1_id);
            assert_eq!(msg, TransactionSyncMessage::NewTransaction(local_tx_id));
        }

        // Add the remote tx. The node should send a NewTransaction message to peer1.
        {
            let remote_tx = remote_tx.clone();
            let remote_tx_options = remote_tx_options.clone();
            let status = node
                .mempool()
                .call_mut(move |m| {
                    m.add_transaction_remote(remote_tx, remote_tx_origin, remote_tx_options)
                })
                .await
                .unwrap()
                .unwrap();
            assert_eq!(status, mempool::TxStatus::InMempool);

            let (peer_id, msg) = node.get_sent_transaction_sync_message().await;
            assert_eq!(peer_id, peer1_id);
            assert_eq!(msg, TransactionSyncMessage::NewTransaction(remote_tx_id));
        }

        // Peer2 connects
        let _peer2 = node.connect_peer(peer2_id, protocol_version).await;

        // Add the local tx again. The sync manager should rebroadcast the tx.
        // Since peer1 has already been offered this tx, the NewTransaction message
        // should only be sent to peer2.
        {
            let status = node
                .mempool()
                .call_mut(move |m| {
                    m.add_transaction_local(local_tx, local_tx_origin, local_tx_options)
                })
                .await
                .unwrap()
                .unwrap();
            assert_eq!(status, mempool::TransactionDuplicateStatus::Duplicate);

            let (peer_id, msg) = node.get_sent_transaction_sync_message().await;
            assert_eq!(peer_id, peer2_id);
            assert_eq!(msg, TransactionSyncMessage::NewTransaction(local_tx_id));

            node.assert_no_sync_message().await;
        }

        // Add the remote tx again. The sync manager should NOT rebroadcast the tx,
        // so event peer2 will not be sent the NewTransaction message.
        {
            let status = node
                .mempool()
                .call_mut(move |m| {
                    m.add_transaction_remote(remote_tx, remote_tx_origin, remote_tx_options)
                })
                .await
                .unwrap()
                .unwrap();
            assert_eq!(status, mempool::TxStatus::InMempoolDuplicate);

            node.assert_no_sync_message().await;
        }

        node.join_subsystem_manager().await;
    })
    .await;
}

// Check that the tx sync mgr announces all txs at once after a delay and that the announcements
// have a specific order.
// * Create 3 transactions that should have a specific order in the mempool.
// * Add them to the mempool, expect no announcement.
// * Advance the mock time, the transactions should now be announced, in the above-mentioned order.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transaction_announcements_are_batched_and_sorted(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut rng = make_seedable_rng(seed);

        let chain_config = Arc::new(create_unit_test_config());
        let time_getter = BasicTestTimeGetter::new();
        let mut tf = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .with_time_getter(time_getter.get_time_getter())
            .build();

        let output_amount = 1_000;
        let funding_tx = {
            let mut builder = TransactionBuilder::new().add_input(
                TxInput::from_utxo(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            );

            for _ in 0..3 {
                builder = builder.add_output(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(output_amount)),
                    common::chain::Destination::AnyoneCanSpend,
                ));
            }

            builder.build()
        };
        let funding_tx_id = funding_tx.transaction().get_id();
        tf.make_block_builder()
            .add_transaction(funding_tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap();

        let p2p_config = Arc::new(test_p2p_config());

        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(&chain_config))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_mempool_config(MempoolConfig {
                min_tx_relay_fee_rate: FeeRate::from_amount_per_kb(Amount::ZERO).into(),
            })
            .with_chainstate(tf.into_chainstate())
            .with_common_time_getter(&time_getter)
            .build()
            .await;

        let peer_id = PeerId::new();
        let remote_origin_peer_id = PeerId::new();
        let _peer = node.connect_peer(peer_id, protocol_version).await;

        // Make sure that the tx sync mgr's main loop had at least one iteration, this ensures
        // that its `next_time_to_announce_txs` has been updated.
        node.wait_for_notification(
            SyncManagerNotification::TxSyncManagerMainLoopIterationCompleted { peer_id },
        )
        .await;

        let independent_tx_fee = rng.random_range(100..200);
        let parent_tx_fee = rng.random_range(10..20);
        let child_tx_fee = rng.random_range(500..600);

        let independent_tx = make_simple_coin_tx(
            &mut rng,
            &[(funding_tx_id.into(), 0)],
            &[output_amount - independent_tx_fee],
        );
        let independent_tx_id = independent_tx.transaction().get_id();

        let parent_tx = make_simple_coin_tx(
            &mut rng,
            &[(funding_tx_id.into(), 1)],
            &[1, output_amount - parent_tx_fee - 1],
        );
        let parent_tx_id = parent_tx.transaction().get_id();

        let child_tx = make_simple_coin_tx(
            &mut rng,
            &[(funding_tx_id.into(), 2), (parent_tx_id.into(), 0)],
            &[1, output_amount - child_tx_fee],
        );
        let child_tx_id = child_tx.transaction().get_id();

        {
            let mut txs = [independent_tx, parent_tx, child_tx];
            txs.shuffle(&mut rng);
            for tx in txs {
                mempool_add_new_tx_with_random_origin(&node, tx, remote_origin_peer_id, &mut rng)
                    .await;
            }
        }

        node.assert_no_sent_transaction_sync_message().await;

        // Advance the time sufficiently, so that tx sync mgr would consider announcing the txs.
        // Note: 37 is the upper bound of what `exponential_rand` can return.
        time_getter.advance_time(TX_RELAY_DELAY_INTERVAL_OUTBOUND * 37);

        let expected_tx_ids = vec![independent_tx_id, parent_tx_id, child_tx_id];
        for expected_tx_id in &expected_tx_ids {
            let (sent_to, msg) = node.get_sent_transaction_sync_message().await;
            assert_eq!(sent_to, peer_id);
            let tx_id = assert_matches_return_val!(
                msg,
                TransactionSyncMessage::NewTransaction(tx_id),
                tx_id
            );
            assert_eq!(&tx_id, expected_tx_id);
        }
        node.assert_no_sent_transaction_sync_message().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

async fn mempool_add_new_tx_with_random_origin(
    node: &TestNode,
    tx: SignedTransaction,
    remote_origin_peer_id: PeerId,
    rng: &mut impl test_utils::random::Rng,
) {
    if rng.random_bool(0.5) {
        let origin = LocalTxOrigin::P2p;
        let options = TxOptions::default_for(origin.into());
        let status = node
            .mempool()
            .call_mut(move |m| m.add_transaction_local(tx, origin, options))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, mempool::TransactionDuplicateStatus::New);
    } else {
        let origin = RemoteTxOrigin::new(remote_origin_peer_id);
        let options = TxOptions::default_for(origin.into());
        let status = node
            .mempool()
            .call_mut(move |m| m.add_transaction_remote(tx, origin, options))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, mempool::TxStatus::InMempool);
    }
}

fn transaction_with_amount(
    rng: &mut impl CryptoRng,
    block_id: Id<GenBlock>,
    amount_atoms: u128,
) -> SignedTransaction {
    make_simple_coin_tx(
        rng,
        &[(OutPointSourceId::from(block_id), 0)],
        &[amount_atoms],
    )
}

fn transaction(rng: &mut impl CryptoRng, block_id: Id<GenBlock>) -> SignedTransaction {
    transaction_with_amount(rng, block_id, 1)
}
