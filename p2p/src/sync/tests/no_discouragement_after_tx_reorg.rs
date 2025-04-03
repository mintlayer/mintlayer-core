// Copyright (c) 2021-2024 RBB S.r.l
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

use std::{collections::BTreeSet, sync::Arc};

use chainstate_storage::Transactional as _;
use chainstate_test_framework::{
    anyonecanspend_address, create_stake_pool_data_with_all_reward_to_staker, TestFramework,
    TransactionBuilder,
};
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        block::timestamp::BlockTimestamp,
        classic_multisig::ClassicMultisigChallenge,
        htlc::{HashedTimelockContract, HtlcSecret},
        make_order_id,
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        tokens::{
            make_token_id, IsTokenFreezable, IsTokenUnfreezable, TokenId, TokenIssuance,
            TokenIssuanceV1, TokenTotalSupply,
        },
        AccountCommand, AccountNonce, AccountOutPoint, AccountSpending, CoinUnit, DelegationId,
        Destination, Genesis, OrderAccountCommand, OrderData, OrderId, OutPointSourceId, PoolId,
        SignedTransaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, Idable as _},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{transcript::with_rng::RngCoreAndCrypto, VRFKeyKind, VRFPrivateKey},
};
use logging::log;
use mempool::{FeeRate, MempoolConfig};
use orders_accounting::OrdersAccountingDB;
use p2p_types::PeerId;
use randomness::Rng;
use test_utils::{
    assert_matches,
    nft_utils::random_nft_issuance,
    random::{gen_random_bytes, Seed},
    random_ascii_alphanumeric_string, BasicTestTimeGetter,
};

use crate::{
    message::{
        BlockListRequest, BlockResponse, BlockSyncMessage, HeaderList, HeaderListRequest,
        TransactionResponse, TransactionSyncMessage,
    },
    sync::test_helpers::{PeerManagerEventDesc, TestNode},
    test_helpers::{for_each_protocol_version, test_p2p_config},
};

// Bugfix: after reorging a transaction that withdraws from a delegation over a block that mines
// that transaction, mempool would produce a TransactionProcessed event with mempool_ban_score
// of 100, which would lead to the peer being discouraged.
#[tracing::instrument(skip(seed))]
#[rstest::rstest]
#[trace]
#[case(Seed::from_entropy())]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_discouragement_after_tx_reorg(#[case] seed: Seed) {
    for_each_protocol_version(|protocol_version| async move {
        let mut tfxt = TestFixture::new(seed, 100);

        let pool_id = tfxt.create_pool();

        let token_id = tfxt.issue_token();
        let token_mint_amount1 = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let token_outpoint1 = tfxt.mint_token(token_id, token_mint_amount1, AccountNonce::new(0));
        let token_mint_amount2 = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let token_outpoint2 = tfxt.mint_token(token_id, token_mint_amount2, AccountNonce::new(1));
        let token_mint_amount3 = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let token_outpoint3 = tfxt.mint_token(token_id, token_mint_amount3, AccountNonce::new(2));

        let order_ask_amount = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let order_give_amount = Amount::from_atoms(
            tfxt.rng
                .gen_range((token_mint_amount1.into_atoms() / 2)..token_mint_amount1.into_atoms()),
        );
        let order_id = tfxt.create_order(
            order_ask_amount,
            order_give_amount,
            token_id,
            token_outpoint1,
        );

        let another_order1_ask_amount = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let another_order1_give_amount = Amount::from_atoms(
            tfxt.rng
                .gen_range((token_mint_amount2.into_atoms() / 2)..token_mint_amount2.into_atoms()),
        );
        let another_order1_id = tfxt.create_order(
            another_order1_ask_amount,
            another_order1_give_amount,
            token_id,
            token_outpoint2,
        );
        let another_order1_ask_amount_to_fill =
            Amount::from_atoms(tfxt.rng.gen_range(100..another_order1_ask_amount.into_atoms()));

        let another_order2_ask_amount = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let another_order2_give_amount = Amount::from_atoms(
            tfxt.rng
                .gen_range((token_mint_amount3.into_atoms() / 2)..token_mint_amount3.into_atoms()),
        );

        let delegate_amount = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let delg_id = tfxt.create_delegation(pool_id);
        tfxt.delegate(delg_id, delegate_amount);

        let another_delg_id = tfxt.create_delegation(pool_id);
        let another_delegate_amount = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));

        let another_minted_token1_amount =
            Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let another_minted_token1_id = tfxt.issue_token();
        let another_minted_token1_outpoint = tfxt.mint_token(
            another_minted_token1_id,
            another_minted_token1_amount,
            AccountNonce::new(0),
        );
        let another_minted_token1_amount_to_unmint =
            Amount::from_atoms(tfxt.rng.gen_range(0..another_minted_token1_amount.into_atoms()));

        let another_minted_token2_amount =
            Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let another_minted_token2_id = tfxt.issue_token();
        tfxt.mint_token(
            another_minted_token2_id,
            another_minted_token2_amount,
            AccountNonce::new(0),
        );

        let another_minted_token3_amount =
            Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let another_minted_token3_id = tfxt.issue_token();
        tfxt.mint_token(
            another_minted_token3_id,
            another_minted_token3_amount,
            AccountNonce::new(0),
        );

        let frozen_token_amount = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let frozen_token_id = tfxt.issue_token();
        tfxt.mint_token(frozen_token_id, frozen_token_amount, AccountNonce::new(0));
        tfxt.freeze_token(frozen_token_id, AccountNonce::new(1));

        let another_unminted_token1_id = tfxt.issue_token();
        let another_unminted_token1_new_authority =
            Destination::PublicKeyHash(PublicKeyHash::random_using(&mut tfxt.rng));

        let another_unminted_token2_id = tfxt.issue_token();
        let another_unminted_token2_new_metadata_uri = gen_random_bytes(
            &mut tfxt.rng,
            1,
            tfxt.tfrm.chain_config().token_max_uri_len(),
        );

        let another_pool_pledge = tfxt
            .rng
            .gen_range(MIN_STAKE_POOL_PLEDGE_ATOMS..(MIN_STAKE_POOL_PLEDGE_ATOMS * 10));

        let another_token_mint_mount = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));
        let htlc_coins_amount = Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000));

        // Transactions to check. Note that the main case is withdrawal from a delegation, which caused the issue originally.
        // But we also check other transaction types.
        let transactions_for_future_block = vec![
            // The main case.
            tfxt.make_tx_to_withdraw_from_delegation(delg_id, delegate_amount),
            // Other cases.
            TransactionBuilder::new()
                .add_input(
                    tfxt.next_input_from_genesis().into(),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Transfer(
                    OutputValue::Coin(Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000))),
                    Destination::AnyoneCanSpend,
                ))
                .build(),
            TransactionBuilder::new()
                .add_input(
                    tfxt.next_input_from_genesis().into(),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::LockThenTransfer(
                    OutputValue::Coin(Amount::from_atoms(tfxt.rng.gen_range(1000..1_000_000_000))),
                    Destination::AnyoneCanSpend,
                    OutputTimeLock::ForBlockCount(tfxt.rng.gen_range(0..10)),
                ))
                .build(),
            TransactionBuilder::new()
                .add_input(
                    tfxt.next_input_from_genesis().into(),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::Burn(OutputValue::Coin(Amount::from_atoms(
                    tfxt.rng.gen_range(1000..1_000_000_000),
                ))))
                .build(),
            TransactionBuilder::new()
                .add_input(
                    tfxt.next_input_from_genesis().into(),
                    InputWitness::NoSignature(None),
                )
                .add_output(TxOutput::DataDeposit(gen_random_bytes(
                    &mut tfxt.rng,
                    10,
                    20,
                )))
                .build(),
            tfxt.make_tx_to_create_pool(Amount::from_atoms(another_pool_pledge)).0,
            tfxt.make_tx_to_create_delegation(pool_id).0,
            tfxt.make_tx_to_delegate(another_delg_id, another_delegate_amount),
            tfxt.make_tx_to_issue_new_token().0,
            tfxt.make_tx_to_mint_tokens(token_id, another_token_mint_mount, AccountNonce::new(3))
                .0,
            tfxt.make_tx_to_unmint_tokens(
                another_minted_token1_id,
                another_minted_token1_amount,
                another_minted_token1_amount_to_unmint,
                AccountNonce::new(1),
                another_minted_token1_outpoint,
            ),
            tfxt.make_tx_to_lock_token_supply(another_minted_token2_id, AccountNonce::new(1)),
            tfxt.make_tx_to_freeze_token(another_minted_token3_id, AccountNonce::new(1)),
            tfxt.make_tx_to_unfreeze_token(frozen_token_id, AccountNonce::new(2)),
            tfxt.make_tx_to_change_token_authority(
                another_unminted_token1_id,
                AccountNonce::new(0),
                another_unminted_token1_new_authority,
            ),
            tfxt.make_tx_to_change_token_metadata_uri(
                another_unminted_token2_id,
                AccountNonce::new(0),
                another_unminted_token2_new_metadata_uri,
            ),
            tfxt.make_tx_to_issue_nft().0,
            tfxt.make_tx_to_create_htlc(htlc_coins_amount),
            tfxt.make_tx_to_create_order(
                another_order2_ask_amount,
                another_order2_give_amount,
                token_id,
                token_outpoint3,
            )
            .0,
            tfxt.make_tx_to_fill_order(
                another_order1_id,
                token_id,
                another_order1_ask_amount_to_fill,
            ),
            tfxt.make_tx_to_conclude_order(order_id, token_id, order_give_amount),
        ];

        let future_block = tfxt
            .tfrm
            .make_block_builder()
            .with_transactions(transactions_for_future_block.clone())
            .build(&mut tfxt.rng);
        let future_block_id = future_block.get_id();

        let p2p_config = Arc::new(test_p2p_config());

        let mempool_config = MempoolConfig {
            min_tx_relay_fee_rate: FeeRate::from_amount_per_kb(Amount::ZERO).into(),
        };
        let mut node = TestNode::builder(protocol_version)
            .with_chain_config(Arc::clone(tfxt.tfrm.chain_config()))
            .with_p2p_config(Arc::clone(&p2p_config))
            .with_mempool_config(mempool_config)
            .with_chainstate(tfxt.tfrm.into_chainstate())
            .build()
            .await;

        let peer1 = node.connect_peer(PeerId::new(), protocol_version).await;

        // Peer1 sends us the transactions from transactions_for_future_block.
        // They are all valid and accepted into mempool.
        for (idx, tx) in transactions_for_future_block.iter().enumerate() {
            let tx_id = tx.transaction().get_id();
            log::debug!("Tx #{idx} id id {tx_id:x}");

            peer1
                .send_transaction_sync_message(TransactionSyncMessage::NewTransaction(tx_id))
                .await;

            let (sent_to, message) = node.get_sent_transaction_sync_message().await;
            assert_eq!(
                (sent_to, message),
                (
                    peer1.get_id(),
                    TransactionSyncMessage::TransactionRequest(tx_id)
                )
            );

            peer1
                .send_transaction_sync_message(TransactionSyncMessage::TransactionResponse(
                    TransactionResponse::Found(tx.clone()),
                ))
                .await;

            node.receive_peer_manager_events(BTreeSet::from_iter(
                [PeerManagerEventDesc::NewValidTransactionReceived {
                    peer_id: peer1.get_id(),
                    txid: tx_id,
                }]
                .into_iter(),
            ))
            .await;

            let tx_processed_by_mempool =
                node.receive_transaction_processed_event_from_mempool().await;
            assert!(tx_processed_by_mempool.was_accepted());
            assert_eq!(tx_processed_by_mempool.tx_id(), &tx_id);

            let tx_in_mempool =
                node.mempool().call(move |m| m.contains_transaction(&tx_id)).await.unwrap();
            assert!(tx_in_mempool);
        }

        // Note: we connect peer2 now and not when peer1 is connected, to prevent the node from sending
        // the NewTransaction event to peer2, which would make it harder to produce correct event expectations.
        let peer2 = node.connect_peer(PeerId::new(), protocol_version).await;

        // Peer 2 sends us the block that mined all the transactions from transactions_for_future_block.
        {
            peer2
                .send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(vec![
                    future_block.header().clone(),
                ])))
                .await;

            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_eq!(
                (sent_to, message),
                (
                    peer2.get_id(),
                    BlockSyncMessage::BlockListRequest(BlockListRequest::new(vec![
                        future_block_id
                    ]))
                )
            );

            peer2
                .send_block_sync_message(BlockSyncMessage::BlockResponse(BlockResponse::new(
                    future_block,
                )))
                .await;

            // A peer would request headers after the last block.
            let (sent_to, message) = node.get_sent_block_sync_message().await;
            assert_matches!(
                (sent_to, message),
                (peer_id, BlockSyncMessage::HeaderListRequest(HeaderListRequest { .. }))
                if peer_id == peer2.get_id()
            );

            peer2
                .send_block_sync_message(BlockSyncMessage::HeaderList(HeaderList::new(Vec::new())))
                .await;

            let new_tip = node.receive_new_tip_event().await;
            assert_eq!(new_tip, future_block_id);
        }

        node.assert_no_error().await;

        // No peer score adjustment, no disconnection.
        node.assert_no_peer_manager_event().await;

        node.assert_no_transaction_processed_event_from_mempool().await;

        node.join_subsystem_manager().await;
    })
    .await;
}

struct TestFixture {
    rng: Box<dyn RngCoreAndCrypto>,
    tfrm: TestFramework,
    last_used_genesis_output_idx: u32,
}

const MIN_STAKE_POOL_PLEDGE_ATOMS: u128 = CoinUnit::ATOMS_PER_COIN * 10;
const GENESIS_OUTPUT_ATOMS: u128 = MIN_STAKE_POOL_PLEDGE_ATOMS * 10;

impl TestFixture {
    fn new(seed: Seed, genesis_outputs_count: usize) -> Self {
        let mut rng = test_utils::random::make_seedable_rng(seed);
        let time_getter = BasicTestTimeGetter::new();
        let chain_config = Arc::new(
            common::chain::config::create_unit_test_config_builder()
                .genesis_custom(Genesis::new(
                    "abc".to_owned(),
                    BlockTimestamp::from_int_seconds(rng.gen_range(1000..1_000_000_000)),
                    vec![
                        TxOutput::LockThenTransfer(
                            OutputValue::Coin(Amount::from_atoms(GENESIS_OUTPUT_ATOMS)),
                            anyonecanspend_address(),
                            OutputTimeLock::ForBlockCount(0),
                        );
                        genesis_outputs_count
                    ],
                ))
                .min_stake_pool_pledge(Amount::from_atoms(MIN_STAKE_POOL_PLEDGE_ATOMS))
                .build(),
        );
        let tfrm = TestFramework::builder(&mut rng)
            .with_chain_config(chain_config.as_ref().clone())
            .with_time_getter(time_getter.get_time_getter())
            .build();

        Self {
            rng: Box::new(rng),
            tfrm,
            last_used_genesis_output_idx: 1,
        }
    }

    fn next_input_from_genesis(&mut self) -> UtxoOutPoint {
        let genesis_id = self.tfrm.chain_config().genesis_block_id();
        let result = UtxoOutPoint::new(
            OutPointSourceId::BlockReward(genesis_id),
            self.last_used_genesis_output_idx,
        );
        self.last_used_genesis_output_idx += 1;
        result
    }

    fn make_block_with_tx(&mut self, tx: SignedTransaction) {
        self.tfrm
            .make_block_builder()
            .add_transaction(tx)
            .build_and_process(&mut self.rng)
            .unwrap()
            .unwrap();
    }

    fn make_tx_to_create_pool(&mut self, amount_to_stake: Amount) -> (SignedTransaction, PoolId) {
        let outpoint = self.next_input_from_genesis();

        let (_, vrf_pk) = VRFPrivateKey::new_from_rng(&mut self.rng, VRFKeyKind::Schnorrkel);
        let (stake_pool_data, _) = create_stake_pool_data_with_all_reward_to_staker(
            &mut self.rng,
            amount_to_stake,
            vrf_pk,
        );

        let pool_id = pos_accounting::make_pool_id(&outpoint);

        let tx = TransactionBuilder::new()
            .add_input(outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateStakePool(
                pool_id,
                Box::new(stake_pool_data),
            ))
            .build();

        (tx, pool_id)
    }

    fn create_pool(&mut self) -> PoolId {
        let (create_pool_tx, pool_id) =
            self.make_tx_to_create_pool(Amount::from_atoms(MIN_STAKE_POOL_PLEDGE_ATOMS));

        self.make_block_with_tx(create_pool_tx);

        pool_id
    }

    fn make_tx_to_create_delegation(
        &mut self,
        pool_id: PoolId,
    ) -> (SignedTransaction, DelegationId) {
        let outpoint = self.next_input_from_genesis();
        let delegation_id = pos_accounting::make_delegation_id(&outpoint);
        let tx = TransactionBuilder::new()
            .add_input(outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateDelegationId(
                Destination::AnyoneCanSpend,
                pool_id,
            ))
            .build();

        (tx, delegation_id)
    }

    fn create_delegation(&mut self, pool_id: PoolId) -> DelegationId {
        let (create_delg_tx, delg_id) = self.make_tx_to_create_delegation(pool_id);
        self.make_block_with_tx(create_delg_tx);
        delg_id
    }

    fn make_tx_to_delegate(&mut self, delg_id: DelegationId, amount: Amount) -> SignedTransaction {
        TransactionBuilder::new()
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::DelegateStaking(amount, delg_id))
            .build()
    }

    fn delegate(&mut self, delg_id: DelegationId, amount: Amount) {
        let delegate_tx = self.make_tx_to_delegate(delg_id, amount);
        self.make_block_with_tx(delegate_tx);
    }

    fn make_tx_to_withdraw_from_delegation(
        &mut self,
        delg_id: DelegationId,
        amount: Amount,
    ) -> SignedTransaction {
        TransactionBuilder::new()
            .add_input(
                TxInput::Account(AccountOutPoint::new(
                    AccountNonce::new(0),
                    AccountSpending::DelegationBalance(delg_id, amount),
                )),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::LockThenTransfer(
                OutputValue::Coin(amount),
                Destination::AnyoneCanSpend,
                OutputTimeLock::ForBlockCount(1),
            ))
            .build()
    }

    fn make_tx_to_issue_new_token(&mut self) -> (SignedTransaction, TokenId) {
        let issuance = {
            let max_ticker_len = self.tfrm.chain_config().token_max_ticker_len();
            let max_dec_count = self.tfrm.chain_config().token_max_dec_count();
            let max_uri_len = self.tfrm.chain_config().token_max_uri_len();

            let issuance = TokenIssuanceV1 {
                token_ticker: random_ascii_alphanumeric_string(&mut self.rng, 1..max_ticker_len)
                    .as_bytes()
                    .to_vec(),
                number_of_decimals: self.rng.gen_range(1..max_dec_count),
                metadata_uri: random_ascii_alphanumeric_string(&mut self.rng, 1..max_uri_len)
                    .as_bytes()
                    .to_vec(),
                total_supply: TokenTotalSupply::Lockable,
                is_freezable: IsTokenFreezable::Yes,
                authority: Destination::AnyoneCanSpend,
            };
            TokenIssuance::V1(issuance)
        };

        let tx = TransactionBuilder::new()
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::IssueFungibleToken(Box::new(issuance)))
            .build();

        let token_id = make_token_id(tx.transaction().inputs()).unwrap();

        (tx, token_id)
    }

    fn issue_token(&mut self) -> TokenId {
        let (issue_token_tx, token_id) = self.make_tx_to_issue_new_token();
        self.make_block_with_tx(issue_token_tx);
        token_id
    }

    fn make_tx_to_issue_nft(&mut self) -> (SignedTransaction, TokenId) {
        let input: TxInput = self.next_input_from_genesis().into();
        let token_id = make_token_id(&[input.clone()]).unwrap();

        let tx = TransactionBuilder::new()
            .add_input(input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                token_id,
                Box::new(random_nft_issuance(self.tfrm.chain_config(), &mut self.rng).into()),
                Destination::AnyoneCanSpend,
            ))
            .build();

        (tx, token_id)
    }

    fn make_tx_to_mint_tokens(
        &mut self,
        token_id: TokenId,
        amount_to_mint: Amount,
        nonce: AccountNonce,
    ) -> (SignedTransaction, UtxoOutPoint) {
        let tx = TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::MintTokens(token_id, amount_to_mint)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, amount_to_mint),
                Destination::AnyoneCanSpend,
            ))
            .build();

        let outpoint = UtxoOutPoint::new(tx.transaction().get_id().into(), 0);
        (tx, outpoint)
    }

    fn mint_token(
        &mut self,
        token_id: TokenId,
        amount: Amount,
        nonce: AccountNonce,
    ) -> UtxoOutPoint {
        let (mint_tokens_tx, tokens_outpoint) =
            self.make_tx_to_mint_tokens(token_id, amount, nonce);
        self.make_block_with_tx(mint_tokens_tx);
        tokens_outpoint
    }

    fn make_tx_to_unmint_tokens(
        &mut self,
        token_id: TokenId,
        minted_amount: Amount,
        amount_to_unmint: Amount,
        nonce: AccountNonce,
        token_outpoint: UtxoOutPoint,
    ) -> SignedTransaction {
        TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::UnmintTokens(token_id)),
                InputWitness::NoSignature(None),
            )
            .add_input(token_outpoint.into(), InputWitness::NoSignature(None))
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, (minted_amount - amount_to_unmint).unwrap()),
                Destination::AnyoneCanSpend,
            ))
            .build()
    }

    fn make_tx_to_lock_token_supply(
        &mut self,
        token_id: TokenId,
        nonce: AccountNonce,
    ) -> SignedTransaction {
        TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::LockTokenSupply(token_id)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1000)),
                Destination::AnyoneCanSpend,
            ))
            .build()
    }

    fn make_tx_to_freeze_token(
        &mut self,
        token_id: TokenId,
        nonce: AccountNonce,
    ) -> SignedTransaction {
        TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    nonce,
                    AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::Yes),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1000)),
                Destination::AnyoneCanSpend,
            ))
            .build()
    }

    fn freeze_token(&mut self, token_id: TokenId, nonce: AccountNonce) {
        let tx = self.make_tx_to_freeze_token(token_id, nonce);
        self.make_block_with_tx(tx);
    }

    fn make_tx_to_unfreeze_token(
        &mut self,
        token_id: TokenId,
        nonce: AccountNonce,
    ) -> SignedTransaction {
        TransactionBuilder::new()
            .add_input(
                TxInput::from_command(nonce, AccountCommand::UnfreezeToken(token_id)),
                InputWitness::NoSignature(None),
            )
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1000)),
                Destination::AnyoneCanSpend,
            ))
            .build()
    }

    fn make_tx_to_change_token_authority(
        &mut self,
        token_id: TokenId,
        nonce: AccountNonce,
        new_authority: Destination,
    ) -> SignedTransaction {
        TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    nonce,
                    AccountCommand::ChangeTokenAuthority(token_id, new_authority),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1000)),
                Destination::AnyoneCanSpend,
            ))
            .build()
    }

    fn make_tx_to_change_token_metadata_uri(
        &mut self,
        token_id: TokenId,
        nonce: AccountNonce,
        new_metadata_uri: Vec<u8>,
    ) -> SignedTransaction {
        TransactionBuilder::new()
            .add_input(
                TxInput::from_command(
                    nonce,
                    AccountCommand::ChangeTokenMetadataUri(token_id, new_metadata_uri),
                ),
                InputWitness::NoSignature(None),
            )
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1000)),
                Destination::AnyoneCanSpend,
            ))
            .build()
    }

    fn make_tx_to_create_order(
        &mut self,
        coin_ask_amount: Amount,
        token_give_amount: Amount,
        token_id: TokenId,
        outpoint: UtxoOutPoint,
    ) -> (SignedTransaction, OrderId) {
        let order_data = OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::Coin(coin_ask_amount),
            OutputValue::TokenV1(token_id, token_give_amount),
        );

        let order_id = make_order_id(&outpoint);
        let tx = TransactionBuilder::new()
            .add_input(outpoint.into(), InputWitness::NoSignature(None))
            .add_output(TxOutput::CreateOrder(Box::new(order_data)))
            .build();

        (tx, order_id)
    }

    fn create_order(
        &mut self,
        coin_ask_amount: Amount,
        token_give_amount: Amount,
        token_id: TokenId,
        token_outpoint: UtxoOutPoint,
    ) -> OrderId {
        let (tx, order_id) = self.make_tx_to_create_order(
            coin_ask_amount,
            token_give_amount,
            token_id,
            token_outpoint,
        );
        self.make_block_with_tx(tx);

        order_id
    }

    fn make_tx_to_fill_order(
        &mut self,
        order_id: OrderId,
        token_id: TokenId,
        coin_amount_to_fill: Amount,
    ) -> SignedTransaction {
        let filled_amount = {
            let db_tx = self.tfrm.storage.transaction_ro().unwrap();
            let orders_db = OrdersAccountingDB::new(&db_tx);
            orders_accounting::calculate_fill_order(
                &orders_db,
                order_id,
                coin_amount_to_fill,
                common::chain::OrdersVersion::V1,
            )
            .unwrap()
        };

        TransactionBuilder::new()
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_input(
                TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                    order_id,
                    coin_amount_to_fill,
                    Destination::AnyoneCanSpend,
                )),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, filled_amount),
                Destination::AnyoneCanSpend,
            ))
            .build()
    }

    fn make_tx_to_conclude_order(
        &mut self,
        order_id: OrderId,
        token_id: TokenId,
        remaining_give_amount: Amount,
    ) -> SignedTransaction {
        TransactionBuilder::new()
            .add_input(
                TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order_id)),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, remaining_give_amount),
                Destination::AnyoneCanSpend,
            ))
            .build()
    }

    fn make_tx_to_create_htlc(&mut self, amount_coins: Amount) -> SignedTransaction {
        TransactionBuilder::new()
            .add_input(
                self.next_input_from_genesis().into(),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::Htlc(
                OutputValue::Coin(amount_coins),
                Box::new(self.make_htlc().0),
            ))
            .build()
    }

    fn make_htlc(&mut self) -> (HashedTimelockContract, ClassicMultisigChallenge) {
        let secret = HtlcSecret::new_from_rng(&mut self.rng);

        let (_alice_sk, alice_pk) =
            PrivateKey::new_from_rng(&mut self.rng, KeyKind::Secp256k1Schnorr);
        let (_bob_sk, bob_pk) = PrivateKey::new_from_rng(&mut self.rng, KeyKind::Secp256k1Schnorr);

        let refund_challenge = ClassicMultisigChallenge::new(
            self.tfrm.chain_config(),
            utils::const_nz_u8!(2),
            vec![alice_pk.clone(), bob_pk.clone()],
        )
        .unwrap();
        let destination_multisig: PublicKeyHash = (&refund_challenge).into();

        let htlc = HashedTimelockContract {
            secret_hash: secret.hash(),
            spend_key: Destination::PublicKeyHash((&bob_pk).into()),
            refund_timelock: OutputTimeLock::ForSeconds(200),
            refund_key: Destination::ClassicMultisig(destination_multisig),
        };
        (htlc, refund_challenge)
    }
}
