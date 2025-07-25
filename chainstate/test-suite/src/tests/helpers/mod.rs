// Copyright (c) 2021-2022 RBB S.r.l
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

use chainstate::BlockSource;
use chainstate_storage::{BlockchainStorageRead, Transactional};
use chainstate_test_framework::{anyonecanspend_address, TestFramework, TransactionBuilder};
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        make_token_id,
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        tokens::{IsTokenFreezable, TokenId, TokenIssuance, TokenIssuanceV1, TokenTotalSupply},
        AccountCommand, AccountNonce, AccountType, Block, Destination, GenBlock, OrderId,
        OrdersVersion, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockDistance, BlockHeight, Id, Idable},
};
use crypto::key::{KeyKind, PrivateKey};
use orders_accounting::OrdersAccountingDB;
use randomness::{CryptoRng, Rng};
use test_utils::random_ascii_alphanumeric_string;

pub mod block_creation_helpers;
pub mod block_index_handle_impl;
pub mod block_status_helpers;
pub mod in_memory_storage_wrapper;
pub mod pos;

/// Adds a block with the locked output and returns input corresponding to this output.
pub fn add_block_with_locked_output(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    output_time_lock: OutputTimeLock,
    timestamp: BlockTimestamp,
) -> (InputWitness, TxInput, Id<Transaction>) {
    // Find the last block.
    let current_height = tf.best_block_index().block_height();
    let prev_block_outputs = tf.outputs_from_genblock(tf.block_id(current_height.into()));

    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(prev_block_outputs.keys().next().unwrap().clone(), 0),
            InputWitness::NoSignature(None),
        )
        .add_anyone_can_spend_output(10000)
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::Coin(Amount::from_atoms(100000)),
            anyonecanspend_address(),
            output_time_lock,
        ))
        .build();
    let tx_id = tx.transaction().get_id();
    tf.make_block_builder()
        .add_transaction(tx)
        .with_timestamp(timestamp)
        .build_and_process(rng)
        .unwrap();

    let new_height = (current_height + BlockDistance::new(1)).unwrap();
    assert_eq!(tf.best_block_index().block_height(), new_height);

    let block_outputs = tf.outputs_from_genblock(tf.block_id(new_height.into()));
    assert!(block_outputs.contains_key(&tx_id.into()));
    (
        InputWitness::NoSignature(None),
        TxInput::from_utxo(tx_id.into(), 1),
        tx_id,
    )
}

pub fn new_pub_key_destination(rng: &mut (impl Rng + CryptoRng)) -> Destination {
    let (_, pub_key) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    Destination::PublicKey(pub_key)
}

pub fn issue_token_from_block(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    parent_block_id: Id<GenBlock>,
    utxo_to_pay_fee: UtxoOutPoint,
    issuance: TokenIssuance,
) -> (TokenId, Id<Block>, UtxoOutPoint) {
    let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

    let fee_utxo_coins = chainstate_test_framework::get_output_value(
        tf.chainstate.utxo(&utxo_to_pay_fee).unwrap().unwrap().output(),
    )
    .unwrap()
    .coin_amount()
    .unwrap();

    let tx = TransactionBuilder::new()
        .add_input(utxo_to_pay_fee.into(), InputWitness::NoSignature(None))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin((fee_utxo_coins - token_issuance_fee).unwrap()),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::IssueFungibleToken(Box::new(issuance.clone())))
        .build();
    let parent_block_height = tf.gen_block_index(&parent_block_id).block_height();
    let token_id = make_token_id(
        tf.chain_config(),
        parent_block_height.next_height(),
        tx.transaction().inputs(),
    )
    .unwrap();
    let tx_id = tx.transaction().get_id();
    let block = tf
        .make_block_builder()
        .add_transaction(tx)
        .with_parent(parent_block_id)
        .build(rng);
    let block_id = block.get_id();
    tf.process_block(block, BlockSource::Local).unwrap();

    (token_id, block_id, UtxoOutPoint::new(tx_id.into(), 0))
}

pub fn mint_tokens_in_block(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    parent_block_id: Id<GenBlock>,
    utxo_to_pay_fee: UtxoOutPoint,
    token_id: TokenId,
    amount_to_mint: Amount,
    produce_change: bool,
) -> (Id<Block>, Id<Transaction>) {
    let token_supply_change_fee =
        tf.chainstate.get_chain_config().token_supply_change_fee(BlockHeight::zero());

    let nonce = BlockchainStorageRead::get_account_nonce_count(
        &tf.storage.transaction_ro().unwrap(),
        AccountType::Token(token_id),
    )
    .unwrap()
    .map_or(AccountNonce::new(0), |n| n.increment().unwrap());

    let tx_builder = TransactionBuilder::new()
        .add_input(
            TxInput::from_command(nonce, AccountCommand::MintTokens(token_id, amount_to_mint)),
            InputWitness::NoSignature(None),
        )
        .add_input(
            utxo_to_pay_fee.clone().into(),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, amount_to_mint),
            Destination::AnyoneCanSpend,
        ));

    let tx_builder = if produce_change {
        let fee_utxo_coins = tf.coin_amount_from_utxo(&utxo_to_pay_fee);

        tx_builder.add_output(TxOutput::Transfer(
            OutputValue::Coin((fee_utxo_coins - token_supply_change_fee).unwrap()),
            Destination::AnyoneCanSpend,
        ))
    } else {
        tx_builder
    };

    let tx = tx_builder.build();
    let tx_id = tx.transaction().get_id();

    let block = tf
        .make_block_builder()
        .add_transaction(tx)
        .with_parent(parent_block_id)
        .build(rng);
    let block_id = block.get_id();
    tf.process_block(block, BlockSource::Local).unwrap();

    (block_id, tx_id)
}

// Note: this function will create 2 blocks
pub fn issue_and_mint_random_token_from_best_block(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    utxo_to_pay_fee: UtxoOutPoint,
    amount_to_mint: Amount,
    total_supply: TokenTotalSupply,
    is_freezable: IsTokenFreezable,
) -> (
    TokenId,
    /*tokens*/ UtxoOutPoint,
    /*coins change*/ UtxoOutPoint,
) {
    let best_block_id = tf.best_block_id();
    let issuance = {
        let max_ticker_len = tf.chain_config().token_max_ticker_len();
        let max_dec_count = tf.chain_config().token_max_dec_count();
        let max_uri_len = tf.chain_config().token_max_uri_len();

        let issuance = TokenIssuanceV1 {
            token_ticker: random_ascii_alphanumeric_string(rng, 1..max_ticker_len)
                .as_bytes()
                .to_vec(),
            number_of_decimals: rng.gen_range(1..max_dec_count),
            metadata_uri: random_ascii_alphanumeric_string(rng, 1..max_uri_len).as_bytes().to_vec(),
            total_supply,
            is_freezable,
            authority: Destination::AnyoneCanSpend,
        };
        TokenIssuance::V1(issuance)
    };

    let (token_id, _, utxo_with_change) =
        issue_token_from_block(rng, tf, best_block_id, utxo_to_pay_fee, issuance);

    let best_block_id = tf.best_block_id();
    let (_, mint_tx_id) = mint_tokens_in_block(
        rng,
        tf,
        best_block_id,
        utxo_with_change,
        token_id,
        amount_to_mint,
        true,
    );

    (
        token_id,
        UtxoOutPoint::new(mint_tx_id.into(), 0),
        UtxoOutPoint::new(mint_tx_id.into(), 1),
    )
}

/// Given the fill amount in the "ask" currency, return the filled amount in the "give" currency.
pub fn calculate_fill_order(
    tf: &TestFramework,
    order_id: &OrderId,
    fill_amount_in_ask_currency: Amount,
    orders_version: OrdersVersion,
) -> Amount {
    let db_tx = tf.storage.transaction_ro().unwrap();
    let orders_db = OrdersAccountingDB::new(&db_tx);
    orders_accounting::calculate_fill_order(
        &orders_db,
        *order_id,
        fill_amount_in_ask_currency,
        orders_version,
    )
    .unwrap()
}
