// Copyright (c) 2021-2025 RBB S.r.l
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
use common::{
    chain::{
        make_token_id,
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{IsTokenFreezable, TokenId, TokenIssuance, TokenIssuanceV1, TokenTotalSupply},
        AccountCommand, AccountNonce, AccountType, Block, Destination, GenBlock, OrderId,
        OrdersVersion, Transaction, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Id, Idable},
};
use orders_accounting::OrdersAccountingDB;
use randomness::{CryptoRng, Rng, SliceRandom as _};
use test_utils::random_ascii_alphanumeric_string;

use crate::{get_output_value, TestFramework, TransactionBuilder};

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

pub fn issue_token_from_block(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    parent_block_id: Id<GenBlock>,
    utxo_to_pay_fee: UtxoOutPoint,
    issuance: TokenIssuance,
) -> (TokenId, Id<Block>, UtxoOutPoint) {
    let token_issuance_fee = tf.chainstate.get_chain_config().fungible_token_issuance_fee();

    let fee_utxo_coins =
        get_output_value(tf.chainstate.utxo(&utxo_to_pay_fee).unwrap().unwrap().output())
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

/// Split an u128 value into the specified number of "randomish" parts (the min part size is half
/// the average part size).
pub fn split_u128(rng: &mut (impl Rng + CryptoRng), amount: u128, parts_count: usize) -> Vec<u128> {
    assert!(parts_count > 0);
    let mut result = Vec::with_capacity(parts_count);
    let parts_count = parts_count as u128;
    let min_part_amount = amount / parts_count / 2;
    let mut remaining_amount_above_min = amount - min_part_amount * parts_count;

    for i in 0..parts_count {
        let amount_part_above_min = if i == parts_count - 1 {
            remaining_amount_above_min
        } else {
            rng.gen_range(0..remaining_amount_above_min / 2)
        };

        result.push(min_part_amount + amount_part_above_min);
        remaining_amount_above_min -= amount_part_above_min;
    }

    assert_eq!(result.iter().sum::<u128>(), amount);

    result.shuffle(rng);
    result
}

/// Start building a tx that will "split" the specified outpoint into the specified number of outpoints.
///
/// The "fee" parameter only makes sense if the outpoint's currency is coins.
pub fn make_tx_builder_to_split_utxo(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    outpoint: UtxoOutPoint,
    parts_count: usize,
    fee: Amount,
) -> TransactionBuilder {
    let utxo_output_value = get_output_value(tf.utxo(&outpoint).output()).unwrap();
    let utxo_amount = utxo_output_value.amount();

    let output_amounts = split_u128(rng, (utxo_amount - fee).unwrap().into_atoms(), parts_count);

    let mut tx_builder =
        TransactionBuilder::new().add_input(outpoint.into(), InputWitness::NoSignature(None));
    for output_amount in output_amounts {
        tx_builder = tx_builder.add_output(TxOutput::Transfer(
            output_value_with_amount(&utxo_output_value, Amount::from_atoms(output_amount)),
            Destination::AnyoneCanSpend,
        ))
    }

    tx_builder
}

pub fn split_utxo(
    rng: &mut (impl Rng + CryptoRng),
    tf: &mut TestFramework,
    outpoint: UtxoOutPoint,
    parts_count: usize,
) -> Id<Transaction> {
    let tx = make_tx_builder_to_split_utxo(rng, tf, outpoint, parts_count, Amount::ZERO).build();
    let tx_id = tx.transaction().get_id();

    tf.make_block_builder().add_transaction(tx).build_and_process(rng).unwrap();
    tx_id
}

pub fn output_value_with_amount(output_value: &OutputValue, new_amount: Amount) -> OutputValue {
    match output_value {
        OutputValue::Coin(_) => OutputValue::Coin(new_amount),
        OutputValue::TokenV0(_) => {
            panic!("Unexpected token v0");
        }
        OutputValue::TokenV1(id, _) => OutputValue::TokenV1(*id, new_amount),
    }
}
