// Copyright (c) 2024 RBB S.r.l
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

use std::collections::BTreeMap;

use common::{
    chain::{
        config::create_unit_test_config, output_value::OutputValue, tokens::TokenId,
        AccountCommand, AccountNonce, Destination, OrderData, OrderId, OutPointSourceId, TxInput,
        TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, CoinOrTokenId, Fee, Id, H256},
};
use orders_accounting::{InMemoryOrdersAccounting, OrdersAccountingDB};
use pos_accounting::{InMemoryPoSAccounting, PoSAccountingDB};
use randomness::Rng;
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Seed};

use crate::{ConstrainedValueAccumulator, Error};

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn create_order_constraints(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = create_unit_test_config();
    let block_height = BlockHeight::one();

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let give_amount = Amount::from_atoms(rng.gen_range(100..1000));
    let token_id = TokenId::random_using(&mut rng);
    let ask_amount = Amount::from_atoms(rng.gen_range(100..1000));
    let order_data = Box::new(OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::TokenV1(token_id, ask_amount),
        OutputValue::Coin(give_amount),
    ));

    let orders_store = InMemoryOrdersAccounting::new();
    let orders_db = OrdersAccountingDB::new(&orders_store);

    // not enough input coins
    {
        let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
            OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
            0,
        ))];
        let input_utxos = vec![Some(TxOutput::Transfer(
            OutputValue::Coin((give_amount - Amount::from_atoms(1)).unwrap()),
            Destination::AnyoneCanSpend,
        ))];

        let outputs = vec![TxOutput::AnyoneCanTake(order_data.clone())];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);

        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );
    }

    // input tokens instead of coins
    {
        let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
            OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
            0,
        ))];
        let input_utxos = vec![Some(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, give_amount),
            Destination::AnyoneCanSpend,
        ))];

        let outputs = vec![TxOutput::AnyoneCanTake(order_data.clone())];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);

        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );
    }

    // print coins in output
    {
        let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
            OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
            0,
        ))];
        let input_utxos = vec![Some(TxOutput::Transfer(
            OutputValue::Coin(give_amount),
            Destination::AnyoneCanSpend,
        ))];

        let outputs = vec![
            TxOutput::AnyoneCanTake(order_data.clone()),
            TxOutput::Transfer(
                OutputValue::Coin(Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ),
        ];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);

        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );
    }

    // print tokens in output
    {
        let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
            OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
            0,
        ))];
        let input_utxos = vec![Some(TxOutput::Transfer(
            OutputValue::Coin(give_amount),
            Destination::AnyoneCanSpend,
        ))];

        let outputs = vec![
            TxOutput::AnyoneCanTake(order_data.clone()),
            TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ),
        ];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);

        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::TokenId(
                token_id
            ))
        );
    }

    // valid case
    let inputs = vec![TxInput::Utxo(UtxoOutPoint::new(
        OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
        0,
    ))];
    let input_utxos = vec![Some(TxOutput::Transfer(
        OutputValue::Coin(give_amount),
        Destination::AnyoneCanSpend,
    ))];

    let outputs = vec![TxOutput::AnyoneCanTake(order_data)];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn fill_order_constraints(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = create_unit_test_config();
    let block_height = BlockHeight::one();

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let order_id = OrderId::random_using(&mut rng);
    let give_amount = Amount::from_atoms(rng.gen_range(100..1000));
    let token_id = TokenId::random_using(&mut rng);
    let ask_amount = Amount::from_atoms(rng.gen_range(100..1000));
    let order_data = OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::TokenV1(token_id, ask_amount),
        OutputValue::Coin(give_amount),
    );

    let orders_store = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, ask_amount)]),
        BTreeMap::from_iter([(order_id, give_amount)]),
    );
    let orders_db = OrdersAccountingDB::new(&orders_store);

    // use in command more than provided in input
    {
        let inputs = vec![
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            )),
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(
                    order_id,
                    OutputValue::TokenV1(token_id, (ask_amount + Amount::from_atoms(1)).unwrap()),
                    Destination::AnyoneCanSpend,
                ),
            ),
        ];
        let input_utxos = vec![
            Some(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, ask_amount),
                Destination::AnyoneCanSpend,
            )),
            None,
        ];

        let result = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        );

        assert_eq!(
            result.unwrap_err(),
            Error::OrdersAccountingError(orders_accounting::Error::OrderOverbid(
                order_id,
                ask_amount,
                (ask_amount + Amount::from_atoms(1)).unwrap()
            ))
        );
    }

    // fill with coins instead of tokens
    {
        let inputs = vec![
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            )),
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(
                    order_id,
                    OutputValue::Coin(ask_amount),
                    Destination::AnyoneCanSpend,
                ),
            ),
        ];
        let input_utxos = vec![
            Some(TxOutput::Transfer(
                OutputValue::Coin(ask_amount),
                Destination::AnyoneCanSpend,
            )),
            None,
        ];

        let result = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        );

        assert_eq!(
            result.unwrap_err(),
            Error::OrdersAccountingError(orders_accounting::Error::CurrencyMismatch)
        );
    }

    // try to print coins in output
    {
        let inputs = vec![
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            )),
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(
                    order_id,
                    OutputValue::TokenV1(token_id, ask_amount),
                    Destination::AnyoneCanSpend,
                ),
            ),
        ];
        let input_utxos = vec![
            Some(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, ask_amount),
                Destination::AnyoneCanSpend,
            )),
            None,
        ];

        let outputs = vec![TxOutput::Transfer(
            OutputValue::Coin((give_amount + Amount::from_atoms(1)).unwrap()),
            Destination::AnyoneCanSpend,
        )];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);

        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );
    }

    // try to print tokens in output
    {
        let inputs = vec![
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            )),
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(
                    order_id,
                    OutputValue::TokenV1(token_id, ask_amount),
                    Destination::AnyoneCanSpend,
                ),
            ),
        ];
        let input_utxos = vec![
            Some(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, ask_amount),
                Destination::AnyoneCanSpend,
            )),
            None,
        ];

        let outputs = vec![
            TxOutput::Transfer(OutputValue::Coin(give_amount), Destination::AnyoneCanSpend),
            TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ),
        ];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);

        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::TokenId(
                token_id
            ))
        );
    }

    {
        // partially use input in command
        let inputs = vec![
            TxInput::Utxo(UtxoOutPoint::new(
                OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
                0,
            )),
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FillOrder(
                    order_id,
                    OutputValue::TokenV1(token_id, ask_amount),
                    Destination::AnyoneCanSpend,
                ),
            ),
        ];
        let input_utxos = vec![
            Some(TxOutput::Transfer(
                OutputValue::TokenV1(token_id, (ask_amount + Amount::from_atoms(1)).unwrap()),
                Destination::AnyoneCanSpend,
            )),
            None,
        ];

        let outputs = vec![
            TxOutput::Transfer(OutputValue::Coin(give_amount), Destination::AnyoneCanSpend),
            TxOutput::Transfer(
                OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
                Destination::AnyoneCanSpend,
            ),
        ];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let accumulated_fee = inputs_accumulator
            .satisfy_with(outputs_accumulator)
            .unwrap()
            .map_into_block_fees(&chain_config, block_height)
            .unwrap();

        assert_eq!(accumulated_fee, Fee(Amount::ZERO));
    }

    // valid case
    let inputs = vec![
        TxInput::Utxo(UtxoOutPoint::new(
            OutPointSourceId::BlockReward(Id::new(H256::random_using(&mut rng))),
            0,
        )),
        TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::FillOrder(
                order_id,
                OutputValue::TokenV1(token_id, ask_amount),
                Destination::AnyoneCanSpend,
            ),
        ),
    ];
    let input_utxos = vec![
        Some(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, ask_amount),
            Destination::AnyoneCanSpend,
        )),
        None,
    ];

    let outputs =
        vec![TxOutput::Transfer(OutputValue::Coin(give_amount), Destination::AnyoneCanSpend)];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn cancel_order_constraints(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = create_unit_test_config();
    let block_height = BlockHeight::one();

    let pos_store = InMemoryPoSAccounting::new();
    let pos_db = PoSAccountingDB::new(&pos_store);

    let order_id = OrderId::random_using(&mut rng);
    let give_amount = Amount::from_atoms(rng.gen_range(100..1000));
    let token_id = TokenId::random_using(&mut rng);
    let ask_amount = Amount::from_atoms(rng.gen_range(100..1000));
    let order_data = OrderData::new(
        Destination::AnyoneCanSpend,
        OutputValue::TokenV1(token_id, ask_amount),
        OutputValue::Coin(give_amount),
    );

    let orders_store = InMemoryOrdersAccounting::from_values(
        BTreeMap::from_iter([(order_id, order_data.clone())]),
        BTreeMap::from_iter([(order_id, ask_amount)]),
        BTreeMap::from_iter([(order_id, give_amount)]),
    );
    let orders_db = OrdersAccountingDB::new(&orders_store);

    // try to print coins in output
    {
        let inputs = vec![TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::CancelOrder(order_id),
        )];
        let input_utxos = vec![None];

        let outputs = vec![TxOutput::Transfer(
            OutputValue::Coin((give_amount + Amount::from_atoms(1)).unwrap()),
            Destination::AnyoneCanSpend,
        )];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);

        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::Coin)
        );
    }

    // try to print tokens in output
    {
        let inputs = vec![TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::CancelOrder(order_id),
        )];
        let input_utxos = vec![None];

        let outputs = vec![TxOutput::Transfer(
            OutputValue::TokenV1(token_id, Amount::from_atoms(1)),
            Destination::AnyoneCanSpend,
        )];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let result = inputs_accumulator.satisfy_with(outputs_accumulator);

        assert_eq!(
            result.unwrap_err(),
            Error::AttemptToPrintMoneyOrViolateTimelockConstraints(CoinOrTokenId::TokenId(
                token_id
            ))
        );
    }

    {
        // partially use input in command
        let inputs = vec![TxInput::AccountCommand(
            AccountNonce::new(0),
            AccountCommand::CancelOrder(order_id),
        )];
        let input_utxos = vec![None];

        let outputs = vec![TxOutput::Transfer(
            OutputValue::Coin((give_amount - Amount::from_atoms(1)).unwrap()),
            Destination::AnyoneCanSpend,
        )];

        let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
            &chain_config,
            block_height,
            &orders_db,
            &pos_db,
            &inputs,
            &input_utxos,
        )
        .unwrap();

        let outputs_accumulator =
            ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs)
                .unwrap();

        let accumulated_fee = inputs_accumulator
            .satisfy_with(outputs_accumulator)
            .unwrap()
            .map_into_block_fees(&chain_config, block_height)
            .unwrap();

        assert_eq!(accumulated_fee, Fee(Amount::from_atoms(1)));
    }

    // valid case
    let inputs = vec![TxInput::AccountCommand(
        AccountNonce::new(0),
        AccountCommand::CancelOrder(order_id),
    )];
    let input_utxos = vec![None];

    let outputs =
        vec![TxOutput::Transfer(OutputValue::Coin(give_amount), Destination::AnyoneCanSpend)];

    let inputs_accumulator = ConstrainedValueAccumulator::from_inputs(
        &chain_config,
        block_height,
        &orders_db,
        &pos_db,
        &inputs,
        &input_utxos,
    )
    .unwrap();

    let outputs_accumulator =
        ConstrainedValueAccumulator::from_outputs(&chain_config, block_height, &outputs).unwrap();

    let accumulated_fee = inputs_accumulator
        .satisfy_with(outputs_accumulator)
        .unwrap()
        .map_into_block_fees(&chain_config, block_height)
        .unwrap();

    assert_eq!(accumulated_fee, Fee(Amount::ZERO));
}
