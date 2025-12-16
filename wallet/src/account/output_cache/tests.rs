// Copyright (c) 2025 RBB S.r.l
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

use rstest::rstest;

use strum::IntoEnumIterator as _;

use chainstate_test_framework::{empty_witness, TransactionBuilder};
use common::{
    address::pubkeyhash::PublicKeyHash,
    chain::{
        config::{create_unit_test_config, create_unit_test_config_builder},
        make_token_id_with_version,
        signature::inputsig::InputWitness,
        timelock::OutputTimeLock,
        tokens::TokenIssuanceV1,
        AccountOutPoint, ChainstateUpgradeBuilder, OrderData, TokenIdGenerationVersion,
    },
};
use randomness::{seq::IteratorRandom as _, Rng};
use test_utils::random::{make_seedable_rng, Seed};
use wallet_types::wallet_tx::TxStateTag;

use crate::account::output_cache;

use super::*;

// Create a diamond shape dependant unconfirmed txs:
//
//  /-->B-->\
// A         D
//  \-->C-->/
//
// Check the cache.
// Remove A from unconfirmed descendants. Check the result.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn diamond_unconfirmed_descendants(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = create_unit_test_config();
    let best_block_height = BlockHeight::new(rng.gen());
    let mut output_cache = OutputCache::empty();

    // A
    let genesis_tx_id = Id::<Transaction>::random_using(&mut rng);
    let tx_a = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(genesis_tx_id.into(), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_a_id = tx_a.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_a_id.into(),
            WalletTx::Tx(TxData::new(tx_a, TxState::Inactive(0))),
        )
        .unwrap();

    // B
    let tx_b = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx_a_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_b_id = tx_b.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_b_id.into(),
            WalletTx::Tx(TxData::new(tx_b, TxState::Inactive(0))),
        )
        .unwrap();

    // C
    let tx_c = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx_a_id.into(), 1),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_c_id = tx_c.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_c_id.into(),
            WalletTx::Tx(TxData::new(tx_c, TxState::Inactive(0))),
        )
        .unwrap();

    // D
    let tx_d = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx_b_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_input(
            TxInput::from_utxo(tx_c_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_d_id = tx_d.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_d_id.into(),
            WalletTx::Tx(TxData::new(tx_d, TxState::Inactive(0))),
        )
        .unwrap();

    let expected_unconfirmed_descendants = BTreeMap::from_iter([
        (
            tx_a_id.into(),
            BTreeSet::from_iter([tx_b_id.into(), tx_c_id.into()]),
        ),
        (tx_b_id.into(), BTreeSet::from_iter([tx_d_id.into()])),
        (tx_c_id.into(), BTreeSet::from_iter([tx_d_id.into()])),
        (tx_d_id.into(), BTreeSet::new()),
    ]);
    assert_eq!(
        expected_unconfirmed_descendants,
        output_cache.unconfirmed_descendants
    );

    let result = output_cache.remove_from_unconfirmed_descendants(tx_a_id);
    assert!(
        (result == vec![tx_a_id, tx_b_id, tx_c_id, tx_d_id])
            || (result == vec![tx_a_id, tx_c_id, tx_b_id, tx_d_id])
    );
    assert!(output_cache.unconfirmed_descendants.is_empty());
}

// Create 2 unconfirmed txs B and C that spend tokens:
//
//  /-->B-->C
// A
//  \-->D
//
// Freeze the token in D.
// Check that both B and C got marked as conflicted.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn update_conflicting_txs_parent_and_child(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = create_unit_test_config();
    let best_block_height = BlockHeight::new(rng.gen());
    let mut output_cache = OutputCache::empty();
    let token_id = TokenId::random_using(&mut rng);

    // A
    let genesis_tx_id = Id::<Transaction>::random_using(&mut rng);
    let tx_a = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(genesis_tx_id.into(), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_a_id = tx_a.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_a_id.into(),
            WalletTx::Tx(TxData::new(
                tx_a,
                TxState::Confirmed(
                    BlockHeight::new(rng.gen()),
                    BlockTimestamp::from_int_seconds(0),
                    0,
                ),
            )),
        )
        .unwrap();

    // B
    let tx_b = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx_a_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_b_id = tx_b.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_b_id.into(),
            WalletTx::Tx(TxData::new(tx_b.clone(), TxState::Inactive(0))),
        )
        .unwrap();

    // C
    let tx_c = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx_b_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_c_id = tx_c.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_c_id.into(),
            WalletTx::Tx(TxData::new(tx_c.clone(), TxState::Inactive(0))),
        )
        .unwrap();

    // D
    let tx_d = TransactionBuilder::new()
        .add_input(
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::No),
            ),
            empty_witness(&mut rng),
        )
        .build();

    let block_id = Id::random_using(&mut rng);
    let result = output_cache
        .update_conflicting_txs(&chain_config, tx_d.transaction(), block_id)
        .unwrap();
    assert_eq!(
        result,
        vec![
            (
                tx_c_id,
                WalletTx::Tx(TxData::new(tx_c, TxState::Conflicted(block_id)))
            ),
            (
                tx_b_id,
                WalletTx::Tx(TxData::new(tx_b, TxState::Conflicted(block_id)))
            ),
        ]
    );
}

// Create unconfirmed txs Bi that use a token in their outputs only:
// a) by transferring zero amount of the token (a legit situation which doesn't require the token
// to be present in the inputs);
// b) creating an order that asks for the token.
//
//  /-->Bi
// A
//  \-->C
//
// Freeze the token in C.
// Check that Bi got marked as conflicted.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn update_conflicting_txs_frozen_token_only_in_outputs(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = create_unit_test_config();
    let best_block_height = BlockHeight::new(rng.gen());
    let mut output_cache = OutputCache::empty();
    let token_id = TokenId::random_using(&mut rng);

    let genesis_tx_id = Id::<Transaction>::random_using(&mut rng);
    let tx_a = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(genesis_tx_id.into(), 0),
            InputWitness::NoSignature(None),
        )
        // Note: only coin outputs here
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_a_id = tx_a.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_a_id.into(),
            WalletTx::Tx(TxData::new(
                tx_a,
                TxState::Confirmed(
                    BlockHeight::new(rng.gen()),
                    BlockTimestamp::from_int_seconds(0),
                    0,
                ),
            )),
        )
        .unwrap();

    // Transfer zero amount
    let tx_b1 = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx_a_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::TokenV1(token_id, Amount::ZERO),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_b1_id = tx_b1.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_b1_id.into(),
            WalletTx::Tx(TxData::new(tx_b1.clone(), TxState::Inactive(0))),
        )
        .unwrap();

    // LockThenTransfer zero amount
    let tx_b2 = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx_a_id.into(), 1),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::LockThenTransfer(
            OutputValue::TokenV1(token_id, Amount::ZERO),
            Destination::AnyoneCanSpend,
            OutputTimeLock::ForBlockCount(1),
        ))
        .build();
    let tx_b2_id = tx_b2.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_b2_id.into(),
            WalletTx::Tx(TxData::new(tx_b2.clone(), TxState::Inactive(0))),
        )
        .unwrap();

    let tx_b3 = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx_a_id.into(), 2),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::CreateOrder(Box::new(OrderData::new(
            Destination::AnyoneCanSpend,
            OutputValue::TokenV1(token_id, Amount::from_atoms(rng.gen())),
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
        ))))
        .build();
    let tx_b3_id = tx_b3.transaction().get_id();
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_b3_id.into(),
            WalletTx::Tx(TxData::new(tx_b3.clone(), TxState::Inactive(0))),
        )
        .unwrap();

    let tx_d = TransactionBuilder::new()
        .add_input(
            TxInput::AccountCommand(
                AccountNonce::new(0),
                AccountCommand::FreezeToken(token_id, IsTokenUnfreezable::No),
            ),
            empty_witness(&mut rng),
        )
        .build();

    let block_id = Id::random_using(&mut rng);
    let result = output_cache
        .update_conflicting_txs(&chain_config, tx_d.transaction(), block_id)
        .unwrap()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        result,
        BTreeMap::from([
            (
                tx_b1_id,
                WalletTx::Tx(TxData::new(tx_b1, TxState::Conflicted(block_id)))
            ),
            (
                tx_b2_id,
                WalletTx::Tx(TxData::new(tx_b2, TxState::Conflicted(block_id)))
            ),
            (
                tx_b3_id,
                WalletTx::Tx(TxData::new(tx_b3, TxState::Conflicted(block_id)))
            ),
        ])
    );
}

// Check that when add_tx is called for a tx with an `IssueFungibleToken` output, the token
// id is generated based on the tx block height if the tx is in a block and on best block height
// plus one if it's not.
// Also call `rollback_tx_data` for the same tx and check that the token is no longer in the cache
// after that.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn token_id_in_add_tx(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let fork_height = BlockHeight::new(rng.gen_range(1000..1_000_000));
    let chain_config = create_unit_test_config_builder()
        .chainstate_upgrades(
            common::chain::NetUpgrades::initialize(vec![
                (
                    BlockHeight::zero(),
                    ChainstateUpgradeBuilder::latest()
                        .token_id_generation_version(TokenIdGenerationVersion::V0)
                        .build(),
                ),
                (
                    fork_height,
                    ChainstateUpgradeBuilder::latest()
                        .token_id_generation_version(TokenIdGenerationVersion::V1)
                        .build(),
                ),
            ])
            .unwrap(),
        )
        .build();

    let genesis_tx_id = Id::<Transaction>::random_using(&mut rng);
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::Account(AccountOutPoint::new(
                AccountNonce::new(rng.gen()),
                AccountSpending::DelegationBalance(
                    Id::random_using(&mut rng),
                    Amount::from_atoms(rng.gen()),
                ),
            )),
            InputWitness::NoSignature(None),
        )
        .add_input(
            TxInput::from_utxo(genesis_tx_id.into(), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::IssueFungibleToken(Box::new(TokenIssuance::V1(
            TokenIssuanceV1 {
                token_ticker: "XXXX".as_bytes().to_vec(),
                number_of_decimals: rng.gen_range(1..18),
                metadata_uri: "http://uri".as_bytes().to_vec(),
                total_supply: common::chain::tokens::TokenTotalSupply::Unlimited,
                authority: Destination::AnyoneCanSpend,
                is_freezable: common::chain::tokens::IsTokenFreezable::No,
            },
        ))))
        .build();
    let tx_id = tx.transaction().get_id();

    // The tx is from a block.
    // Tx block height is before the fork, best block height is after the fork.
    // Expecting V0 token id.
    {
        let tx_block_height = BlockHeight::new(rng.gen_range(0..fork_height.into_int()));
        let best_block_height =
            BlockHeight::new(rng.gen_range(fork_height.into_int()..fork_height.into_int() * 2));
        let mut output_cache = OutputCache::empty();

        let wallet_tx = WalletTx::Tx(TxData::new(
            tx.clone(),
            TxState::Confirmed(tx_block_height, BlockTimestamp::from_int_seconds(0), 0),
        ));
        output_cache
            .add_tx(
                &chain_config,
                best_block_height,
                tx_id.into(),
                wallet_tx.clone(),
            )
            .unwrap();

        let correct_token_id =
            make_token_id_with_version(TokenIdGenerationVersion::V0, tx.inputs()).unwrap();
        let wrong_token_id =
            make_token_id_with_version(TokenIdGenerationVersion::V1, tx.inputs()).unwrap();

        assert!(output_cache.token_issuance.contains_key(&correct_token_id));
        assert!(!output_cache.token_issuance.contains_key(&wrong_token_id));

        output_cache.rollback_tx_data(&chain_config, &wallet_tx).unwrap();

        assert!(!output_cache.token_issuance.contains_key(&correct_token_id));
        assert!(!output_cache.token_issuance.contains_key(&wrong_token_id));
    }

    // The tx is from a block.
    // Tx block height is after the fork, best block height is before the fork (note that this
    // situation shouldn't really be possible, we just want to make sure that the token id
    // is based on the tx block height and not the best block height).
    // Expecting V1 token id.
    {
        let tx_block_height =
            BlockHeight::new(rng.gen_range(fork_height.into_int()..fork_height.into_int() * 2));
        let best_block_height = BlockHeight::new(rng.gen_range(0..fork_height.into_int()));
        let mut output_cache = OutputCache::empty();

        let wallet_tx = WalletTx::Tx(TxData::new(
            tx.clone(),
            TxState::Confirmed(tx_block_height, BlockTimestamp::from_int_seconds(0), 0),
        ));
        output_cache
            .add_tx(
                &chain_config,
                best_block_height,
                tx_id.into(),
                wallet_tx.clone(),
            )
            .unwrap();

        let correct_token_id =
            make_token_id_with_version(TokenIdGenerationVersion::V1, tx.inputs()).unwrap();
        let wrong_token_id =
            make_token_id_with_version(TokenIdGenerationVersion::V0, tx.inputs()).unwrap();

        assert!(output_cache.token_issuance.contains_key(&correct_token_id));
        assert!(!output_cache.token_issuance.contains_key(&wrong_token_id));

        output_cache.rollback_tx_data(&chain_config, &wallet_tx).unwrap();

        assert!(!output_cache.token_issuance.contains_key(&correct_token_id));
        assert!(!output_cache.token_issuance.contains_key(&wrong_token_id));
    }

    // The tx is not from a block.
    // Best block height is the fork height minus 2 or less.
    // Expecting V0 token id.
    {
        let best_block_height = if rng.gen_bool(0.5) {
            fork_height.prev_height().unwrap().prev_height().unwrap()
        } else {
            BlockHeight::new(rng.gen_range(0..fork_height.into_int() - 2))
        };
        let mut output_cache = OutputCache::empty();

        let wallet_tx = WalletTx::Tx(TxData::new(tx.clone(), TxState::Inactive(rng.gen())));
        output_cache
            .add_tx(
                &chain_config,
                best_block_height,
                tx_id.into(),
                wallet_tx.clone(),
            )
            .unwrap();

        let correct_token_id =
            make_token_id_with_version(TokenIdGenerationVersion::V0, tx.inputs()).unwrap();
        let wrong_token_id =
            make_token_id_with_version(TokenIdGenerationVersion::V1, tx.inputs()).unwrap();

        assert!(output_cache.token_issuance.contains_key(&correct_token_id));
        assert!(!output_cache.token_issuance.contains_key(&wrong_token_id));

        output_cache.rollback_tx_data(&chain_config, &wallet_tx).unwrap();

        assert!(!output_cache.token_issuance.contains_key(&correct_token_id));
        assert!(!output_cache.token_issuance.contains_key(&wrong_token_id));
    }

    // The tx is not from a block.
    // Best block height is the fork height minus 1 or bigger.
    // Expecting V0 token id.
    {
        let best_block_height = if rng.gen_bool(0.5) {
            fork_height.prev_height().unwrap()
        } else {
            BlockHeight::new(rng.gen_range(fork_height.into_int()..fork_height.into_int() * 2))
        };
        let mut output_cache = OutputCache::empty();

        let wallet_tx = WalletTx::Tx(TxData::new(tx.clone(), TxState::Inactive(rng.gen())));
        output_cache
            .add_tx(
                &chain_config,
                best_block_height,
                tx_id.into(),
                wallet_tx.clone(),
            )
            .unwrap();

        let correct_token_id =
            make_token_id_with_version(TokenIdGenerationVersion::V1, tx.inputs()).unwrap();
        let wrong_token_id =
            make_token_id_with_version(TokenIdGenerationVersion::V0, tx.inputs()).unwrap();

        assert!(output_cache.token_issuance.contains_key(&correct_token_id));
        assert!(!output_cache.token_issuance.contains_key(&wrong_token_id));

        output_cache.rollback_tx_data(&chain_config, &wallet_tx).unwrap();

        assert!(!output_cache.token_issuance.contains_key(&correct_token_id));
        assert!(!output_cache.token_issuance.contains_key(&wrong_token_id));
    }
}

// Having transactions "A->B->C", where B is Inactive and C is Conflicted,
// abandon B and check that both B and C get into the "Abandoned" state.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn abandon_transaction(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = create_unit_test_config();
    let best_block_height = BlockHeight::new(rng.gen());
    let mut output_cache = OutputCache::empty();

    let genesis_tx_id = Id::<Transaction>::random_using(&mut rng);
    let tx_a = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(genesis_tx_id.into(), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_a_id = tx_a.transaction().get_id();

    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_a_id.into(),
            WalletTx::Tx(TxData::new(tx_a, TxState::Inactive(0))),
        )
        .unwrap();

    let tx_b = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx_a_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_b_id = tx_b.transaction().get_id();

    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_b_id.into(),
            WalletTx::Tx(TxData::new(tx_b.clone(), TxState::Inactive(0))),
        )
        .unwrap();

    let tx_c = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(tx_b_id.into(), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let tx_c_id = tx_c.transaction().get_id();

    let block_id = Id::random_using(&mut rng);
    output_cache
        .add_tx(
            &chain_config,
            best_block_height,
            tx_c_id.into(),
            WalletTx::Tx(TxData::new(tx_c.clone(), TxState::Conflicted(block_id))),
        )
        .unwrap();

    let result = output_cache
        .abandon_transaction(&chain_config, tx_b_id)
        .unwrap()
        .into_iter()
        .collect::<BTreeMap<_, _>>();

    assert_eq!(
        result,
        BTreeMap::from([
            (tx_b_id, WalletTx::Tx(TxData::new(tx_b, TxState::Abandoned))),
            (tx_c_id, WalletTx::Tx(TxData::new(tx_c, TxState::Abandoned))),
        ])
    );
}

// Create, fill, freeze and conclude 2 orders, checking the contents of the `orders` map
// inside the cache.
// The txs related to the 1st order are Confirmed, and those related to the 2nd one are Inactive.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn orders_state_update(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let chain_config = create_unit_test_config();

    let token_id = TokenId::random_using(&mut rng);

    let conclude_key1 = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
    let conclude_key2 = Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng));
    let coins1 = OutputValue::Coin(Amount::from_atoms(rng.gen_range(1000..100_1000)));
    let coins2 = OutputValue::Coin(Amount::from_atoms(rng.gen_range(1000..100_1000)));
    let tokens1 = OutputValue::TokenV1(token_id, Amount::from_atoms(rng.gen_range(1000..100_1000)));
    let tokens2 = OutputValue::TokenV1(token_id, Amount::from_atoms(rng.gen_range(1000..100_1000)));

    let parent_tx_1_id = Id::<Transaction>::random_using(&mut rng);
    let order1_creation_tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(parent_tx_1_id.into(), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::CreateOrder(Box::new(OrderData::new(
            conclude_key1.clone(),
            coins1.clone(),
            tokens1.clone(),
        ))))
        .build();
    let order1_creation_tx_id = order1_creation_tx.transaction().get_id();
    let order1_creation_timestamp = BlockTimestamp::from_int_seconds(rng.gen_range(0..10));
    let order1_id = make_order_id(order1_creation_tx.inputs()).unwrap();
    let order1_creation_tx_confirmation_height = BlockHeight::new(rng.gen_range(0..10));

    let mut output_cache = OutputCache::empty();

    // Create order 1

    if rng.gen_bool(0.5) {
        add_random_transfer_tx(&mut output_cache, &chain_config, &mut rng);
    }

    output_cache
        .add_tx(
            &chain_config,
            BlockHeight::new(10),
            order1_creation_tx_id.into(),
            WalletTx::Tx(TxData::new(
                order1_creation_tx,
                TxState::Confirmed(
                    order1_creation_tx_confirmation_height,
                    order1_creation_timestamp,
                    rng.gen_range(0..10),
                ),
            )),
        )
        .unwrap();

    if rng.gen_bool(0.5) {
        add_random_transfer_tx(&mut output_cache, &chain_config, &mut rng);
    }

    let mut expected_cached_order1_data = output_cache::OrderData {
        conclude_key: conclude_key1.clone(),
        initially_asked: RpcOutputValue::from_output_value(&coins1).unwrap(),
        initially_given: RpcOutputValue::from_output_value(&tokens1).unwrap(),
        creation_timestamp: Some(order1_creation_timestamp),
        last_nonce: None,
        last_parent: None,
        is_concluded: false,
        is_frozen: false,
    };

    assert_eq!(
        output_cache.orders,
        BTreeMap::from_iter([(order1_id, expected_cached_order1_data.clone())])
    );

    // Create order 2

    let parent_tx_2_id = Id::<Transaction>::random_using(&mut rng);
    let order2_creation_tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(parent_tx_2_id.into(), 0),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::CreateOrder(Box::new(OrderData::new(
            conclude_key2.clone(),
            tokens2.clone(),
            coins2.clone(),
        ))))
        .build();
    let order2_creation_tx_id = order2_creation_tx.transaction().get_id();
    let order2_id = make_order_id(order2_creation_tx.inputs()).unwrap();

    output_cache
        .add_tx(
            &chain_config,
            BlockHeight::new(20),
            order2_creation_tx_id.into(),
            WalletTx::Tx(TxData::new(
                order2_creation_tx,
                TxState::Inactive(rng.gen()),
            )),
        )
        .unwrap();

    if rng.gen_bool(0.5) {
        add_random_transfer_tx(&mut output_cache, &chain_config, &mut rng);
    }

    let mut expected_cached_order2_data = output_cache::OrderData {
        conclude_key: conclude_key2,
        initially_asked: RpcOutputValue::from_output_value(&tokens2).unwrap(),
        initially_given: RpcOutputValue::from_output_value(&coins2).unwrap(),
        creation_timestamp: None,
        last_nonce: None,
        last_parent: None,
        is_concluded: false,
        is_frozen: false,
    };

    assert_eq!(
        output_cache.orders,
        BTreeMap::from_iter([
            (order1_id, expected_cached_order1_data.clone()),
            (order2_id, expected_cached_order2_data.clone())
        ])
    );

    // Fill order 1

    let order1_fill_tx = TransactionBuilder::new()
        .add_input(
            TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order1_id,
                Amount::from_atoms(rng.gen_range(100..200)),
            )),
            InputWitness::NoSignature(None),
        )
        .build();
    let order1_fill_tx_id = order1_fill_tx.transaction().get_id();

    output_cache
        .add_tx(
            &chain_config,
            BlockHeight::new(30),
            order1_fill_tx_id.into(),
            WalletTx::Tx(TxData::new(
                order1_fill_tx,
                TxState::Confirmed(
                    BlockHeight::new(rng.gen_range(20..30)),
                    BlockTimestamp::from_int_seconds(rng.gen_range(20..30)),
                    rng.gen_range(0..10),
                ),
            )),
        )
        .unwrap();

    if rng.gen_bool(0.5) {
        add_random_transfer_tx(&mut output_cache, &chain_config, &mut rng);
    }

    expected_cached_order1_data.last_parent = Some(order1_fill_tx_id.into());
    assert_eq!(
        output_cache.orders,
        BTreeMap::from_iter([
            (order1_id, expected_cached_order1_data.clone()),
            (order2_id, expected_cached_order2_data.clone())
        ])
    );

    // Fill order 2

    let order2_fill_tx = TransactionBuilder::new()
        .add_input(
            TxInput::OrderAccountCommand(OrderAccountCommand::FillOrder(
                order2_id,
                Amount::from_atoms(rng.gen_range(100..200)),
            )),
            InputWitness::NoSignature(None),
        )
        .build();
    let order2_fill_tx_id = order2_fill_tx.transaction().get_id();

    output_cache
        .add_tx(
            &chain_config,
            BlockHeight::new(40),
            order2_fill_tx_id.into(),
            WalletTx::Tx(TxData::new(order2_fill_tx, TxState::Inactive(rng.gen()))),
        )
        .unwrap();

    if rng.gen_bool(0.5) {
        add_random_transfer_tx(&mut output_cache, &chain_config, &mut rng);
    }

    expected_cached_order2_data.last_parent = Some(order2_fill_tx_id.into());
    assert_eq!(
        output_cache.orders,
        BTreeMap::from_iter([
            (order1_id, expected_cached_order1_data.clone()),
            (order2_id, expected_cached_order2_data.clone())
        ])
    );

    // Freeze order 1

    let order1_freeze_tx = TransactionBuilder::new()
        .add_input(
            TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order1_id)),
            InputWitness::NoSignature(None),
        )
        .build();
    let order1_freeze_tx_id = order1_freeze_tx.transaction().get_id();

    output_cache
        .add_tx(
            &chain_config,
            BlockHeight::new(50),
            order1_freeze_tx_id.into(),
            WalletTx::Tx(TxData::new(
                order1_freeze_tx,
                TxState::Confirmed(
                    BlockHeight::new(rng.gen_range(40..50)),
                    BlockTimestamp::from_int_seconds(rng.gen_range(40..50)),
                    rng.gen_range(0..10),
                ),
            )),
        )
        .unwrap();

    if rng.gen_bool(0.5) {
        add_random_transfer_tx(&mut output_cache, &chain_config, &mut rng);
    }

    expected_cached_order1_data.last_parent = Some(order1_freeze_tx_id.into());
    expected_cached_order1_data.is_frozen = true;
    assert_eq!(
        output_cache.orders,
        BTreeMap::from_iter([
            (order1_id, expected_cached_order1_data.clone()),
            (order2_id, expected_cached_order2_data.clone())
        ])
    );

    // Freeze order 2

    let order2_freeze_tx = TransactionBuilder::new()
        .add_input(
            TxInput::OrderAccountCommand(OrderAccountCommand::FreezeOrder(order2_id)),
            InputWitness::NoSignature(None),
        )
        .build();
    let order2_freeze_tx_id = order2_freeze_tx.transaction().get_id();

    output_cache
        .add_tx(
            &chain_config,
            BlockHeight::new(60),
            order2_freeze_tx_id.into(),
            WalletTx::Tx(TxData::new(order2_freeze_tx, TxState::Inactive(rng.gen()))),
        )
        .unwrap();

    if rng.gen_bool(0.5) {
        add_random_transfer_tx(&mut output_cache, &chain_config, &mut rng);
    }

    expected_cached_order2_data.last_parent = Some(order2_freeze_tx_id.into());
    expected_cached_order2_data.is_frozen = true;
    assert_eq!(
        output_cache.orders,
        BTreeMap::from_iter([
            (order1_id, expected_cached_order1_data.clone()),
            (order2_id, expected_cached_order2_data.clone())
        ])
    );

    // Conclude order 1

    let order1_conclude_tx = TransactionBuilder::new()
        .add_input(
            TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order1_id)),
            InputWitness::NoSignature(None),
        )
        .build();
    let order1_conclude_tx_id = order1_conclude_tx.transaction().get_id();

    output_cache
        .add_tx(
            &chain_config,
            BlockHeight::new(70),
            order1_conclude_tx_id.into(),
            WalletTx::Tx(TxData::new(
                order1_conclude_tx,
                TxState::Confirmed(
                    BlockHeight::new(rng.gen_range(60..70)),
                    BlockTimestamp::from_int_seconds(rng.gen_range(60..70)),
                    rng.gen_range(0..10),
                ),
            )),
        )
        .unwrap();

    if rng.gen_bool(0.5) {
        add_random_transfer_tx(&mut output_cache, &chain_config, &mut rng);
    }

    expected_cached_order1_data.last_parent = Some(order1_conclude_tx_id.into());
    expected_cached_order1_data.is_concluded = true;
    assert_eq!(
        output_cache.orders,
        BTreeMap::from_iter([
            (order1_id, expected_cached_order1_data.clone()),
            (order2_id, expected_cached_order2_data.clone())
        ])
    );

    // Conclude order 2

    let order2_conclude_tx = TransactionBuilder::new()
        .add_input(
            TxInput::OrderAccountCommand(OrderAccountCommand::ConcludeOrder(order2_id)),
            InputWitness::NoSignature(None),
        )
        .build();
    let order2_conclude_tx_id = order2_conclude_tx.transaction().get_id();

    output_cache
        .add_tx(
            &chain_config,
            BlockHeight::new(80),
            order2_conclude_tx_id.into(),
            WalletTx::Tx(TxData::new(
                order2_conclude_tx,
                TxState::Inactive(rng.gen()),
            )),
        )
        .unwrap();

    if rng.gen_bool(0.5) {
        add_random_transfer_tx(&mut output_cache, &chain_config, &mut rng);
    }

    expected_cached_order2_data.last_parent = Some(order2_conclude_tx_id.into());
    expected_cached_order2_data.is_concluded = true;
    assert_eq!(
        output_cache.orders,
        BTreeMap::from_iter([
            (order1_id, expected_cached_order1_data.clone()),
            (order2_id, expected_cached_order2_data.clone())
        ])
    );
}

fn add_random_transfer_tx(
    output_cache: &mut OutputCache,
    chain_config: &ChainConfig,
    mut rng: impl Rng,
) {
    let random_tx_id = Id::<Transaction>::random_using(&mut rng);
    let random_block_id = Id::<GenBlock>::random_using(&mut rng);
    let tx = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(random_tx_id.into(), rng.gen()),
            InputWitness::NoSignature(None),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(rng.gen())),
            Destination::PublicKeyHash(PublicKeyHash::random_using(&mut rng)),
        ))
        .build();
    let tx_id = tx.transaction().get_id();

    let tx_state = match TxStateTag::iter().choose(&mut rng).unwrap() {
        TxStateTag::Confirmed => TxState::Confirmed(
            BlockHeight::new(rng.gen_range(0..100)),
            BlockTimestamp::from_int_seconds(rng.gen_range(0..100)),
            rng.gen_range(0..100),
        ),
        TxStateTag::InMempool => TxState::InMempool(rng.gen()),
        TxStateTag::Conflicted => TxState::Conflicted(random_block_id),
        TxStateTag::Inactive => TxState::Inactive(rng.gen()),
        TxStateTag::Abandoned => TxState::Abandoned,
    };

    output_cache
        .add_tx(
            chain_config,
            BlockHeight::new(rng.gen_range(0..100)),
            tx_id.into(),
            WalletTx::Tx(TxData::new(tx, tx_state)),
        )
        .unwrap();
}
