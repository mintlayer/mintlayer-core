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

use chainstate_test_framework::{empty_witness, TransactionBuilder};
use common::chain::{
    config::{create_unit_test_config, create_unit_test_config_builder},
    signature::inputsig::InputWitness,
    timelock::OutputTimeLock,
    OrderData,
};
use randomness::Rng;
use test_utils::random::{make_seedable_rng, Seed};

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
    use common::chain::{
        make_token_id_with_version, tokens::TokenIssuanceV1, AccountOutPoint,
        ChainstateUpgradeBuilder, TokenIdGenerationVersion,
    };

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
