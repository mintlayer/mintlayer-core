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

use std::collections::{BTreeMap, BTreeSet};

use itertools::Itertools as _;
use rand::seq::IteratorRandom as _;
use rstest::rstest;

use chainstate::{ChainstateError, PropertyQueryError};
use chainstate_test_framework::{
    get_output_value,
    helpers::{issue_token_from_block, issue_token_from_genesis, make_token_issuance},
    TestFramework, TransactionBuilder,
};
use common::{
    chain::{
        output_value::OutputValue,
        signature::inputsig::InputWitness,
        tokens::{IsTokenFreezable, IsTokenFrozen, TokenId, TokenIssuance, TokenTotalSupply},
        Destination, TxInput, TxOutput, UtxoOutPoint,
    },
    primitives::{Amount, BlockHeight, Idable},
};
use test_utils::{
    assert_matches_return_val,
    random::{make_seedable_rng, Seed},
    token_utils::random_nft_issuance,
};

use crate::tests::helpers::token_checks::{
    make_expected_rpc_token_info_from_nft_metadata,
    make_expected_rpc_token_info_from_token_issuance,
};

// Test get_tokens_info_for_rpc when multiple tokens are available (2 fungible ones, 2 NFTs).
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn get_tokens_info_for_rpc_test(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).build();

        let (token1_id, _, _, issuance1, utxo_with_change) = issue_token_from_genesis(
            &mut rng,
            &mut tf,
            TokenTotalSupply::Unlimited,
            IsTokenFreezable::No,
        );

        let issuance1_v1 =
            assert_matches_return_val!(issuance1, TokenIssuance::V1(issuance), issuance);

        let token1_expected_info_for_rpc = make_expected_rpc_token_info_from_token_issuance(
            token1_id,
            &issuance1_v1,
            Amount::ZERO,
            false,
            IsTokenFrozen::No(IsTokenFreezable::No),
        );

        let issuance2 =
            make_token_issuance(&mut rng, TokenTotalSupply::Unlimited, IsTokenFreezable::No);
        let best_block_id = tf.best_block_id();
        let (token2_id, _, _, utxo_with_change) = issue_token_from_block(
            &mut rng,
            &mut tf,
            best_block_id,
            utxo_with_change,
            issuance2.clone(),
        );

        let issuance2_v1 =
            assert_matches_return_val!(issuance2, TokenIssuance::V1(issuance), issuance);

        let token2_expected_info_for_rpc = make_expected_rpc_token_info_from_token_issuance(
            token2_id,
            &issuance2_v1,
            Amount::ZERO,
            false,
            IsTokenFrozen::No(IsTokenFreezable::No),
        );

        let nft_issuance_fee =
            tf.chainstate.get_chain_config().nft_issuance_fee(BlockHeight::zero());
        let change_amount =
            get_output_value(tf.chainstate.utxo(&utxo_with_change).unwrap().unwrap().output())
                .unwrap()
                .coin_amount()
                .unwrap();

        let nft_tx1_first_input = TxInput::Utxo(utxo_with_change);
        let nft1_id = TokenId::from_tx_input(&nft_tx1_first_input);
        let nft1_issuance = random_nft_issuance(tf.chain_config().as_ref(), &mut rng);
        let next_change_amount = (change_amount - nft_issuance_fee).unwrap();

        let ntf1_issuance_tx = TransactionBuilder::new()
            .add_input(nft_tx1_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                nft1_id,
                Box::new(nft1_issuance.clone().into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(next_change_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let nft1_issuance_tx_id = ntf1_issuance_tx.transaction().get_id();
        let utxo_with_change = UtxoOutPoint::new(ntf1_issuance_tx.transaction().get_id().into(), 1);
        let change_amount = next_change_amount;

        let nft1_issuance_block_id = *tf
            .make_block_builder()
            .add_transaction(ntf1_issuance_tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap()
            .block_id();

        let nft1_expected_info_for_rpc = make_expected_rpc_token_info_from_nft_metadata(
            nft1_id,
            nft1_issuance_tx_id,
            nft1_issuance_block_id,
            &nft1_issuance.metadata,
        );

        let nft_tx2_first_input = TxInput::Utxo(utxo_with_change);
        let nft2_id = TokenId::from_tx_input(&nft_tx2_first_input);
        let nft2_issuance = random_nft_issuance(tf.chain_config().as_ref(), &mut rng);
        let next_change_amount = (change_amount - nft_issuance_fee).unwrap();

        let ntf2_issuance_tx = TransactionBuilder::new()
            .add_input(nft_tx2_first_input, InputWitness::NoSignature(None))
            .add_output(TxOutput::IssueNft(
                nft2_id,
                Box::new(nft2_issuance.clone().into()),
                Destination::AnyoneCanSpend,
            ))
            .add_output(TxOutput::Transfer(
                OutputValue::Coin(next_change_amount),
                Destination::AnyoneCanSpend,
            ))
            .build();
        let nft2_issuance_tx_id = ntf2_issuance_tx.transaction().get_id();

        let nft2_issuance_block_id = *tf
            .make_block_builder()
            .add_transaction(ntf2_issuance_tx)
            .build_and_process(&mut rng)
            .unwrap()
            .unwrap()
            .block_id();

        let nft2_expected_info_for_rpc = make_expected_rpc_token_info_from_nft_metadata(
            nft2_id,
            nft2_issuance_tx_id,
            nft2_issuance_block_id,
            &nft2_issuance.metadata,
        );

        let random_token_id = TokenId::random_using(&mut rng);

        let all_expected_infos = BTreeMap::from_iter([
            (token1_id, token1_expected_info_for_rpc),
            (token2_id, token2_expected_info_for_rpc),
            (nft1_id, nft1_expected_info_for_rpc),
            (nft2_id, nft2_expected_info_for_rpc),
        ]);

        // Check obtaining the info for each token individually
        for (token_id, expected_info_for_rpc) in &all_expected_infos {
            let actual_infos_for_rpc = tf
                .chainstate
                .get_tokens_info_for_rpc(&BTreeSet::from_iter([*token_id]))
                .unwrap();
            assert_eq!(
                &actual_infos_for_rpc[..],
                std::slice::from_ref(expected_info_for_rpc)
            );

            // Also check that adding random_token_id to the set results in an error.
            assert_eq!(
                tf.chainstate
                    .get_tokens_info_for_rpc(&BTreeSet::from_iter([*token_id, random_token_id]))
                    .unwrap_err(),
                ChainstateError::FailedToReadProperty(PropertyQueryError::TokenInfoMissing(
                    random_token_id
                ))
            )
        }

        // Check obtaining the info for 2, 3 and all the tokens simultaneously
        for test_set in [
            all_expected_infos.iter().choose_multiple(&mut rng, 2),
            all_expected_infos.iter().choose_multiple(&mut rng, 3),
            all_expected_infos.iter().collect_vec(),
        ] {
            // Collect the test set into a BTreeMap, so that the expected infos are sorted
            // by token id. This is how get_tokens_info_for_rpc returns them.
            let tokens_map = test_set.into_iter().collect::<BTreeMap<_, _>>();
            let token_ids = tokens_map.keys().copied().copied().collect::<BTreeSet<_>>();
            let expected_infos_for_rpc = tokens_map.values().copied().cloned().collect_vec();

            let actual_infos_for_rpc = tf.chainstate.get_tokens_info_for_rpc(&token_ids).unwrap();
            assert_eq!(&actual_infos_for_rpc[..], &expected_infos_for_rpc);

            // Also check that adding random_token_id to the set results in an error.
            let mut token_ids = token_ids;
            token_ids.insert(random_token_id);
            assert_eq!(
                tf.chainstate.get_tokens_info_for_rpc(&token_ids).unwrap_err(),
                ChainstateError::FailedToReadProperty(PropertyQueryError::TokenInfoMissing(
                    random_token_id
                ))
            )
        }
    })
}
