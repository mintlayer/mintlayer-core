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

use super::*;
use ::tx_verifier::transaction_verifier::{flush, BlockTransactableRef, TransactionVerifier};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use chainstate_types::BlockIndex;
use common::{
    chain::{
        block::timestamp::BlockTimestamp,
        config::Builder as ConfigBuilder,
        tokens::{OutputValue, TokenData},
        Destination, OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{id::WithId, Amount, Idable},
};

// FIXME: proper description
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn homomorphism(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);

        let chain_config = ConfigBuilder::test_chain().build();
        let storage1 = InMemoryStorageWrapper {
            storage: Store::new_empty().unwrap(),
            chain_config: chain_config.clone(),
        };
        let storage2 = InMemoryStorageWrapper {
            storage: Store::new_empty().unwrap(),
            chain_config: chain_config.clone(),
        };
        let mut tf = TestFramework::builder().with_storage(storage1.storage.clone()).build();
        let mut _tf_2 = TestFramework::builder().with_storage(storage2.storage.clone()).build();

        let tx_1 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(
                    (tf.chainstate.get_chain_config().token_min_issuance_fee() * 2).unwrap(),
                ),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .build();

        let tx_2 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::Transaction(tx_1.transaction().get_id().into()),
                    0,
                ),
                InputWitness::NoSignature(None),
            )
            .add_output(TxOutput::new(
                OutputValue::Token(TokenData::TokenIssuanceV1 {
                    token_ticker: "XXXX".as_bytes().to_vec(),
                    amount_to_issue: Amount::from_atoms(rng.gen_range(1..u128::MAX)),
                    number_of_decimals: rng.gen_range(1..18),
                    metadata_uri: "http://uri".as_bytes().to_vec(),
                }),
                OutputPurpose::Transfer(Destination::AnyoneCanSpend),
            ))
            .build();

        let block: WithId<Block> = tf
            .make_block_builder()
            .add_transaction(tx_1.clone())
            .add_transaction(tx_2.clone())
            .build()
            .into();

        let fake_block_index = BlockIndex::new(
            &block,
            Uint256::ZERO,
            block.get_id().into(),
            BlockHeight::one(),
            BlockTimestamp::from_int_seconds(1),
        );

        let mut verifier_1 = TransactionVerifier::new(&storage1, &chain_config);
        verifier_1
            .connect_transactable(
                &fake_block_index,
                BlockTransactableRef::Transaction(&block, 0),
                &BlockHeight::one(),
                &BlockTimestamp::from_int_seconds(1),
            )
            .unwrap();
        verifier_1
            .connect_transactable(
                &fake_block_index,
                BlockTransactableRef::Transaction(&block, 1),
                &BlockHeight::one(),
                &BlockTimestamp::from_int_seconds(1),
            )
            .unwrap();

        let mut verifier_2 = TransactionVerifier::new(&storage2, &chain_config);
        verifier_2
            .connect_transactable(
                &fake_block_index,
                BlockTransactableRef::Transaction(&block, 0),
                &BlockHeight::one(),
                &BlockTimestamp::from_int_seconds(1),
            )
            .unwrap();

        let mut verifier_3 = verifier_2.derive_child();
        verifier_3
            .connect_transactable(
                &fake_block_index,
                BlockTransactableRef::Transaction(&block, 1),
                &BlockHeight::one(),
                &BlockTimestamp::from_int_seconds(1),
            )
            .unwrap();

        let consumed_cache_3 = verifier_3.consume().unwrap();
        flush::flush_to_storage(&mut verifier_2, consumed_cache_3).unwrap();

        let consumed_cache_1 = verifier_1.consume().unwrap();
        let consumed_cache_2 = verifier_2.consume().unwrap();
        assert_eq!(consumed_cache_1, consumed_cache_2);
    });
}
