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
use chainstate_storage::{inmemory::Store, BlockchainStorageWrite, TransactionRw, Transactional};
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TransactionBuilder,
};
use common::{
    chain::{stakelock::StakePoolData, tokens::OutputValue, OutPointSourceId, TxInput, TxOutput},
    primitives::{Amount, Id, Idable},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};

// Produce `genesis -> a` chain, then a parallel `genesis -> b -> c` that should trigger a reorg.
// Block `a` and block `c` have stake pool operation.
// Check that after reorg all accounting data from block `a` was removed and from block `c` added to storage.
#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn basic_reorg(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let storage = Store::new_empty().unwrap();
        let mut rng = make_seedable_rng(seed);
        let mut tf = TestFramework::builder(&mut rng).with_storage(storage.clone()).build();
        let genesis_id = tf.genesis().get_id();

        // prepare tx_a
        let (_, pub_key_a) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, vrf_pub_key_a) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);
        let tx_a = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::BlockReward(genesis_id.into()), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::StakePool(Box::new(StakePoolData::new(
                    anyonecanspend_address(),
                    None,
                    vrf_pub_key_a,
                    pub_key_a,
                    0,
                    Amount::ZERO,
                ))),
            ))
            .build();

        // prepare tx_b
        let tx_b = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::BlockReward(genesis_id.into()), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(100_000..200_000))),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .build();

        // prepare tx_c
        let (_, pub_key_c) = PrivateKey::new_from_rng(&mut rng, KeyKind::RistrettoSchnorr);
        let (_, vrf_pub_key_c) = VRFPrivateKey::new(VRFKeyKind::Schnorrkel);
        let tx_c = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::Transaction(tx_b.transaction().get_id()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(rng.gen_range(1000..100_000))),
                OutputPurpose::StakePool(Box::new(StakePoolData::new(
                    anyonecanspend_address(),
                    None,
                    vrf_pub_key_c,
                    pub_key_c,
                    0,
                    Amount::ZERO,
                ))),
            ))
            .build();

        // create block a
        let block_a = tf.make_block_builder().add_transaction(tx_a).build();
        let block_a_index = tf.process_block(block_a.clone(), BlockSource::Local).unwrap().unwrap();
        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_a_index.block_id())
        );

        // create block b
        let block_b = tf
            .make_block_builder()
            .with_parent(genesis_id.into())
            .add_transaction(tx_b.clone())
            .build();
        let block_b_id = block_b.get_id();
        tf.process_block(block_b, BlockSource::Local).unwrap();

        // no reorg here
        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_a_index.block_id())
        );

        // create block c
        let block_c = tf
            .make_block_builder()
            .with_parent(block_b_id.into())
            .add_transaction(tx_c.clone())
            .build_and_process()
            .unwrap()
            .unwrap();

        assert_eq!(
            tf.best_block_id(),
            Id::<GenBlock>::from(*block_c.block_id())
        );

        // Accounting data in storage after reorg should equal to the data in storage for chain
        // where reorg never happened.
        //
        // Construct fresh `genesis -> b -> c` chain as a reference
        let expected_accounting_data = {
            let storage = Store::new_empty().unwrap();
            let mut tf = TestFramework::builder(&mut rng)
                .with_storage(storage.clone())
                .with_chainstate_config(tf.chainstate().get_chainstate_config())
                .build();

            {
                // manually add block_a info
                let mut db_tx = storage.transaction_rw().unwrap();
                db_tx.set_block_index(&block_a_index).unwrap();
                db_tx.add_block(&block_a).unwrap();
                db_tx.commit().unwrap();
            }

            let block_b = tf
                .make_block_builder()
                .with_parent(genesis_id.into())
                .add_transaction(tx_b)
                .build_and_process()
                .unwrap()
                .unwrap();

            tf.make_block_builder()
                .with_parent((*block_b.block_id()).into())
                .add_transaction(tx_c)
                .build_and_process()
                .unwrap();

            storage.dump_raw()
        };

        assert_eq!(storage.dump_raw(), expected_accounting_data);
    });
}
