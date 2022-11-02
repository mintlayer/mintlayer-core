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

use super::helpers::in_memory_storage_wrapper::InMemoryStorageWrapper;
use super::*;

use chainstate::ConnectTransactionError;
use chainstate_test_framework::{
    anyonecanspend_address, empty_witness, TestFramework, TestStore, TransactionBuilder,
};
use common::{
    chain::{
        config::Builder as ConfigBuilder, tokens::OutputValue, ChainConfig, GenBlockId,
        OutPointSourceId, TxInput, TxOutput,
    },
    primitives::{Amount, Idable},
};
use tx_verifier::transaction_verifier::{
    TransactionSource, TransactionSourceForConnect, TransactionVerifier,
};

fn setup() -> (ChainConfig, InMemoryStorageWrapper, TestFramework) {
    let storage = TestStore::new_empty().unwrap();
    let tf = TestFramework::builder().with_storage(storage.clone()).build();

    let chain_config = ConfigBuilder::test_chain().build();
    let storage = InMemoryStorageWrapper::new(storage, chain_config.clone());

    (chain_config, storage, tf)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy(), 2)]
fn attempt_to_disconnect_tx_mainchain(#[case] seed: Seed, #[case] num_blocks: usize) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, mut tf) = setup();

        let genesis_id = tf.genesis().get_id();
        tf.create_chain(&genesis_id.into(), num_blocks, &mut rng).unwrap();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);

        for height in 1..num_blocks {
            let block_id = match tf.block_id(height as u64).classify(&chain_config) {
                GenBlockId::Genesis(_) => unreachable!(),
                GenBlockId::Block(id) => id,
            };
            let block = tf.block(block_id);
            let tx = block.transactions().get(0).unwrap();
            let tx_id = tx.transaction().get_id();

            // check if can be disconnected
            assert!(!verifier
                .can_disconnect_transaction(&TransactionSource::Chain(block_id), &tx_id)
                .unwrap());

            // try to disconnect anyway
            let mut tmp_verifier = verifier.derive_child();
            assert_eq!(
                tmp_verifier.disconnect_transaction(&TransactionSource::Chain(block_id), tx),
                Err(chainstate::ConnectTransactionError::UtxoError(
                    utxo::Error::NoUtxoFound
                ))
            );
        }

        // only txs from the last block can be disconnected
        let block_id = match tf.block_id(num_blocks as u64).classify(&chain_config) {
            GenBlockId::Genesis(_) => unreachable!(),
            GenBlockId::Block(id) => id,
        };
        let block = tf.block(block_id);
        let tx = block.transactions().get(0).unwrap();
        let tx_id = tx.transaction().get_id();

        assert!(verifier
            .can_disconnect_transaction(&TransactionSource::Chain(block_id), &tx_id)
            .unwrap());
        verifier
            .disconnect_transaction(&TransactionSource::Chain(block_id), tx)
            .unwrap();
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn connect_disconnect_tx_mempool(#[case] seed: Seed) {
    utils::concurrency::model(move || {
        let mut rng = make_seedable_rng(seed);
        let (chain_config, storage, mut tf) = setup();

        // create a block with a single tx based on genesis
        let tx0 = TransactionBuilder::new()
            .add_input(
                TxInput::new(
                    OutPointSourceId::BlockReward(tf.genesis().get_id().into()),
                    0,
                ),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(1000)),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .build();
        let tx0_id = tx0.transaction().get_id();

        let best_block = tf
            .make_block_builder()
            .add_transaction(tx0)
            .build_and_process()
            .unwrap()
            .unwrap();

        let mut verifier = TransactionVerifier::new(&storage, &chain_config);
        let tx_source = TransactionSourceForConnect::Mempool {
            current_best: &best_block,
        };

        // create and connect a tx from mempool based on best block
        let tx1 = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx0_id), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(100)),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .build();

        verifier
            .connect_transaction(&tx_source, &tx1, &tf.genesis().timestamp())
            .unwrap();

        // create and connect a tx from mempool based on previous tx from mempool
        let tx2 = TransactionBuilder::new()
            .add_input(
                TxInput::new(OutPointSourceId::Transaction(tx1.transaction().get_id()), 0),
                empty_witness(&mut rng),
            )
            .add_output(TxOutput::new(
                OutputValue::Coin(Amount::from_atoms(10)),
                OutputPurpose::Transfer(anyonecanspend_address()),
            ))
            .build();

        verifier
            .connect_transaction(&tx_source, &tx2, &tf.genesis().timestamp())
            .unwrap();

        {
            // derived verifier that didn't connect a tx should not be able to disconnect it
            let mut child_verifier = verifier.derive_child();
            assert_eq!(
                child_verifier
                    .can_disconnect_transaction(
                        &TransactionSource::Mempool,
                        &tx1.transaction().get_id(),
                    )
                    .unwrap_err(),
                ConnectTransactionError::MissingMempoolTxsUndo,
            );
            assert_eq!(
                child_verifier.disconnect_transaction(&TransactionSource::Mempool, &tx1),
                Err(chainstate::ConnectTransactionError::MissingMempoolTxsUndo)
            );
            assert_eq!(
                child_verifier
                    .can_disconnect_transaction(
                        &TransactionSource::Mempool,
                        &tx2.transaction().get_id()
                    )
                    .unwrap_err(),
                ConnectTransactionError::MissingMempoolTxsUndo,
            );
            assert_eq!(
                child_verifier.disconnect_transaction(&TransactionSource::Mempool, &tx2),
                Err(chainstate::ConnectTransactionError::MissingMempoolTxsUndo)
            );
        }

        // disconnect should work in proper order only: tx2 and then tx1
        assert!(!verifier
            .can_disconnect_transaction(&TransactionSource::Mempool, &tx1.transaction().get_id())
            .unwrap());
        assert!(verifier
            .can_disconnect_transaction(&TransactionSource::Mempool, &tx2.transaction().get_id())
            .unwrap());

        assert_eq!(
            verifier.disconnect_transaction(&TransactionSource::Mempool, &tx1),
            Err(chainstate::ConnectTransactionError::TxUndoWithDependency(
                tx1.transaction().get_id()
            ))
        );
        verifier.disconnect_transaction(&TransactionSource::Mempool, &tx2).unwrap();

        assert!(verifier
            .can_disconnect_transaction(&TransactionSource::Mempool, &tx1.transaction().get_id())
            .unwrap());
        verifier.disconnect_transaction(&TransactionSource::Mempool, &tx1).unwrap();
    });
}
