// Copyright (c) 2021 RBB S.r.l
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

use super::{in_memory::UtxosDBInMemoryImpl, *};
use crate::{
    tests::test_helper::{convert_to_utxo, create_tx_inputs, create_tx_outputs, create_utxo},
    utxo_entry::{IsDirty, IsFresh, UtxoEntry},
    ConsumedUtxoCache,
    Error::*,
    FlushableUtxoView, UtxosView,
};
use common::{
    chain::{
        block::timestamp::BlockTimestamp, signature::inputsig::InputWitness, OutPointSourceId,
        Transaction, TxInput,
    },
    primitives::{BlockHeight, Id, Idable, H256},
};
use crypto::random::Rng;
use itertools::Itertools;
use rstest::rstest;
use std::collections::BTreeMap;
use test_utils::random::{make_seedable_rng, Seed};

fn create_transactions(
    rng: &mut impl Rng,
    inputs: Vec<TxInput>,
    max_num_of_outputs: usize,
    num_of_txs: usize,
) -> Vec<Transaction> {
    // distribute the inputs on the number of the transactions specified.
    let input_size = inputs.len() / num_of_txs;

    // create the multiple transactions based on the inputs.
    inputs
        .chunks(input_size)
        .into_iter()
        .map(|inputs| {
            let outputs = if max_num_of_outputs > 1 {
                let rnd = rng.gen_range(1..max_num_of_outputs);
                create_tx_outputs(rng, rnd as u32)
            } else {
                vec![]
            };

            Transaction::new(0x00, inputs.to_vec(), outputs, 0)
                .expect("should create a transaction successfully")
        })
        .collect_vec()
}

fn create_block(
    rng: &mut impl Rng,
    prev_block_id: Id<GenBlock>,
    inputs: Vec<TxInput>,
    max_num_of_outputs: usize,
    num_of_txs: usize,
) -> Block {
    let txs = create_transactions(rng, inputs, max_num_of_outputs, num_of_txs);
    Block::new_with_no_consensus(txs, prev_block_id, BlockTimestamp::from_int_seconds(1))
        .expect("should be able to create a block")
}

/// populate the db with random values, for testing.
/// returns a tuple of the best block id and the outpoints (for spending)
fn initialize_db(rng: &mut impl Rng, tx_outputs_size: u32) -> (UtxosDBInMemoryImpl, Vec<OutPoint>) {
    let best_block_id: Id<GenBlock> = Id::new(H256::random());
    let mut db_interface = UtxosDBInMemoryImpl::new(best_block_id, Default::default());

    // let's populate the db with outputs.
    let tx_outputs = create_tx_outputs(rng, tx_outputs_size);

    // collect outpoints for spending later
    let outpoints = tx_outputs
        .into_iter()
        .enumerate()
        .map(|(idx, output)| {
            let (outpoint, utxo) = convert_to_utxo(output, 0, idx);
            // immediately add to the db
            assert!(db_interface.set_utxo(&outpoint, utxo).is_ok());

            outpoint
        })
        .collect_vec();

    (db_interface, outpoints)
}

fn create_utxo_entries(rng: &mut impl Rng, num_of_utxos: u8) -> BTreeMap<OutPoint, UtxoEntry> {
    let mut map = BTreeMap::new();
    for _ in 0..num_of_utxos {
        let (utxo, outpoint) = create_utxo(rng, 0);
        let entry = UtxoEntry::new(Some(utxo), IsFresh::Yes, IsDirty::Yes);
        map.insert(outpoint, entry);
    }

    map
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
// This tests the utxo and the undo. This does not include testing the state of the block.
fn utxo_and_undo_test(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let tx_outputs_size = 3;
    let num_of_txs = 1;

    // initializing the db with existing utxos.
    let (mut db_impl, outpoints) = initialize_db(&mut rng, tx_outputs_size);
    // create the TxInputs for spending.
    let expected_tx_inputs = create_tx_inputs(&mut rng, &outpoints);
    // create the UtxosDB.
    let mut db = UtxosDBMut::new(&mut db_impl);

    // let's check that each tx_input exists in the db. Secure the spent utxos.
    let spent_utxos = expected_tx_inputs
        .iter()
        .map(|input| {
            let outpoint = input.outpoint();
            assert!(db.has_utxo(outpoint));

            db.utxo(outpoint).expect("utxo should exist.")
        })
        .collect_vec();

    // test the spend
    let (block, block_undo) = {
        // create a cache based on the db.
        let mut cache = db.derive_cache();

        // create a new block to spend.
        let block = create_block(
            &mut rng,
            cache.best_block_hash(),
            expected_tx_inputs.clone(),
            0,
            num_of_txs,
        );
        let block_height = BlockHeight::new(1);
        // spend the block
        let block_undo = {
            let undos = block
                .transactions()
                .iter()
                .map(|tx| cache.spend_utxos_from_tx(tx, block_height).expect("should spend okay."))
                .collect_vec();
            BlockUndo::new(Default::default(), undos)
        };

        // check that the block_undo contains the same utxos recorded as "spent",
        // using the `spent_utxos`
        {
            block_undo.tx_undos().iter().enumerate().for_each(|(b_idx, tx_undo)| {
                tx_undo.inner().iter().enumerate().for_each(|(t_idx, utxo)| {
                    assert_eq!(Some(utxo), spent_utxos.get(b_idx + t_idx));
                })
            })
        }

        // flush to db
        cache.set_best_block(block.get_id().into());
        let consumed_cache = cache.consume();
        db.batch_write(consumed_cache).unwrap();

        (block, block_undo)
    };

    // check that all in tx_inputs do NOT exist
    expected_tx_inputs.iter().for_each(|input| {
        assert_eq!(db.utxo(input.outpoint()), None);
    });

    // save the undo data to the db.
    {
        db.set_undo_data(block.get_id(), &block_undo).unwrap();
        // check that the block_undo retrieved from db is the same as the one being stored.
        let block_undo_from_db = db.get_undo_data(block.get_id()).unwrap();
        assert_eq!(block_undo_from_db.as_ref(), Some(&block_undo));
    }

    // check that the inputs of the block do not exist in the utxo column.
    {
        block.transactions().iter().for_each(|tx| {
            tx.inputs().iter().for_each(|input| {
                assert_eq!(db.utxo(input.outpoint()), None);
            });
        });
    }

    // let's try to reverse the spending.
    {
        // get the best_block_id
        let current_best_block_id = db.best_block_hash();

        // the current best_block_id should be the block id..
        assert_eq!(&current_best_block_id, &block.get_id());

        // get the block_undo.
        let block_undo = db
            .get_undo_data(Id::new(current_best_block_id.get()))
            .expect("query should not fail")
            .expect("should return the undo file");

        // check that the block_undo's size is the same as the expected tx inputs.
        assert_eq!(block_undo.tx_undos().len(), expected_tx_inputs.len());

        // let's create a view.
        let mut cache = db.derive_cache();

        // get the block txinputs, and add them to the view.
        block.transactions().iter().enumerate().for_each(|(idx, tx)| {
            // use the undo to get the utxos
            let undo = block_undo.tx_undos().get(idx).unwrap();
            let undos = undo.inner();

            // add the undo utxos back to the view.
            tx.inputs().iter().enumerate().for_each(|(in_idx, input)| {
                let utxo = undos.get(in_idx).unwrap();
                cache.add_utxo(input.outpoint(), utxo.clone(), true).unwrap();
            });
        });

        // flush the view to the db.
        let consumed_cache = cache.consume();
        db.batch_write(consumed_cache).unwrap();

        // remove the block undo file
        db.del_undo_data(block.get_id()).unwrap();
        assert_eq!(db.get_undo_data(block.get_id()), Ok(None));
    }

    // check that all the expected_tx_inputs exists, and the same utxo is saved.
    expected_tx_inputs.iter().enumerate().for_each(|(idx, input)| {
        let res = db.utxo(input.outpoint());

        let expected_utxo = spent_utxos.get(idx);
        assert_eq!(res.as_ref(), expected_utxo);
    });
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_spend_tx_with_no_outputs(#[case] seed: Seed) {
    let num_of_txs = 1;
    let tx_outputs_size = 3;

    let mut rng = make_seedable_rng(seed);

    let (db_impl, _) = initialize_db(&mut rng, tx_outputs_size);
    let db = UtxosDB::new(&db_impl);

    let tx_inputs: Vec<TxInput> = (0..rng.gen_range(num_of_txs..20))
        .into_iter()
        .map(|i| {
            let id: Id<GenBlock> = Id::new(H256::random());
            let id = OutPointSourceId::BlockReward(id);

            TxInput::new(id, i, InputWitness::NoSignature(None))
        })
        .collect();

    let id = db.best_block_hash();

    // Create a block with 1 tx and 0 outputs in txs
    let block = create_block(&mut rng, id, tx_inputs, 0, num_of_txs as usize);
    let mut view = db.derive_cache();
    let tx = block.transactions().get(0).unwrap();

    assert_eq!(
        view.spend_utxos_from_tx(tx, BlockHeight::new(2)).unwrap_err(),
        NoUtxoFound
    );
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn test_batch_write(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let utxos = create_utxo_entries(&mut rng, 10);
    let new_best_block_hash = Id::new(H256::random());

    let mut db_interface = UtxosDBInMemoryImpl::new(new_best_block_hash, Default::default());
    let mut utxo_db = UtxosDBMut::new(&mut db_interface);

    let utxos = ConsumedUtxoCache {
        container: utxos,
        best_block: new_best_block_hash,
    };

    utxo_db.batch_write(utxos.clone()).unwrap();

    // randomly get a key for checking
    let keys = utxos.container.keys().collect_vec();
    let key_index = rng.gen_range(0..keys.len());
    let outpoint = keys[key_index].clone();

    // test the get_utxo
    let utxo_opt = utxo_db.utxo(&outpoint);
    let utxo_entry = utxos.container.get(&outpoint).expect("an entry should be found");
    assert_eq!(utxo_entry.utxo(), utxo_opt.as_ref());

    // check has_utxo
    assert!(utxo_db.has_utxo(&outpoint));

    //check the best block hash
    assert_eq!(utxo_db.best_block_hash(), new_best_block_hash);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn try_flush_non_dirty_utxo(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);

    let mut db_interface = UtxosDBInMemoryImpl::new(Id::new(H256::random()), Default::default());
    let mut utxo_db = UtxosDBMut::new(&mut db_interface);

    let (utxo, outpoint) = create_utxo(&mut rng, 1);
    let mut map = BTreeMap::new();
    let entry = UtxoEntry::new(Some(utxo), IsFresh::No, IsDirty::No);
    map.insert(outpoint.clone(), entry);

    let cache = ConsumedUtxoCache {
        container: map,
        best_block: Id::new(H256::random()),
    };

    utxo_db.batch_write(cache).unwrap();

    assert!(!utxo_db.has_utxo(&outpoint));
}

#[test]
fn try_flush_spent_utxo() {
    let mut db_interface = UtxosDBInMemoryImpl::new(Id::new(H256::random()), Default::default());
    let mut utxo_db = UtxosDBMut::new(&mut db_interface);

    let outpoint = OutPoint::new(OutPointSourceId::Transaction(Id::new(H256::random())), 0);
    let mut map = BTreeMap::new();
    let entry = UtxoEntry::new(None, IsFresh::No, IsDirty::Yes);
    map.insert(outpoint.clone(), entry);

    let cache = ConsumedUtxoCache {
        container: map,
        best_block: Id::new(H256::random()),
    };

    utxo_db.batch_write(cache).unwrap();

    assert!(!utxo_db.has_utxo(&outpoint));
}
