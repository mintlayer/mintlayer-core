// Copyright (c) 2023 RBB S.r.l
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
use common::{
    chain::{signature::inputsig::InputWitness, SignedTransaction, TxInput},
    primitives::H256,
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Rng, Seed};

fn check_integrity(op: &TxOrphanPool) {
    assert_eq!(op.transactions.len(), op.maps.by_tx_id.len());
    assert_eq!(op.transactions.len(), op.maps.by_insertion_time.len());
    op.maps.by_tx_id.iter().for_each(|(tx_id, iid)| {
        assert_eq!(
            op.get_at(*iid).tx_id(),
            tx_id,
            "Entry {iid:?} tx ID inconsistent",
        );
    });
    op.maps.by_insertion_time.iter().for_each(|(time, iid)| {
        assert_eq!(
            op.get_at(*iid).creation_time(),
            *time,
            "Entry {iid:?} insertion time inconsistent",
        );
    });
    op.maps.by_input.iter().for_each(|(outpt, iid)| {
        assert!(
            op.get_at(*iid).transaction().inputs().iter().any(|i| i.outpoint() == outpt),
            "Entry {iid:?} outpoint missing",
        );
    });
}

fn sample_tx_entry(rng: &mut impl Rng) -> TxEntry {
    let n_inputs = rng.gen_range(1..=10);
    let inputs: Vec<_> = (0..n_inputs)
        .map(|_| {
            let source = H256(rng.gen()).into();
            let source = common::chain::OutPointSourceId::Transaction(source);
            let output_index = rng.gen_range(0..=400);
            TxInput::new(source, output_index)
        })
        .collect();

    let transaction = Transaction::new(0, inputs, Vec::new()).unwrap();
    let signatures = vec![InputWitness::NoSignature(None); n_inputs];
    let transaction = SignedTransaction::new(transaction, signatures).unwrap();
    let insertion_time = Time::from_secs(rng.gen());
    TxEntry::new(transaction, insertion_time)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn insert_and_delete(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut orphans = TxOrphanPool::new();

    let entry = sample_tx_entry(&mut rng);
    let tx_id = *entry.tx_id();
    let n_inputs = entry.transaction().inputs().len();

    println!("Inserting {tx_id:?}");
    assert!(orphans.insert(entry).is_ok());

    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans.transactions.len(), 1);
    assert_eq!(
        orphans.maps.by_tx_id.keys().collect::<Vec<_>>(),
        vec![&tx_id],
    );
    assert_eq!(orphans.maps.by_insertion_time.len(), 1);
    assert_eq!(orphans.maps.by_input.len(), n_inputs);

    println!("{orphans:?}");
    assert!(orphans.remove(tx_id).is_some());

    assert!(orphans.transactions.is_empty());
    assert!(orphans.maps.by_tx_id.is_empty());
    assert!(orphans.maps.by_insertion_time.is_empty());
    assert!(orphans.maps.by_input.is_empty());
    check_integrity(&orphans);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn simulation(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut orphans = TxOrphanPool::new();
    check_integrity(&orphans);

    for _ in 0..200 {
        let len_before = orphans.len();
        match rng.gen_range(0..=3) {
            // Insert a random tx
            0..=1 => {
                let entry = sample_tx_entry(&mut rng);
                assert_eq!(
                    orphans.insert(entry.clone()),
                    Ok(()),
                    "Insertion of {entry:?} failed"
                );
                assert_eq!(orphans.len(), len_before + 1);
            }

            // Delete an existing tx
            2..=2 => {
                if orphans.transactions.is_empty() {
                    continue;
                }
                let i = rng.gen_range(0..orphans.transactions.len());
                let id = *orphans.transactions[i].tx_id();
                assert!(orphans.remove(id).is_some(), "Removal of {id:?} failed");
                assert_eq!(orphans.len(), len_before - 1);
            }

            // Delete a non-existing tx
            3..=3 => {
                let id: Id<Transaction> = H256(rng.gen::<[u8; 32]>()).into();
                assert_eq!(
                    orphans.remove(id),
                    None,
                    "Removal of non-existent {id:?} failed"
                );
                assert_eq!(orphans.len(), len_before);
            }

            // This should not be generated
            i => panic!("Out of range: {i}"),
        }

        check_integrity(&orphans);
    }
}
