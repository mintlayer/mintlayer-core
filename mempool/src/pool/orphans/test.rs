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
    chain::{
        signature::inputsig::InputWitness, AccountNonce, AccountSpending, DelegationId,
        SignedTransaction, TxInput,
    },
    primitives::{Amount, H256},
};
use rstest::rstest;
use test_utils::random::{make_seedable_rng, Rng, Seed};

fn check_integrity(orphans: &TxOrphanPool) {
    let len = orphans.len();
    assert!(len <= ORPHAN_POOL_SIZE_HARD_LIMIT);
    assert_eq!(len, orphans.transactions.len());
    assert_eq!(len, orphans.maps.by_tx_id.len());
    assert_eq!(len, orphans.maps.by_insertion_time.len());

    orphans.maps.by_tx_id.iter().for_each(|(tx_id, iid)| {
        assert_eq!(
            orphans.get_at(*iid).tx_id(),
            tx_id,
            "Entry {iid:?} tx ID inconsistent",
        );
    });
    orphans.maps.by_insertion_time.iter().for_each(|(time, iid)| {
        assert_eq!(
            orphans.get_at(*iid).creation_time(),
            *time,
            "Entry {iid:?} insertion time inconsistent",
        );
    });
    orphans.maps.by_deps.iter().for_each(|(dep, iid)| {
        let tx_dep = orphans.get_at(*iid).requires().find(|r| r == dep);
        assert!(tx_dep.is_some(), "Entry {iid:?} outpoint missing");
    });
}

fn random_peer_origin(rng: &mut impl Rng) -> TxOrigin {
    TxOrigin::Peer(p2p_types::PeerId::from_u64(rng.gen_range(0u64..20)))
}

fn random_tx_entry(rng: &mut impl Rng) -> TxEntry {
    let n_inputs = rng.gen_range(1..=10);
    let inputs: Vec<_> = (0..n_inputs)
        .map(|_| {
            if rng.gen_bool(0.8) {
                let source: Id<Transaction> = H256(rng.gen()).into();
                let output_index = rng.gen_range(0..=400);
                TxInput::from_utxo(source.into(), output_index)
            } else {
                let nonce = AccountNonce::new(rng.gen());
                let delegation_id: DelegationId = H256(rng.gen()).into();
                let amount = Amount::from_atoms(rng.gen());
                TxInput::from_account(nonce, AccountSpending::Delegation(delegation_id, amount))
            }
        })
        .collect();

    let transaction = Transaction::new(0, inputs, Vec::new()).unwrap();
    let signatures = vec![InputWitness::NoSignature(None); n_inputs];
    let transaction = SignedTransaction::new(transaction, signatures).unwrap();
    let insertion_time = Time::from_secs(rng.gen());

    let origin = match rng.gen_range(0..4) {
        0 | 1 => random_peer_origin(rng),
        2 => TxOrigin::LocalMempool,
        3 => TxOrigin::LocalP2p,
        _ => panic!("out of range"),
    };

    TxEntry::new(transaction, insertion_time, origin)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn insert_and_delete(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut orphans = TxOrphanPool::new();

    let entry = random_tx_entry(&mut rng);
    let tx_id = *entry.tx_id();
    let n_deps = BTreeSet::from_iter(entry.requires()).len();

    assert_eq!(orphans.insert(entry), Ok(()));

    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans.transactions.len(), 1);
    assert_eq!(
        orphans.maps.by_tx_id.keys().collect::<Vec<_>>(),
        vec![&tx_id],
    );
    assert_eq!(orphans.maps.by_deps.len(), n_deps);
    assert_eq!(orphans.maps.by_insertion_time.len(), 1);
    check_integrity(&orphans);

    assert!(orphans.remove(tx_id).is_some());

    assert!(orphans.transactions.is_empty());
    assert!(orphans.maps.by_tx_id.is_empty());
    assert!(orphans.maps.by_insertion_time.is_empty());
    assert!(orphans.maps.by_deps.is_empty());
    check_integrity(&orphans);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn capacity_reached(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut orphans = TxOrphanPool::new();
    let time = Time::from_secs(0);

    for entry in (0..config::DEFAULT_ORPHAN_POOL_CAPACITY).map(|_| random_tx_entry(&mut rng)) {
        assert_eq!(orphans.insert_and_enforce_limits(entry, time), Ok(()));
    }

    assert_eq!(orphans.len(), config::DEFAULT_ORPHAN_POOL_CAPACITY);

    for entry in (0..rng.gen_range(1..100)).map(|_| random_tx_entry(&mut rng)) {
        let _ = orphans.insert_and_enforce_limits(entry, time);
        assert_eq!(orphans.len(), config::DEFAULT_ORPHAN_POOL_CAPACITY);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn simulation(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut orphans = TxOrphanPool::new();
    check_integrity(&orphans);

    for _ in 0..300 {
        let len_before = orphans.len();
        match rng.gen_range(0..=5) {
            // Insert a random tx
            0..=1 => {
                let entry = random_tx_entry(&mut rng);
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

            // Enforce size limits
            4..=4 => {
                let limit = rng.gen_range(0..=150);
                orphans.enforce_max_size(limit);
                assert!(orphans.len() <= limit);
                assert!(orphans.len() <= len_before);
            }

            // Delete all txs by origin
            5..=5 => {
                let origin = match rng.gen_range(0..=5) {
                    0..=3 => random_peer_origin(&mut rng),
                    4..=4 => TxOrigin::LocalMempool,
                    5..=5 => TxOrigin::LocalP2p,
                    _ => panic!("out of range"),
                };
                orphans.remove_by_origin(origin);
                let count = orphans
                    .maps
                    .by_origin
                    .range((origin, InternalId::ZERO)..=(origin, InternalId::MAX))
                    .count();
                assert_eq!(count, 0, "Removing txs by origin {origin:?} failed");
            }

            // This should not be generated
            i => panic!("Out of range: {i}"),
        }

        check_integrity(&orphans);
    }
}
