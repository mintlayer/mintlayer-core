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

use std::time::Duration;

use rstest::rstest;

use common::{
    chain::{
        AccountNonce, AccountSpending, DelegationId, SignedTransaction, TxInput,
        signature::inputsig::InputWitness,
    },
    primitives::{Amount, H256},
};
use randomness::RngExt;
use test_utils::random::{Rng, Seed, make_seedable_rng};

use super::*;

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
        let tx_dep = orphans.get_at(*iid).required_deps().find(|r| r == dep);
        assert!(tx_dep.is_some(), "Entry {iid:?} outpoint missing");
    });

    let mut count_sum = 0;
    let mut size_sum = 0;
    orphans.maps.origin_stats.iter().for_each(|(origin, stat)| {
        assert!(
            stat.count > 0,
            "Origin {origin:?} lingers with zero entries"
        );
        let entries = orphans
            .maps
            .by_origin
            .range((*origin, InternalId::ZERO)..=(*origin, InternalId::MAX))
            .count();
        assert_eq!(stat.count, entries, "Origin {origin:?} count inconsistent");
        count_sum += stat.count;
        size_sum += stat.size;
    });
    assert_eq!(count_sum, len, "Origin stats count sum inconsistent");
    assert_eq!(
        size_sum,
        orphans.transactions.iter().map(|entry| entry.size().get()).sum::<usize>(),
        "Origin stats size sum inconsistent",
    );
}

fn random_peer_origin(rng: &mut impl Rng) -> RemoteTxOrigin {
    RemoteTxOrigin::new(p2p_types::PeerId::from_u64(rng.random_range(0u64..20)))
}

fn random_tx_entry(rng: &mut impl Rng) -> TxEntry {
    let n_inputs = rng.random_range(1..=10);
    let inputs: Vec<_> = (0..n_inputs)
        .map(|_| {
            if rng.random_bool(0.8) {
                let source: Id<Transaction> = H256(rng.random()).into();
                let output_index = rng.random_range(0..=400);
                TxInput::from_utxo(source.into(), output_index)
            } else {
                let nonce = AccountNonce::new(rng.random());
                let delegation_id: DelegationId = H256(rng.random()).into();
                let amount = Amount::from_atoms(rng.random());
                TxInput::from_account(
                    nonce,
                    AccountSpending::DelegationBalance(delegation_id, amount),
                )
            }
        })
        .collect();

    let transaction = Transaction::new(0, inputs, Vec::new()).unwrap();
    let signatures = vec![InputWitness::NoSignature(None); n_inputs];
    let transaction = SignedTransaction::new(transaction, signatures).unwrap();
    let insertion_time = Duration::from_secs(rng.random());
    let origin = random_peer_origin(rng).into();
    let options = crate::TxOptions::default_for(origin);

    TxEntry::new(
        transaction,
        Time::from_duration_since_epoch(insertion_time),
        origin,
        options,
    )
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn insert_and_delete(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut orphans = TxOrphanPool::new(
        config::DEFAULT_LOCAL_ORPHAN_POOL_CAPACITY,
        config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
        config::DEFAULT_OUTBOUND_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
    );

    let entry = random_tx_entry(&mut rng);
    let tx_id = *entry.tx_id();
    let n_deps = BTreeSet::from_iter(entry.required_deps()).len();

    assert_eq!(orphans.insert(entry), Ok(TxStatus::InOrphanPool));

    assert_eq!(orphans.len(), 1);
    assert_eq!(orphans.transactions.len(), 1);
    assert_eq!(
        orphans.maps.by_tx_id.keys().collect::<Vec<_>>(),
        vec![&tx_id],
    );
    assert_eq!(orphans.maps.by_deps.len(), n_deps);
    assert_eq!(orphans.maps.by_insertion_time.len(), 1);
    check_integrity(&orphans);

    assert!(orphans.entry(&tx_id).map(|e| e.take()).is_some());

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
    let mut orphans = TxOrphanPool::new(
        config::DEFAULT_LOCAL_ORPHAN_POOL_CAPACITY,
        config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
        config::DEFAULT_OUTBOUND_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
    );
    let time = Time::from_secs_since_epoch(0);

    for entry in (0..config::DEFAULT_ORPHAN_POOL_CAPACITY).map(|_| random_tx_entry(&mut rng)) {
        assert_eq!(
            orphans.insert_and_enforce_limits(entry, time),
            Ok(TxStatus::InOrphanPool)
        );
    }

    assert_eq!(orphans.len(), config::DEFAULT_ORPHAN_POOL_CAPACITY);

    for entry in (0..rng.random_range(1..100)).map(|_| random_tx_entry(&mut rng)) {
        let _ = orphans.insert_and_enforce_limits(entry, time);
        assert_eq!(orphans.len(), config::DEFAULT_ORPHAN_POOL_CAPACITY);
    }
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn simulation(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut orphans = TxOrphanPool::new(
        config::DEFAULT_LOCAL_ORPHAN_POOL_CAPACITY,
        config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
        config::DEFAULT_OUTBOUND_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
    );
    check_integrity(&orphans);

    for _ in 0..300 {
        let len_before = orphans.len();
        match rng.random_range(0..=4) {
            // Insert a random tx
            0..=1 => {
                let entry = random_tx_entry(&mut rng);
                assert_eq!(
                    orphans.insert(entry.clone()),
                    Ok(TxStatus::InOrphanPool),
                    "Insertion of {entry:?} failed"
                );
                assert_eq!(orphans.len(), len_before + 1);
            }

            // Delete an existing tx
            2..=2 => {
                if orphans.transactions.is_empty() {
                    continue;
                }
                let i = rng.random_range(0..orphans.transactions.len());
                let id = *orphans.transactions[i].tx_id();
                assert!(
                    orphans.entry(&id).map(|e| e.take()).is_some(),
                    "Removal of {id:?} failed"
                );
                assert_eq!(orphans.len(), len_before - 1);
            }

            // Enforce size limits
            3..=3 => {
                let limit = rng.random_range(0..=150);
                orphans.enforce_max_size(limit);
                assert!(orphans.len() <= limit);
                assert!(orphans.len() <= len_before);
            }

            // Delete all txs by origin
            4..=4 => {
                let origin = TxOrigin::Remote(random_peer_origin(&mut rng));
                orphans.remove_by_origin_impl(origin);
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

fn tx_entry_with_origin(rng: &mut impl Rng, origin: TxOrigin, time: Time) -> TxEntry {
    tx_entry_with_options(rng, origin, time, false)
}

fn tx_entry_with_options(
    rng: &mut impl Rng,
    origin: TxOrigin,
    time: Time,
    outbound: bool,
) -> TxEntry {
    let n_inputs = rng.random_range(1..=3);
    let inputs: Vec<_> = (0..n_inputs)
        .map(|_| {
            let source: Id<Transaction> = H256(rng.random()).into();
            TxInput::from_utxo(source.into(), rng.random_range(0..=400))
        })
        .collect();

    let transaction = Transaction::new(0, inputs, Vec::new()).unwrap();
    let signatures = vec![InputWitness::NoSignature(None); n_inputs];
    let transaction = SignedTransaction::new(transaction, signatures).unwrap();
    let options = crate::TxOptions::default_for(origin).with_origin_peer_outbound(outbound);

    TxEntry::new(transaction, time, origin, options)
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn accounting_tracks_per_origin_occupancy(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut orphans = TxOrphanPool::new(
        config::DEFAULT_LOCAL_ORPHAN_POOL_CAPACITY,
        config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
        config::DEFAULT_OUTBOUND_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
    );
    let time = Time::from_secs_since_epoch(0);

    let origin_a = TxOrigin::Remote(RemoteTxOrigin::new(p2p_types::PeerId::from_u64(11)));
    let origin_b = TxOrigin::Remote(RemoteTxOrigin::new(p2p_types::PeerId::from_u64(12)));

    let mut sizes = BTreeMap::new();
    for (origin, n) in [(origin_a, 3), (origin_b, 2)] {
        for _ in 0..n {
            let entry = tx_entry_with_origin(&mut rng, origin, time);
            *sizes.entry(origin).or_insert(0) += entry.size().get();
            assert_eq!(
                orphans.insert_and_enforce_limits(entry, time),
                Ok(TxStatus::InOrphanPool)
            );
        }
    }

    assert_eq!(orphans.len(), 5);
    assert_eq!(orphans.origin_len(origin_a), 3);
    assert_eq!(orphans.origin_len(origin_b), 2);
    assert_eq!(orphans.origin_size(origin_a), sizes[&origin_a]);
    assert_eq!(orphans.origin_size(origin_b), sizes[&origin_b]);
    assert_eq!(orphans.tracked_origin_count(), 2);
    assert_eq!(orphans.local_len(), 0);
    check_integrity(&orphans);

    orphans.remove_by_origin_impl(origin_a);
    assert_eq!(orphans.origin_len(origin_a), 0);
    assert_eq!(orphans.origin_size(origin_a), 0);
    assert_eq!(orphans.origin_len(origin_b), 2);
    check_integrity(&orphans);
}

#[rstest]
#[trace]
#[case(Seed::from_entropy())]
fn teardown_purges_zero_count_origin_keys(#[case] seed: Seed) {
    let mut rng = make_seedable_rng(seed);
    let mut orphans = TxOrphanPool::new(
        config::DEFAULT_LOCAL_ORPHAN_POOL_CAPACITY,
        config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
        config::DEFAULT_OUTBOUND_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
    );
    let time = Time::from_secs_since_epoch(0);

    let origin = TxOrigin::Remote(RemoteTxOrigin::new(p2p_types::PeerId::from_u64(21)));
    let entry = tx_entry_with_origin(&mut rng, origin, time);
    assert_eq!(orphans.insert(entry), Ok(TxStatus::InOrphanPool));
    assert_eq!(orphans.tracked_origin_count(), 1);

    orphans.remove_by_origin_impl(origin);
    assert_eq!(orphans.origin_len(origin), 0);
    assert_eq!(
        orphans.tracked_origin_count(),
        0,
        "zero-count origin keys must not accumulate across peer churn",
    );
}

fn remote_origin(peer: u64) -> TxOrigin {
    TxOrigin::Remote(RemoteTxOrigin::new(p2p_types::PeerId::from_u64(peer)))
}

/// Fill the pool exactly to its capacity: `peers` remote peers with `per_peer` entries each.
/// Every origin is at (not beyond) its reservation. All entries share one timestamp (no
/// expiry sweep); "oldest" ties in the maps break by insertion order via the internal ID.
fn fill_to_capacity(peers: u64, per_peer: usize) -> (TxOrphanPool, Vec<Vec<Id<Transaction>>>) {
    let mut rng = make_seedable_rng(Seed::from_entropy());
    let mut orphans = TxOrphanPool::new(
        config::DEFAULT_LOCAL_ORPHAN_POOL_CAPACITY,
        config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
        config::DEFAULT_OUTBOUND_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
    );
    let mut ids_per_peer = Vec::new();

    for peer in 0..peers {
        let mut ids = Vec::new();
        for _i in 0..per_peer {
            let time = Time::from_secs_since_epoch(0);
            let entry = tx_entry_with_origin(&mut rng, remote_origin(peer), time);
            ids.push(*entry.tx_id());
            assert_eq!(
                orphans.insert_and_enforce_limits(entry, time),
                Ok(TxStatus::InOrphanPool)
            );
        }
        ids_per_peer.push(ids);
    }

    assert_eq!(orphans.len(), config::DEFAULT_ORPHAN_POOL_CAPACITY);
    (orphans, ids_per_peer)
}

#[test]
fn admission_rejects_flood_when_full_instead_of_evicting_protected_entries() {
    let (mut orphans, ids_per_peer) = fill_to_capacity(10, 10);
    let mut rng = make_seedable_rng(Seed::from_entropy());

    // A flood from another peer cannot displace any parked entry; it is rejected outright.
    for _i in 0..100u32 {
        let time = Time::from_secs_since_epoch(0);
        let entry = tx_entry_with_origin(&mut rng, remote_origin(99), time);
        assert_eq!(
            orphans.insert_and_enforce_limits(entry, time),
            Err(OrphanPoolError::Full)
        );
    }

    assert_eq!(orphans.len(), config::DEFAULT_ORPHAN_POOL_CAPACITY);
    for ids in &ids_per_peer {
        assert!(ids.iter().all(|id| orphans.contains(id)));
    }
    check_integrity(&orphans);
}

#[test]
fn eviction_reservation_uses_outbound_tier() {
    let mut rng = make_seedable_rng(Seed::from_entropy());
    let mut orphans = TxOrphanPool::new(
        config::DEFAULT_LOCAL_ORPHAN_POOL_CAPACITY,
        config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
        config::DEFAULT_OUTBOUND_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
    );
    let time = Time::from_secs_since_epoch(0);

    // An outbound origin pushed 4 entries beyond its own (larger) reservation; an inbound
    // origin 2 beyond its smaller one. Total pool target: 40 + 10 = 50.
    let mut outbound_ids = Vec::new();
    for _i in 0..44 {
        let entry = tx_entry_with_options(&mut rng, remote_origin(1), time, true);
        outbound_ids.push(*entry.tx_id());
        assert_eq!(orphans.insert(entry), Ok(TxStatus::InOrphanPool));
    }
    let mut inbound_ids = Vec::new();
    for _i in 0..12 {
        let entry = tx_entry_with_origin(&mut rng, remote_origin(2), time);
        inbound_ids.push(*entry.tx_id());
        assert_eq!(orphans.insert(entry), Ok(TxStatus::InOrphanPool));
    }

    // Evicting down to 50 removes exactly each origin's over-reservation excess: the 4
    // oldest outbound entries (largest excess first), then the 2 oldest inbound ones. The
    // outbound origin keeps its full 40-entry tier, not the inbound 10.
    assert_eq!(orphans.enforce_max_size(50), 6);
    assert_eq!(orphans.len(), 50);

    // The outbound origin loses exactly its 4 over-reservation entries (its oldest — at this
    // point internal IDs still match insertion order) and keeps the rest of its 40-entry tier.
    for id in &outbound_ids[..4] {
        assert!(
            !orphans.contains(id),
            "oldest over-reservation outbound entry to go"
        );
    }
    assert!(outbound_ids[4..].iter().all(|id| orphans.contains(id)));

    // The inbound origin loses exactly its 2 over-reservation entries. Which two of the twelve
    // is not pinned down: after the first swap-removal, internal IDs no longer track insertion
    // order, so the "oldest" pick among equal timestamps is an arbitrary member of the origin.
    let n_inbound_gone = inbound_ids.iter().filter(|id| !orphans.contains(id)).count();
    assert_eq!(n_inbound_gone, 2);
    check_integrity(&orphans);
}

#[test]
fn eviction_prefers_entries_from_origins_beyond_reservation() {
    let (mut orphans, ids_per_peer) = fill_to_capacity(10, 10);
    let mut rng = make_seedable_rng(Seed::from_entropy());

    // Take peer 0 one entry beyond its reservation with a direct insert.
    let overflow = tx_entry_with_origin(&mut rng, remote_origin(0), Time::from_secs_since_epoch(1));
    let overflow_id = *overflow.tx_id();
    assert_eq!(orphans.insert(overflow), Ok(TxStatus::InOrphanPool));
    assert_eq!(orphans.len(), 101);

    // Enforcing the cap removes exactly the over-reservation origin's oldest entry.
    assert_eq!(
        orphans.enforce_max_size(config::DEFAULT_ORPHAN_POOL_CAPACITY),
        1
    );
    assert_eq!(orphans.len(), 100);
    assert_eq!(orphans.origin_len(remote_origin(0)), 10);
    assert!(orphans.contains(&overflow_id));
    assert!(!orphans.contains(&ids_per_peer[0][0]));
    for ids in ids_per_peer.iter().skip(1) {
        assert!(ids.iter().all(|id| orphans.contains(id)));
    }
    check_integrity(&orphans);
}

#[test]
fn resubmission_of_parked_orphan_stays_idempotent_when_pool_is_full() {
    let (mut orphans, ids_per_peer) = fill_to_capacity(10, 10);

    let parked_id = ids_per_peer[3][5];
    let resubmission = orphans.get(&parked_id).unwrap().clone();
    assert_eq!(
        orphans.insert_and_enforce_limits(resubmission, Time::from_secs_since_epoch(0)),
        Ok(TxStatus::InOrphanPoolDuplicate)
    );
    assert_eq!(orphans.len(), config::DEFAULT_ORPHAN_POOL_CAPACITY);
    check_integrity(&orphans);
}

#[test]
fn resubmission_of_expired_orphan_is_rejected_and_swept() {
    let mut rng = make_seedable_rng(Seed::from_entropy());
    let mut orphans = TxOrphanPool::new(
        config::DEFAULT_LOCAL_ORPHAN_POOL_CAPACITY,
        config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
        config::DEFAULT_OUTBOUND_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
    );

    let entry = tx_entry_with_origin(&mut rng, remote_origin(1), Time::from_secs_since_epoch(0));
    assert_eq!(
        orphans.insert_and_enforce_limits(entry.clone(), Time::from_secs_since_epoch(0)),
        Ok(TxStatus::InOrphanPool)
    );

    // Once the expiry interval has passed, the sweep must remove the entry even when the
    // very same transaction is resubmitted: the duplicate check must not shield stale
    // entries from expiry. The resubmission itself is stale by then and falls through to
    // admission, where its own creation time makes it expire again — reported as `Full`,
    // leaving the pool empty, instead of the old order's perpetual `InOrphanPoolDuplicate`.
    let after_expiry =
        Time::from_secs_since_epoch(config::DEFAULT_ORPHAN_TX_EXPIRY_INTERVAL.as_secs() + 1);
    assert_eq!(
        orphans.insert_and_enforce_limits(entry, after_expiry),
        Err(OrphanPoolError::Full)
    );
    assert_eq!(orphans.len(), 0);
    check_integrity(&orphans);
}
