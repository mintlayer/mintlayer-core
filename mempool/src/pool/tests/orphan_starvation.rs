// Proof of concept: orphan pool starvation in the mintlayer-core mempool.
//
// Regression suite for the fix: per-peer quotas for remote orphans plus reservation-aware
// admission mean a full pool rejects a flood instead of displacing other peers' parked
// orphans, and eviction no longer ignores which peer contributed an entry.
//
// Every submission goes through `MempoolInterface::add_transaction_remote`, the same method p2p
// calls (`p2p/src/sync/peer/transaction_manager.rs`), so no test-only shortcut is involved.
//
// Sections (one or more tests each):
//   1. control  - a child parked before its parent is promoted once the parent arrives.
//   2. attack   - a flood from a single peer cannot cost a parked child its promotion.
//   3. scale    - a flood against a full pool is rejected; every parked orphan survives.
//   4. quota    - per-peer fairness: hostile floods, many small peers, legitimate load.
//   5. expiry   - expired entries are reclaimed before the quota is evaluated.
//   6. teardown - a peer's orphans leave with its connection.
//   7. tiers    - outbound peers get a larger share; both tiers cap their own peers.
//
// Run:  cd mintlayer-core && cargo test -p mempool --lib orphan_starvation -- --nocapture --test-threads=1

use super::*;

use crate::interface::MempoolInterface;
use common::chain::signature::inputsig::InputWitness;
use common::primitives::time::Time;
use common::time_getter::{TimeGetter, TimeGetterFn};
use mempool_types::tx_origin::RemoteTxOrigin;
use p2p_types::PeerId;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// A clock the test advances manually, so expiry windows can be crossed without waiting.
struct FixedClock(Arc<AtomicU64>);

impl TimeGetterFn for FixedClock {
    fn get_time(&self) -> Time {
        Time::from_secs_since_epoch(self.0.load(Ordering::SeqCst))
    }
}

type Pool = crate::pool::Mempool<crate::pool::memory_usage_estimator::StoreMemoryUsageEstimator>;

// The scale scenario parks one peer per unit of the inbound quota and assumes the result
// fills the pool exactly; keep the defaults coupled or the scenario must be reworked.
const _: () = assert!(
    crate::config::DEFAULT_ORPHAN_POOL_CAPACITY
        == 10 * crate::config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
    "scale scenario assumes 10 peers at the default per-peer quota fill the pool exactly",
);

const HONEST_PEER: u64 = 2;
const HOSTILE_PEER: u64 = 3;

/// Submit a transaction exactly as a remote peer would.
fn submit(
    mempool: &mut Pool,
    tx: SignedTransaction,
    peer_id: u64,
) -> Result<TxStatus, crate::error::Error> {
    let origin = RemoteTxOrigin::new(PeerId::from_u64(peer_id));
    let options = TxOptions::default_for(origin.into());
    mempool.add_transaction_remote(tx, origin, options)
}

/// A minimal transaction whose input spends an outpoint that exists nowhere.
/// It satisfies `check_transaction` (structure, witness count, size) and fails later at the utxo
/// lookup, which classifies it as an orphan. No fee is ever computed and no signature is ever
/// verified, because the fee policy only runs for transactions that already validated.
fn free_orphan_tx(counter: u32, tag: u8) -> SignedTransaction {
    let mut input_bytes = [0u8; 32];
    input_bytes[0] = (counter & 0xff) as u8;
    input_bytes[1] = ((counter >> 8) & 0xff) as u8;
    input_bytes[2] = tag;

    let source: Id<Transaction> = H256(input_bytes).into();
    let tx = Transaction::new(
        0,
        vec![TxInput::from_utxo(source.into(), 0)],
        vec![TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1_000)),
            Destination::AnyoneCanSpend,
        )],
    )
    .unwrap();
    SignedTransaction::new(tx, vec![InputWitness::NoSignature(None)]).unwrap()
}

/// One block with one funding tx that provides two spendable outputs.
fn setup() -> (Pool, Id<Transaction>, BlockHeight) {
    setup_with_clock(Default::default())
}

fn setup_with_clock(clock: TimeGetter) -> (Pool, Id<Transaction>, BlockHeight) {
    let mut rng = make_seedable_rng(Seed::from_u64(1));
    let mut tf = TestFramework::builder(&mut rng).build();
    let genesis_id = tf.genesis().get_id();

    let funding = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::BlockReward(genesis_id.into()), 0),
            empty_witness(&mut rng),
        )
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1_000_000)),
            Destination::AnyoneCanSpend,
        ))
        .add_output(TxOutput::Transfer(
            OutputValue::Coin(Amount::from_atoms(1_000_000)),
            Destination::AnyoneCanSpend,
        ))
        .build();
    let funding_id = funding.transaction().get_id();
    tf.make_block_builder()
        .add_transaction(funding)
        .build_and_process(&mut rng)
        .unwrap();

    let height = tf.best_block_index().block_height();
    let mempool = setup_with_chainstate_generic(tf.chainstate(), create_mempool_config(), clock);

    (mempool, funding_id, height)
}

fn parent_and_child(
    rng: &mut impl CryptoRng,
    funding_id: Id<Transaction>,
    out_idx: u32,
) -> (SignedTransaction, SignedTransaction) {
    let parent = TransactionBuilder::new()
        .add_input(
            TxInput::from_utxo(OutPointSourceId::Transaction(funding_id), out_idx),
            empty_witness(rng),
        )
        .add_anyone_can_spend_output(900_000)
        .build();
    let parent_id = parent.transaction().get_id();
    let child = TransactionBuilder::new()
        .add_input(TxInput::from_utxo(parent_id.into(), 0), empty_witness(rng))
        .add_anyone_can_spend_output(800_000)
        .build();
    (parent, child)
}

// ------------------------------------------------------------------ 1. control

/// Baseline: park the child, then deliver the parent. The child is promoted into the mempool.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poc_orphan_control_child_is_promoted() {
    let mut rng = make_seedable_rng(Seed::from_u64(1));
    let (mut mempool, funding_id, height) = setup();
    println!("CONTROL: tip height = {height:?}");

    let (parent, child) = parent_and_child(&mut rng, funding_id, 0);
    let parent_id = parent.transaction().get_id();
    let child_id = child.transaction().get_id();

    submit(&mut mempool, child, HONEST_PEER)
        .expect("child should be parked")
        .assert_in_orphan_pool();
    println!(
        "CONTROL: child parked in orphan pool = {}",
        mempool.contains_orphan_transaction(&child_id)
    );

    submit(&mut mempool, parent, HONEST_PEER)
        .expect("parent should be accepted")
        .assert_in_mempool();
    mempool.process_queue();

    let promoted = mempool.contains_transaction(&child_id);
    println!(
        "CONTROL: parent {parent_id} accepted into mempool = {}",
        mempool.contains_transaction(&parent_id)
    );
    println!("CONTROL: child promoted into mempool = {promoted}");
    assert!(promoted, "baseline broken: the child was not promoted");
}

// ------------------------------------------------------------------ 2. attack

/// Same setup, but the hostile peer floods the pool between the child and its parent.
/// With the per-peer quota in place the flood is capped and the child survives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poc_orphan_attack_quota_protects_child() {
    let mut rng = make_seedable_rng(Seed::from_u64(2));
    let (mut mempool, funding_id, height) = setup();
    println!("ATTACK: tip height = {height:?}");

    let (parent, child) = parent_and_child(&mut rng, funding_id, 1);
    let child_id = child.transaction().get_id();

    submit(&mut mempool, child, HONEST_PEER)
        .expect("child should be parked")
        .assert_in_orphan_pool();
    println!(
        "ATTACK: child parked in orphan pool = {}",
        mempool.contains_orphan_transaction(&child_id)
    );

    let mut accepted = 0u32;
    let mut rejected = 0u32;
    for i in 0..1500u32 {
        match submit(&mut mempool, free_orphan_tx(i, 0xb2), HOSTILE_PEER) {
            Ok(_) => accepted += 1,
            Err(_) => rejected += 1,
        }
    }
    println!("ATTACK: hostile submissions accepted = {accepted}, rejected = {rejected}");
    println!(
        "ATTACK: child survives the flood = {}",
        mempool.contains_orphan_transaction(&child_id)
    );

    submit(&mut mempool, parent, HONEST_PEER)
        .expect("parent should be accepted")
        .assert_in_mempool();
    mempool.process_queue();

    let promoted = mempool.contains_transaction(&child_id);
    println!("ATTACK: child promoted into mempool = {promoted}");
    assert!(promoted, "the per-peer quota must protect the parked child");
}

// ------------------------------------------------------------------ 3. scale

/// With the pool at capacity, a flood is rejected instead of displacing other peers' parked
/// orphans: every peer keeps what it parked and the flood gains nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn poc_orphan_scale_flood_is_rejected_not_displacing() {
    let (mut mempool, _funding_id, _height) = setup();

    // Ten peers park ten orphans each: every peer is at its quota and the pool is full.
    let mut honest_ids = Vec::new();
    for peer in 0..10u32 {
        for i in 0..10u32 {
            let tx = free_orphan_tx(peer * 1000 + i, 0xa1);
            honest_ids.push(tx.transaction().get_id());
            submit(&mut mempool, tx, 10 + peer as u64)
                .expect("orphan should be parked")
                .assert_in_orphan_pool();
        }
    }
    assert_eq!(honest_ids.len(), 100);

    let mut accepted = 0u32;
    for i in 0..1500u32 {
        if submit(&mut mempool, free_orphan_tx(i, 0xb2), HOSTILE_PEER).is_ok() {
            accepted += 1;
        }
    }

    let survivors = honest_ids.iter().filter(|id| mempool.contains_orphan_transaction(id)).count();
    println!("SCALE: hostile submissions accepted = {accepted}");
    println!(
        "SCALE: honest orphans still parked = {survivors} / {}",
        honest_ids.len()
    );
    assert_eq!(
        accepted, 0,
        "a full pool must reject the flood, not evict protected entries"
    );
    assert_eq!(survivors, 100, "every parked orphan must survive the flood");
}

// ------------------------------------------------------------------ 4. quota

/// One hostile connection must not be able to evict another peer's parked orphans.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quota_two_peer_fairness_hostile_flood_cannot_evict() {
    let mut rng = make_seedable_rng(Seed::from_u64(4));
    let (mut mempool, funding_id, _height) = setup();

    let (parent, child) = parent_and_child(&mut rng, funding_id, 0);
    let child_id = child.transaction().get_id();
    submit(&mut mempool, child, HONEST_PEER)
        .expect("child should be parked")
        .assert_in_orphan_pool();

    for i in 0..1500u32 {
        let _ = submit(&mut mempool, free_orphan_tx(i, 0xb2), HOSTILE_PEER);
    }

    assert!(
        mempool.contains_orphan_transaction(&child_id),
        "a hostile peer must not evict another peer's parked orphan"
    );

    // A surviving parked child must still be promotable once its parent arrives.
    submit(&mut mempool, parent, HONEST_PEER)
        .expect("parent should be accepted")
        .assert_in_mempool();
    mempool.process_queue();
    assert!(
        mempool.contains_transaction(&child_id),
        "a surviving orphan must be promoted when its parent arrives"
    );
}

/// Eviction must not degenerate into coin flips when many peers hold one entry each.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quota_many_small_peers_cannot_evict_honest_entry() {
    let mut rng = make_seedable_rng(Seed::from_u64(5));
    let (mut mempool, funding_id, _height) = setup();

    let (_, child) = parent_and_child(&mut rng, funding_id, 1);
    let child_id = child.transaction().get_id();
    submit(&mut mempool, child, HONEST_PEER)
        .expect("child should be parked")
        .assert_in_orphan_pool();

    // 99 distinct peers each contribute one junk orphan, then flood fresh distinct
    // transactions round-robin. Each peer stays under its own quota, so the policy admits
    // them; the saturated pool must reject them instead of displacing any parked entry.
    let junk: Vec<_> = (0..99u32).map(|i| free_orphan_tx(i, 0xb3)).collect();
    for (i, tx) in junk.iter().enumerate() {
        let _ = submit(&mut mempool, tx.clone(), 10 + i as u64);
    }
    let flood: Vec<_> = (1000u32..1000 + 99 * 8).map(|i| free_orphan_tx(i, 0xb4)).collect();
    for (i, tx) in flood.iter().enumerate() {
        let _ = submit(&mut mempool, tx.clone(), 10 + (i % 99) as u64);
    }

    assert!(
        mempool.contains_orphan_transaction(&child_id),
        "many single-entry peers must not displace an honest peer's orphan"
    );
}

/// A busy honest peer (no attacker) must not crowd out a slow peer's parked orphan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quota_fair_share_under_legitimate_load() {
    let mut rng = make_seedable_rng(Seed::from_u64(7));
    let (mut mempool, funding_id, _height) = setup();

    let (_, child) = parent_and_child(&mut rng, funding_id, 1);
    let child_id = child.transaction().get_id();
    submit(&mut mempool, child, HONEST_PEER)
        .expect("child should be parked")
        .assert_in_orphan_pool();

    // A busy-but-honest peer streams ordinary orphans; nothing hostile.
    for i in 0..500u32 {
        let _ = submit(&mut mempool, free_orphan_tx(i, 0xa2), 4);
    }

    assert!(
        mempool.contains_orphan_transaction(&child_id),
        "honest traffic must not evict another peer's parked orphan"
    );
}

// --------------------------------------------------- 5. expiry vs. quota accounting

/// A peer whose parked orphans have all expired must not be locked out by stale occupancy:
/// the quota has to be evaluated after expired entries are reclaimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quota_ignores_expired_entries_when_admitting_new_ones() {
    let now = Arc::new(AtomicU64::new(1_000_000));
    let clock = TimeGetter::new(Arc::new(FixedClock(Arc::clone(&now))));
    let (mut mempool, _funding_id, _height) = setup_with_clock(clock);

    // Park the full inbound quota for one peer.
    for i in 0..crate::config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER as u32 {
        submit(&mut mempool, free_orphan_tx(i, 0xc1), HONEST_PEER)
            .expect("orphan should be parked")
            .assert_in_orphan_pool();
    }

    // Advance the clock past the expiry interval; everything parked above is now expired.
    now.store(
        1_000_000 + crate::config::DEFAULT_ORPHAN_TX_EXPIRY_INTERVAL.as_secs() + 1,
        Ordering::SeqCst,
    );

    // The same peer must be able to park a new orphan against fresh occupancy.
    submit(&mut mempool, free_orphan_tx(100, 0xc1), HONEST_PEER)
        .expect("expired entries must not count against the quota")
        .assert_in_orphan_pool();
}

// ------------------------------------------------------------------ 6. disconnect teardown

/// Orphans parked by a peer must leave with the peer's connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn teardown_removes_peer_orphans_on_disconnect() {
    let mut rng = make_seedable_rng(Seed::from_u64(6));
    let (mut mempool, funding_id, _height) = setup();

    let (_, child) = parent_and_child(&mut rng, funding_id, 0);
    let child_id = child.transaction().get_id();
    submit(&mut mempool, child, HONEST_PEER)
        .expect("child should be parked")
        .assert_in_orphan_pool();

    mempool.on_peer_disconnected(PeerId::from_u64(HONEST_PEER));

    assert!(
        !mempool.contains_orphan_transaction(&child_id),
        "a peer's orphans must be purged when it disconnects"
    );
}

// ------------------------------------------------------------------ 7. outbound peer tier

/// Outbound (node-selected) peers get a larger per-peer share of the orphan pool than
/// inbound peers; each tier still caps its own peers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbound_tier_gets_larger_per_peer_capacity() {
    // The outbound tier is only meaningful if it is strictly larger than the inbound one.
    assert!(
        crate::config::DEFAULT_OUTBOUND_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER
            > crate::config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER,
        "outbound per-peer capacity must exceed the inbound per-peer capacity"
    );

    let (mut mempool, _funding_id, _height) = setup();

    let submit_outbound = |mempool: &mut Pool,
                           tx: SignedTransaction,
                           peer_id: u64|
     -> Result<TxStatus, crate::error::Error> {
        let origin = RemoteTxOrigin::new(PeerId::from_u64(peer_id));
        let options = TxOptions::default_for(origin.into()).with_origin_peer_outbound(true);
        mempool.add_transaction_remote(tx, origin, options)
    };

    // An outbound peer can park up to the outbound per-peer capacity...
    for i in 0..crate::config::DEFAULT_OUTBOUND_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER as u32 {
        submit_outbound(&mut mempool, free_orphan_tx(i, 0xc1), 11)
            .unwrap_or_else(|e| panic!("outbound orphan {i} should park: {e:?}"))
            .assert_in_orphan_pool();
    }
    // ...but not beyond it.
    assert!(submit_outbound(&mut mempool, free_orphan_tx(999, 0xc1), 11).is_err());

    // The inbound cap is unchanged and applies independently.
    for i in 0..crate::config::DEFAULT_REMOTE_ORPHAN_POOL_CAPACITY_PER_PEER as u32 {
        submit(&mut mempool, free_orphan_tx(i, 0xc2), 12)
            .expect("inbound orphan should park")
            .assert_in_orphan_pool();
    }
    assert!(submit(&mut mempool, free_orphan_tx(999, 0xc2), 12).is_err());
}
