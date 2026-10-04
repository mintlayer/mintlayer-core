# NV-2 execution plan: Experiment + upstream issue

Approved by user: benchmark branch → run → GitHub issue → update audit record.
Blocked by plan-mode permissions; execute when switched to normal mode.

## Steps

1. **Create** `chainstate/test-suite/benches/reorg_growth.rs` (source below) and add to `chainstate/test-suite/Cargo.toml` after the existing `[[bench]]`:
   ```toml
   [[bench]]
   name = "reorg_growth"
   harness = false
   ```
2. **Run**: `cargo bench --offline -p chainstate-test-suite --bench reorg_growth` (release profile; deps cached). Capture table.
3. **Branch + push**: `git checkout -b bench/pos-sidechain-reorg-growth`, commit both files, push to origin.
4. **Issue** on mintlayer/mintlayer-core: trace + refinements (reorg-before-consensus ordering = zero-marginal-cost garbage triggers; no trust pre-filter; losing branches persisted) + bench table + fix options (branch-state cache / configured connect-side cap / partial pre-checks).
5. **Update** `~/security-audit-skill/mintlayer-core/run-1/NEEDS-VALIDATION.md` NV-2 entry with refinements + links.

## Bench source (composed, signatures verified against framework.rs / pos_block_builder.rs / benches.rs)

Key facts used: `tf.chainstate` public (framework.rs:62); `make_pos_block_builder()` (framework.rs:105); builder `with_parent/with_stake_pool_id/with_stake_spending_key/with_vrf_key/build` (pos_block_builder.rs:155-291); `process_block` via `ChainstateInterface` (chainstate re-exported from test-framework's use: `use chainstate::{BlockSource, ChainstateError, chainstate_interface::ChainstateInterface}`); setup copied from `pos_reorg` bench (benches.rs:51-78).

```rust
// (license header: MIT, same as benches.rs)

use std::time::Instant;

use chainstate::{BlockSource, chainstate_interface::ChainstateInterface};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{Block, Destination, GenBlock, PoolId, config::create_unit_test_config, stakelock::StakePoolData},
    primitives::{Amount, BlockDistance, H256, Id, Idable, per_thousand::PerThousand},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use test_utils::random::make_seedable_rng;

const MAIN_CHAIN_MARGIN: usize = 10;
const WINDOW: usize = 5;

fn make_pos_chain(rng: &mut impl CryptoRng) -> (TestFramework, PoolId, PrivateKey, VRFPrivateKey) {
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);

    let genesis_pool_id = PoolId::new(H256::random_using(rng));
    let stake_pool_pledge = create_unit_test_config().min_stake_pool_pledge();
    let stake_pool_data = StakePoolData::new(
        stake_pool_pledge,
        Destination::PublicKey(staking_pk),
        vrf_pk,
        Destination::AnyoneCanSpend,
        PerThousand::new(1000).unwrap(),
        Amount::ZERO,
    );

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        rng,
        Amount::from_atoms(1000),
        genesis_pool_id,
        stake_pool_data,
    )
    .max_depth_for_reorg(BlockDistance::new(5000))
    .build();
    let target_block_time = chain_config.target_block_spacing();

    let mut tf = TestFramework::builder(rng).with_chain_config(chain_config).build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    (tf, genesis_pool_id, staking_sk, vrf_sk)
}

fn build_side_block(
    tf: &mut TestFramework,
    rng: &mut impl CryptoRng,
    parent: &Id<GenBlock>,
    pool_id: PoolId,
    staking_sk: &PrivateKey,
    vrf_sk: &VRFPrivateKey,
) -> Block {
    tf.make_pos_block_builder()
        .with_parent(*parent)
        .with_stake_pool_id(pool_id)
        .with_stake_spending_key(staking_sk.clone())
        .with_vrf_key(vrf_sk.clone())
        .build(rng)
}

/// Structurally valid PoS block signed by a random wrong key: passes
/// parent/size/checkpoint/reorg-depth checks, triggers the full in-memory
/// reorg, and only fails consensus validation afterwards.
fn build_garbage_block(
    tf: &mut TestFramework,
    rng: &mut impl CryptoRng,
    parent: &Id<GenBlock>,
    pool_id: PoolId,
) -> Block {
    let (wrong_sk, _) = PrivateKey::new_from_rng(rng, KeyKind::Secp256k1Schnorr);
    let (wrong_vrf_sk, _) = VRFPrivateKey::new_from_rng(rng, VRFKeyKind::Schnorrkel);
    tf.make_pos_block_builder()
        .with_parent(*parent)
        .with_stake_pool_id(pool_id)
        .with_stake_spending_key(wrong_sk)
        .with_vrf_key(wrong_vrf_sk)
        .build(rng)
}

fn report_row(label: &str, samples: &[f64]) {
    let n = samples.len();
    let mean: f64 = samples.iter().sum::<f64>() / n as f64;
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = sorted[n / 2];
    println!("{label:>28} | mean {mean:>10.3} ms | median {median:>10.3} ms");
}

fn run_case(n: usize, rng: &mut impl CryptoRng) {
    let (mut tf, pool_id, staking_sk, vrf_sk) = make_pos_chain(rng);

    let common_block_id = tf
        .create_chain_pos(rng, &tf.genesis().get_id().into(), 5, pool_id, &staking_sk, &vrf_sk)
        .unwrap();

    let started = Instant::now();
    tf.create_chain_pos(rng, &common_block_id, n + MAIN_CHAIN_MARGIN, pool_id, &staking_sk, &vrf_sk)
        .unwrap();
    println!(
        "N={n}: main chain of {} built in {:.2}s",
        n + MAIN_CHAIN_MARGIN,
        started.elapsed().as_secs_f64()
    );

    // Losing-branch side chain: submit blocks one at a time, timing process_block only.
    let mut prev = common_block_id;
    let mut window_samples: Vec<f64> = Vec::with_capacity(WINDOW);
    let quarter = (n / 4).max(WINDOW);
    let mut checkpoints: Vec<usize> = [1, quarter, quarter * 2, quarter * 3, n]
        .into_iter()
        .map(|x| x.max(1).min(n))
        .collect();
    checkpoints.sort();
    checkpoints.dedup();

    let total_start = Instant::now();
    for i in 1..=n {
        let block = build_side_block(&mut tf, rng, &prev, pool_id, &staking_sk, &vrf_sk);
        let block_id: Id<GenBlock> = block.get_id().into();

        let t = Instant::now();
        tf.chainstate.process_block(block, BlockSource::Local).unwrap();
        window_samples.push(t.elapsed().as_secs_f64() * 1000.0);

        if Some(&i) == checkpoints.first() {
            let label = format!("side arrival #{i} (branch len {})", i - 1);
            report_row(&label, &window_samples);
            window_samples.clear();
            checkpoints.remove(0);
        }
        prev = block_id;
    }
    println!(
        "N={n}: side chain of {n} accepted in {:.2}s",
        total_start.elapsed().as_secs_f64()
    );

    // Trigger phase: garbage blocks pointing at the side-chain tip. Each is
    // rejected, but only after paying the full in-memory reorg.
    let mut garbage_samples = Vec::with_capacity(WINDOW);
    for _ in 0..WINDOW {
        let garbage = build_garbage_block(&mut tf, rng, &prev, pool_id);
        let t = Instant::now();
        let res = tf.chainstate.process_block(garbage, BlockSource::Local);
        let elapsed = t.elapsed().as_secs_f64() * 1000.0;
        assert!(res.is_err(), "garbage block was unexpectedly accepted");
        garbage_samples.push(elapsed);
    }
    report_row(&format!("garbage @branch len {n}"), &garbage_samples);
    println!();
}

fn main() {
    let mut rng = make_seedable_rng(4242.into());
    println!("PoS side-chain growth cost (per-arrival process_block, in-memory store)\n");
    for n in [100usize, 200, 400] {
        run_case(n, &mut rng);
    }
}
```

## Notes
- Garbage blocks use wrong staking/VRF keys (structurally valid, consensus-invalid) — distinct keys give distinct ids, no seal grinding needed.
- Side chain length ≤ main chain length (margin 10) so it stays a losing branch; per-arrival reorg cost is paid regardless of trust (verified: no trust pre-filter, reorganize_in_memory at chainstateref/mod.rs:688 runs before validate_consensus at :703).
- If compile fails on imports (e.g. `Block`/`GenBlock` paths), check `common::chain` re-exports used by framework.rs imports.
