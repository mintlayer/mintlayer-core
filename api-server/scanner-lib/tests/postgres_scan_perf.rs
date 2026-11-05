// (experimental) End-to-end validation of the scanner stage/statement timing
// instrumentation against a real postgres instance.
//
// Requires a running postgres with trust auth, e.g.:
//   docker run -d --name ml-pg-scan-perf -e POSTGRES_HOST_AUTH_METHOD=trust \
//     -e POSTGRES_DB=postgres -p 15432:5432 postgres:15
//
// Run with:
//   ML_SCANNER_STAGE_TIMING=1 ML_PG_SCAN_PERF=1 \
//     cargo test -p api-blockchain-scanner-lib --test postgres_scan_perf -- --ignored --nocapture
//
// Throwaway measurement code for the experimental IBD/indexer performance branch.

use std::sync::Arc;

use api_blockchain_scanner_lib::blockchain_state::BlockchainState;
use api_blockchain_scanner_lib::sync::local_state::LocalBlockchainState;
use api_server_common::storage::{
    impls::postgres::TransactionalApiServerPostgresStorage,
    storage_api::{ApiServerStorageWrite, ApiServerTransactionRw, Transactional},
};
use chainstate_test_framework::TestFramework;
use common::{
    chain::{
        Destination, PoolId, config::create_unit_test_config, stakelock::StakePoolData,
    },
    primitives::{Amount, BlockDistance, BlockHeight, H256, Idable, per_thousand::PerThousand},
};
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use test_utils::random::make_seedable_rng;

const BLOCKS: usize = 20;

/// (experimental) Recreate a fresh database for a test so parallel tests don't
/// clobber each other's schema.
async fn reset_db(db_name: &str) {
    let bootstrap = "host=127.0.0.1 port=15432 user=postgres dbname=postgres";
    let (client, conn) = tokio_postgres::connect(bootstrap, tokio_postgres::NoTls)
        .await
        .expect("connect to postgres");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    client
        .execute(
            &format!("DROP DATABASE IF EXISTS {db_name} WITH (FORCE)"),
            &[],
        )
        .await
        .expect("drop db");
    client
        .execute(&format!("CREATE DATABASE {db_name}"), &[])
        .await
        .expect("create db");
}

#[tokio::test]
#[ignore = "requires a running postgres; see module docs"]
async fn postgres_scan_perf_summary() {
    if std::env::var("ML_PG_SCAN_PERF").is_err() {
        eprintln!("Set ML_PG_SCAN_PERF=1 to run against postgres on 127.0.0.1:15432");
        return;
    }

    let mut rng = make_seedable_rng(4444.into());
    let (staking_sk, staking_pk) = PrivateKey::new_from_rng(&mut rng, KeyKind::Secp256k1Schnorr);
    let (vrf_sk, vrf_pk) = VRFPrivateKey::new_from_rng(&mut rng, VRFKeyKind::Schnorrkel);

    let genesis_pool_id = PoolId::new(H256::random_using(&mut rng));
    let stake_pool_pledge = create_unit_test_config().min_stake_pool_pledge();
    let stake_pool_data = StakePoolData::new(
        stake_pool_pledge,
        Destination::PublicKey(staking_pk),
        vrf_pk,
        Destination::AnyoneCanSpend,
        PerThousand::new(1000).unwrap(),
        Amount::ZERO,
    );
    let mint_amount = Amount::from_atoms(1000);

    let chain_config = chainstate_test_framework::create_chain_config_with_staking_pool(
        &mut rng,
        mint_amount,
        genesis_pool_id,
        stake_pool_data,
    )
    .max_depth_for_reorg(BlockDistance::new(5000))
    .build();
    let target_block_time = chain_config.target_block_spacing();

    let mut tf = TestFramework::builder(&mut rng)
        .with_chain_config(chain_config.clone())
        .build();
    tf.progress_time_seconds_since_epoch(target_block_time.as_secs());

    tf.create_chain_pos(
        &mut rng,
        &tf.genesis().get_id().into(),
        BLOCKS,
        genesis_pool_id,
        &staking_sk,
        &vrf_sk,
    )
    .unwrap();

    let chain_config = Arc::new(chain_config);
    reset_db("ml_scan_perf_pos").await;
    let mut storage = TransactionalApiServerPostgresStorage::new(
        "127.0.0.1",
        15432,
        "postgres",
        None,
        Some("ml_scan_perf_pos"),
        4,
        Arc::clone(&chain_config),
    )
    .await
    .unwrap();

    {
        let mut db_tx = storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();
    }

    let mut local_state = BlockchainState::new(Arc::clone(&chain_config), storage);
    local_state
        .scan_genesis(chain_config.genesis_block().as_ref())
        .await
        .unwrap();

    // All blocks above genesis, scanned in a single batch, like the sync loop
    // does with MAX_FETCH_BLOCK_COUNT=100.
    let mut blocks = Vec::with_capacity(BLOCKS);
    for height in 1..=BLOCKS {
        blocks.push(tf.block(*tf.index_at(height).block_id()));
    }

    local_state
        .scan_blocks(BlockHeight::zero(), blocks)
        .await
        .unwrap();

    // The (experimental scanner timing) summary, including the postgres
    // statement count, is printed by log_batch_summary inside scan_blocks.
}

/// (experimental) Same as above but with one transfer transaction per block
/// (via TestFramework::create_chain), so the per-tx statement counts (fee
/// calculation, input UTXO fetches) are exercised.
#[tokio::test]
#[ignore = "requires a running postgres; see module docs"]
async fn postgres_scan_perf_summary_with_txs() {
    if std::env::var("ML_PG_SCAN_PERF").is_err() {
        eprintln!("Set ML_PG_SCAN_PERF=1 to run against postgres on 127.0.0.1:15432");
        return;
    }

    let mut rng = make_seedable_rng(5555.into());

    // Default unit-test (regtest) config so PoW-style blocks with transfer
    // transactions are valid on this chain.
    let mut tf = TestFramework::builder(&mut rng).build();
    let chain_config = tf.chain_config().clone();

    tf.create_chain(&tf.genesis().get_id().into(), BLOCKS, &mut rng)
        .unwrap();

    let chain_config = Arc::new(chain_config);
    reset_db("ml_scan_perf_tx").await;
    let mut storage = TransactionalApiServerPostgresStorage::new(
        "127.0.0.1",
        15432,
        "postgres",
        None,
        Some("ml_scan_perf_tx"),
        4,
        Arc::clone(&chain_config),
    )
    .await
    .unwrap();

    {
        let mut db_tx = storage.transaction_rw().await.unwrap();
        db_tx.reinitialize_storage(&chain_config).await.unwrap();
        db_tx.commit().await.unwrap();
    }

    let mut local_state = BlockchainState::new(Arc::clone(&chain_config), storage);
    local_state
        .scan_genesis(chain_config.genesis_block().as_ref())
        .await
        .unwrap();

    let mut blocks = Vec::with_capacity(BLOCKS);
    for height in 1..=BLOCKS {
        blocks.push(tf.block(*tf.index_at(height).block_id()));
    }

    local_state
        .scan_blocks(BlockHeight::zero(), blocks)
        .await
        .unwrap();
}
