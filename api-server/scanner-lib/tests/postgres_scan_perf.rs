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
        Destination, PoolId, Transaction, UtxoOutPoint as UtxoOutPointT,
        config::create_unit_test_config, stakelock::StakePoolData,
    },
    primitives::{Amount, BlockDistance, BlockHeight, H256, Id, Idable, per_thousand::PerThousand},
};
use randomness::CryptoRng;
use crypto::{
    key::{KeyKind, PrivateKey},
    vrf::{VRFKeyKind, VRFPrivateKey},
};
use test_utils::random::make_seedable_rng;

/// (review fix) Exercises the postgres get_utxos override against real data:
/// batched results must match single fetches for every outpoint referenced by
/// the scanned blocks (inputs and PoS kernel inputs), a missing outpoint must
/// return None, and duplicate request entries must return identical values.
async fn assert_get_utxos_matches_single<S>(
    storage: &S,
    blocks: &[common::chain::Block],
    rng: &mut impl CryptoRng,
) where
    S: for<'tx> api_server_common::storage::storage_api::Transactional<'tx>,
{
    use api_server_common::storage::storage_api::ApiServerStorageRead;
    use randomness::RngExt as _;
    // transaction_ro comes from the Transactional trait implemented for the
    // storage; the reference-based call resolves through the ApiServerStorage
    // supertrait bounds on S.

    let mut outpoints = std::collections::BTreeSet::new();
    for block in blocks {
        for tx in block.transactions() {
            for input in tx.transaction().inputs() {
                if let common::chain::TxInput::Utxo(outpoint) = input {
                    outpoints.insert(outpoint.clone());
                }
            }
        }
        if let common::chain::block::ConsensusData::PoS(pos_data) = block.consensus_data() {
            for input in pos_data.kernel_inputs() {
                if let common::chain::TxInput::Utxo(outpoint) = input {
                    outpoints.insert(outpoint.clone());
                }
            }
        }
    }
    let missing = UtxoOutPointT::new(
        common::chain::OutPointSourceId::Transaction(Id::<Transaction>::random_using(rng)),
        rng.random::<u32>(),
    );

    let db_tx = storage.transaction_ro().await.unwrap();

    let requested: Vec<common::chain::UtxoOutPoint> =
        std::iter::once(missing.clone()).chain(outpoints.iter().cloned()).collect();
    let batched = db_tx.get_utxos(&requested).await.unwrap();
    assert_eq!(batched.len(), requested.len());
    assert!(batched[0].is_none(), "missing outpoint must resolve to None");

    for (position, outpoint) in requested.iter().enumerate().skip(1) {
        let single = db_tx.get_utxo(outpoint.clone()).await.unwrap().expect("must be present");
        let batched_utxo = batched[position].as_ref().expect("must be present");
        assert_eq!(
            batched_utxo,
            &single,
            "batched fetch disagrees with single fetch for {outpoint:?}"
        );
    }

    // Duplicate request entries return identical values.
    let first_known = requested[1].clone();
    let dup = db_tx
        .get_utxos(&[first_known.clone(), first_known.clone()])
        .await
        .unwrap();
    assert_eq!(dup[0], dup[1]);
    assert!(dup[0].is_some());
}

const BLOCKS: usize = 20;

/// (experimental) Recreate a fresh database for a test so parallel tests don't
/// clobber each other's schema.
async fn reset_db(db_name: &str) {
    // (review fix) identifiers cannot be bound as parameters; since this
    // helper interpolates into destructive DDL, restrict the name to a safe
    // charset before use.
    assert!(
        !db_name.is_empty()
            && db_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !db_name.starts_with(|c: char| c.is_ascii_digit()),
        "invalid database name: {db_name}"
    );
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

    let scanned: Vec<common::chain::Block> = (1..=BLOCKS)
        .map(|height| tf.block(*tf.index_at(height).block_id()))
        .collect();
    assert_get_utxos_matches_single(local_state.storage(), &scanned, &mut rng).await;

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

    let scanned: Vec<common::chain::Block> = (1..=BLOCKS)
        .map(|height| tf.block(*tf.index_at(height).block_id()))
        .collect();
    assert_get_utxos_matches_single(local_state.storage(), &scanned, &mut rng).await;
}
