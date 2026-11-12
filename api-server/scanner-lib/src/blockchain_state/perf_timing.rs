// (experimental) Stage-timing instrumentation for scanner (indexer) profiling.
//
// Enabled via ML_SCANNER_STAGE_TIMING=1. Accumulates wall-clock time spent in
// per-batch/per-block stages of scan_blocks into global atomic counters and
// logs a summary once per sync batch.
//
// Throwaway measurement code for the experimental IBD/indexer performance
// branch; must not be merged to master in this form.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

const STAGES: [&str; 7] = [
    "reorg_cleanup",
    "median_locked",
    "fee_calc",
    "tx_tables",
    "block_tables",
    "commit",
    "other",
];

static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var("ML_SCANNER_STAGE_TIMING")
            .is_ok_and(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
    })
}

#[derive(Clone, Copy)]
#[allow(dead_code)] // Other is only referenced via the STAGES name table
pub enum Stage {
    ReorgCleanup = 0,
    MedianLocked = 1,
    FeeCalc = 2,
    TxTables = 3,
    BlockTables = 4,
    Commit = 5,
    Other = 6,
}

static STAGE_NS: [AtomicU64; 7] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

static BATCH_BLOCKS: AtomicUsize = AtomicUsize::new(0);
static BATCH_TXS: AtomicUsize = AtomicUsize::new(0);
static CACHE_HITS: AtomicUsize = AtomicUsize::new(0);
static CACHE_MISSES: AtomicUsize = AtomicUsize::new(0);

pub struct TimingGuard {
    stage: usize,
    start: std::time::Instant,
    active: bool,
}

impl TimingGuard {
    pub fn stage(stage: Stage) -> Self {
        Self {
            stage: stage as usize,
            start: std::time::Instant::now(),
            active: enabled(),
        }
    }
}

impl Drop for TimingGuard {
    fn drop(&mut self) {
        if self.active {
            STAGE_NS[self.stage].fetch_add(
                u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
    }
}

pub fn count_blocks(blocks: usize) {
    if enabled() {
        BATCH_BLOCKS.fetch_add(blocks, Ordering::Relaxed);
    }
}

pub fn count_txs(txs: usize) {
    if enabled() {
        BATCH_TXS.fetch_add(txs, Ordering::Relaxed);
    }
}

pub fn count_cache_hit() {
    if enabled() {
        CACHE_HITS.fetch_add(1, Ordering::Relaxed);
    }
}

pub fn count_cache_miss() {
    if enabled() {
        CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Log and reset accumulated stage times; call at the end of scan_blocks.
pub fn log_batch_summary() {
    if !enabled() {
        return;
    }

    let blocks = BATCH_BLOCKS.swap(0, Ordering::Relaxed);
    let txs = BATCH_TXS.swap(0, Ordering::Relaxed);
    if blocks == 0 {
        return;
    }

    let stmts = api_server_common::storage::impls::postgres::take_postgres_statement_count();
    let hits = CACHE_HITS.swap(0, Ordering::Relaxed);
    let misses = CACHE_MISSES.swap(0, Ordering::Relaxed);
    let (stmt_cache_hits, stmt_cache_misses) =
        api_server_common::storage::impls::postgres::take_postgres_statement_cache_stats();

    let stage_lines: Vec<String> = STAGES
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let ns = STAGE_NS[i].swap(0, Ordering::Relaxed);
            let d = Duration::from_nanos(ns);
            format!(
                "{:>13}: {:>8.2} ms/block ({:>8.2} ms/tx)",
                name,
                d.as_millis() as f64 / blocks as f64,
                if txs > 0 {
                    d.as_millis() as f64 / txs as f64
                } else {
                    0.0
                },
            )
        })
        .collect();

    eprintln!(
        "(experimental scanner timing) batch: {} blocks, {} txs, {} sql statements \
         ({:.1} stmts/block, {:.1} stmts/tx), utxo cache: {} hits / {} misses, \
         stmt cache: {} hits / {} misses:\n{}",
        blocks,
        txs,
        stmts,
        stmts as f64 / blocks as f64,
        if txs > 0 {
            stmts as f64 / txs as f64
        } else {
            0.0
        },
        hits,
        misses,
        stmt_cache_hits,
        stmt_cache_misses,
        stage_lines.join("\n"),
    );
}
