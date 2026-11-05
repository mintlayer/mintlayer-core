// (experimental) Stage-timing instrumentation for IBD profiling.
//
// Enabled via ML_IBD_STAGE_TIMING=1. Accumulates wall-clock time spent in
// per-block stages (check, persist, seal-index, connect, commit, ro txs) into
// global atomic counters and logs a summary every N processed blocks.
//
// This is throwaway measurement code for the experimental IBD/indexer
// performance branch; it must not be merged to master in this form.
//
// The chainstate write path is single-threaded, so plain atomics are enough;
// the instrumentation adds one atomic add per stage per block.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

const STAGES: [&str; 7] = [
    "ro_tx",
    "check_block",
    "persist",
    "seal_index",
    "connect",
    "min_height",
    "commit",
];

static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::env::var("ML_IBD_STAGE_TIMING").is_ok_and(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
    })
}

pub(crate) struct TimingGuard {
    stage: usize,
    start: std::time::Instant,
    active: bool,
}

impl TimingGuard {
    pub(crate) fn stage(stage: Stage) -> Self {
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

#[derive(Clone, Copy)]
pub(crate) enum Stage {
    RoTx = 0,
    CheckBlock = 1,
    Persist = 2,
    SealIndex = 3,
    Connect = 4,
    MinHeight = 5,
    Commit = 6,
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

static WINDOW_NS: AtomicU64 = AtomicU64::new(0);
static WINDOW_BLOCKS: AtomicUsize = AtomicUsize::new(0);
static TOTAL_BLOCKS: AtomicUsize = AtomicUsize::new(0);

const SUMMARY_EVERY_BLOCKS: usize = 100;

/// Called by the attempt_to_process_block wrapper on every exit (success or
/// failure) so the wall-clock window and block count stay in sync.
pub(crate) fn on_block_processed() {
    if !enabled() {
        return;
    }

    TOTAL_BLOCKS.fetch_add(1, Ordering::Relaxed);
    let window_blocks = WINDOW_BLOCKS.fetch_add(1, Ordering::Relaxed) + 1;

    if window_blocks >= SUMMARY_EVERY_BLOCKS {
        WINDOW_BLOCKS.store(0, Ordering::Relaxed);
        let window_ns = WINDOW_NS.swap(0, Ordering::Relaxed);
        log_summary(window_blocks, Duration::from_nanos(window_ns));
    }
}

/// Marks the start of a new wall-clock measurement window; call at the top of
/// the per-block processing function.
pub(crate) struct WindowGuard {
    start: std::time::Instant,
    active: bool,
}

impl WindowGuard {
    pub(crate) fn start() -> Self {
        Self {
            start: std::time::Instant::now(),
            active: enabled(),
        }
    }
}

impl Drop for WindowGuard {
    fn drop(&mut self) {
        if self.active {
            WINDOW_NS.fetch_add(
                u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
    }
}

fn log_summary(window_blocks: usize, window: Duration) {
    let mut accounted_ns = 0u64;
    let stage_lines: Vec<String> = STAGES
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let ns = STAGE_NS[i].swap(0, Ordering::Relaxed);
            accounted_ns += ns;
            let d = Duration::from_nanos(ns);
            let per_block_ms = d.as_nanos() as f64 / window_blocks as f64 / 1e6;
            format!(
                "{:>11}: {:>9.2} ms/block ({:>6.1}% of wall)",
                name,
                per_block_ms,
                if window.as_nanos() > 0 {
                    100.0 * ns as f64 / window.as_nanos() as f64
                } else {
                    0.0
                }
            )
        })
        .collect();

    let unaccounted = window.as_nanos() as f64 - accounted_ns as f64;
    let unaccounted_pct = if window.as_nanos() > 0 {
        100.0 * unaccounted / window.as_nanos() as f64
    } else {
        0.0
    };

    eprintln!(
        "(experimental stage timing) blocks: {} (total {}), wall {:.2} ms/block \
         ({:.1} blocks/s), unaccounted {:.1}% (network wait, events, logging):\n{}",
        window_blocks,
        TOTAL_BLOCKS.load(Ordering::Relaxed),
        window.as_nanos() as f64 / window_blocks as f64 / 1e6,
        window_blocks as f64 / window.as_secs_f64(),
        unaccounted_pct,
        stage_lines.join("\n"),
    );
}
