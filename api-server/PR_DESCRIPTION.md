# Fix: api-blockchain-scanner-daemon does not recover from a node WebSocket disconnection

Branch: `fix/scanner-daemon-ws-reconnect`

## Summary

The scanner daemon created its node RPC client once and looped on it forever. When the node
closed the WebSocket connection (production incident on testnet, 2026-09-28: 23 hours of
`Scanner sync error: ... The background task closed Connection was closed: CloseReason 1000 ...
restart required` while the node itself was healthy), every subsequent call failed instantly on
the dead client and the explorer served a stale tip until the scanner container was manually
restarted. The restart proved the resume path is safe: the scanner reconnected, resumed from its
DB-stored tip and caught up ~711 blocks in under a minute with zero duplication.

The client creation now lives inside the supervision loop:

- A sync error classified as **connection-level** (node unreachable, connection closed, request
  timeout) drops the client, waits out an exponential backoff (1s doubling up to 60s, jittered by
  ±20%), re-creates the client and continues the loop with the same `BlockchainState` — i.e. it
  always resumes from the Postgres-stored tip; the existing reorg handling on resume is reused
  unchanged.
- Reconnection attempts are logged at WARN with the attempt number and elapsed outage time; the
  recovery is logged at INFO: `Scanner reconnected to the node after N attempt(s) (<elapsed>
  elapsed); resuming from height H`.
- The backoff resets after a successful reconnection or a successful sync.
- **Non-connection errors** (e.g. the node being behind the scanner right after a restart) do not
  trigger a reconnect; they keep the client and pause the sync for 1s so the loop cannot spin hot
  or flood the logs (today's error path can emit thousands of lines/second).
- Genuinely non-recoverable failures (invalid RPC config, storage version mismatch, storage init
  panics) still fail fast and loud, as before.
- A node that is simply down at startup no longer aborts the daemon; the initial connection is
  established through the same backoff loop.
- No DB schema or storage version changes; `sync_once` semantics unchanged (it is already
  resumable); no new external dependencies (jsonrpsee 0.26 has no `reopen()`/`on_disconnect`
  API to lean on, so the client is re-created instead).

On the `"; restart required"` advice: that text is produced by jsonrpsee's `RestartNeeded` error
display, not by our code (there was no such message in mintlayer-core to remove). With in-place
recovery it now only appears transiently inside WARN lines instead of describing the actual
remedy.

## Changes

1. **`rpc`**: `ClientErrorExt::is_connection_error()` — classifies jsonrpsee client errors into
   connection-level (transport, terminated background task, timeout, service disconnect) vs
   application-level (a definitive answer from the node).
2. **`node-comm`** (`wallet-node-client`): `NodeRpcError::is_connection_error()` built on the
   above, so consumers never string-match jsonrpsee messages. Unit-tested against the
   `RestartNeeded` ("background task closed") and `Transport` errors.
3. **`scanner-lib`**: `RemoteNode` gains a connection-error classification hook (default `false`,
   so the test mocks are unaffected) and `SyncError::RemoteNode` carries the classification; the
   incident-level message format is unchanged.
4. **`scanner-daemon`**: the supervision loop (`run`) as described above; the daemon crate gained
   a lib target so the stack test suite can drive the real loop. `ReconnectBackoff` is unit-tested
   (growth 1s→60s, ±20% jitter bounds, reset after success).
5. **Integration test** `api-server/stack-test-suite/tests/scanner_reconnect.rs` (gated behind
   `ML_CONTAINERIZED_TESTS` like the other Postgres tests): a real WebSocket RPC server serves the
   four `chainstate` methods the scanner uses (same names and wire format as the node) backed by a
   `TestFramework` chain; a proxy sits between the scanner and the server so the test can sever
   the established connections exactly like a node RPC listener shutdown and refuse new ones while
   the chain advances. Asserts: scanner indexes the pre-outage blocks, survives the outage window
   (multiple backoff attempts, no crash, no restart), then reconnects on its own and the DB tip
   converges with the advanced node tip, with the scanner task never having exited.

## Services left as-is (issue step 3)

- **api-server/web-server**: same one-shot client, shared between the mempool bridge and the REST
  endpoints. The mempool bridge already re-subscribes with backoff and stall detection, but it
  re-subscribes on the same dead `ws_client()`, so after a `RestartNeeded` the `tx_seen` stream
  (and RPC-backed REST calls) stay broken until restart. Fixing it properly means re-creating and
  swapping the client behind the axum state that many endpoints and the streaming bridge share —
  a structural change for a follow-up PR. The failure mode there is degraded responses (visible
  5xx / `lag` advisories), not a silently stalled indexer.
- **wallet-rpc-daemon / wallet-cli (hot wallets)**: `WalletController` is generic over
  `NodeInterface` (mocked in tests) and holds a live mempool subscription; its loop already
  retries with a fixed delay and re-subscribes on stream close (an in-code comment even admits
  "the wallet is unable to automatically reconnect to the node"), but both operations fail forever
  on a dead client. Automatic reconnection needs a client factory threaded through the controller
  plus subscription/rescan bookkeeping — invasive; should be its own issue. Note the loop does not
  spin hot, so there is no log flood; the wallet just needs a manual restart, as before.
- **node-gui**: shares the wallet controller design; same reasoning, and the user can restart it
  from the GUI.

The reusable pieces from this PR (`NodeRpcError::is_connection_error`,
`rpc::ClientErrorExt::is_connection_error`) are exactly what those follow-ups would build on.

## Manual soak (reproducing the incident)

1. Run a node (testnet) and the scanner against it; let it index some blocks.
2. While indexing, stop the node (`SIGTERM`/`SIGINT`), wait a few seconds, start it again on the
   same RPC address (or, to keep the node healthy like the real incident, just drop its
   connections with e.g. `ss -K dst 127.0.0.1 <node-rpc-port>`).
3. In the scanner logs expect, in order:
   - one `WARN ... Lost the connection to the node (attempt 1, ...)` line (the incident error,
     now actionable), then
   - a few `WARN ... Failed to connect to the node (attempt N, elapsed <t>) ... retrying in <d>`
     lines with growing `d` while the node is away, and
   - exactly one `INFO ... Scanner reconnected to the node after N attempt(s) ... resuming from
     height H`, followed by normal indexing logs.
4. Confirm: no `Scanner sync error` line repeats more than once per failure (no tight loop, no
   thousands of lines/second), no `restart required` remedy is needed, the process stays up, and
   the indexed tip (`GET /v2/chain/tip` on the web server, or the `ml.blocks` table) converges
   with the node tip. Leaving the node down for hours is safe: attempts continue at 60s intervals.

## Verification

- `cargo fmt --check` on all touched crates.
- `cargo clippy --all-targets` with the repo's `do_checks.sh` lint profile: clean (the two
  `infallible_try_from` errors in `crypto` are pre-existing on master with clippy 1.98 and are
  allowed by `do_checks.sh`).
- `cargo test -p rpc -p node-comm -p api-blockchain-scanner-lib -p api-blockchain-scanner-daemon`:
  all green (including the new classifier, backoff and sync regression tests).
- `cargo test -p api-server-stack-test-suite --test in_memory`: 111 passed (no regressions).
- `ML_CONTAINERIZED_TESTS=1 cargo test -p api-server-stack-test-suite --test scanner_reconnect`:
  passes; sample log excerpt from the run:

  ```
  WARN api_blockchain_scanner_daemon: Lost the connection to the node (attempt 1, elapsed 16.9µs):
      Unexpected remote node error: Response error: The background task closed connection closed;
      restart required; re-connecting in 996ms
  WARN api_blockchain_scanner_daemon: Failed to connect to the node (attempt 2, elapsed 997ms):
      Client creation error: i/o error: unexpected end of file; retrying in 1.71s
  WARN api_blockchain_scanner_daemon: Failed to connect to the node (attempt 3, elapsed 2.71s):
      Client creation error: i/o error: unexpected end of file; retrying in 3.69s
  INFO api_blockchain_scanner_daemon: Scanner reconnected to the node after 3 attempt(s)
      (6.4s elapsed); resuming from height 3
  ```
