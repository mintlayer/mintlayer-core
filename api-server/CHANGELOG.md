# API server changelog

All notable changes to the API server will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Pending transactions are now served through the regular REST endpoints: `GET /v2/transaction/{id}` falls back to the mempool of the connected node when the transaction is not confirmed yet, and a new `GET /v2/mempool/transactions` endpoint lists the pending transactions (paginated with `offset`/`items`, with an optional `order=dependency` parameter that lists transactions after the transactions they depend on).\
  The responses have the same shape as the confirmed ones, with empty `block_id`/`timestamp`/`confirmations` fields; the `fee` field is omitted and the spent utxos of the inputs of a pending transaction are not populated. The endpoints proxy the mempool of the connected node, so the data reflects the view of that node and disappears once the transactions are confirmed, evicted or reorganized away.
- New endpoint `/v2/stream` (Server-Sent Events) that streams `tx_seen`, `block` and `reorg` events in real time, with an optional `types` filter parameter.\
  The stream carries keepalive comments, an in-stream reconnection hint, and a `lag` advisory for clients that fall behind; there is no replay, so missed events must be recovered through the regular REST endpoints.
- New web server options: `--stream-events-broadcast-capacity`, `--stream-events-max-subscribers`, `--stream-events-poll-interval-secs`, `--stream-events-keepalive-interval-secs`.
- The scanner now emits block/reorg events into a new `ml.emitted_events` table (transactionally consistent with the indexed data) and notifies listeners on commit.\
  Transactions seen in the node's mempool are bridged into `tx_seen` events by the web server.

### Changed
- The api-server storage version was bumped from 25 to 26 (new `ml.emitted_events` table); the scanner re-initializes the database when it finds a different version, as before. Full resync is required.
- The stream event retention pruning no longer deletes events that the event pump has not consumed yet: the pump records its progress in the database and the pruning never overtakes it (with a hard limit of 100k retained events before the first progress record or during a pump outage, logged as an error when it kicks in).
- A terminated streaming background task (the event pump or the mempool bridge) now brings the web server process down instead of leaving the event stream silently dead while the REST endpoints keep working.
- The streaming CLI options are validated (`clap` range checks) instead of silently clamping invalid values, and an SSE connection above `--stream-events-max-subscribers` is rejected with `429 Too Many Requests`.
- A `lag` advisory (`skipped: 0`) is now broadcast when the node's mempool subscription is lost or an event cannot be decoded, so clients can detect gaps; a single undecodable event no longer stalls the whole stream.

### Fixed
- `/v2/token` and `/v2/token/ticker/{ticker}` no longer return the same id more than once.\
  Both tokens and NFTs are stored with a row per block height they changed at, and every one
  of those rows was being listed. Tokens that were updated, and NFTs that changed owner, now
  appear once each, so the composition of a page has changed.
- The same two endpoints no longer return more entries than the requested `items`.

## [1.4.0] - 2026-07-09

No changes

## [1.3.1] - 2026-06-03

No changes

## [1.3.0] - 2026-04-09

### Added
- New endpoint was added: `/v2/transaction/{id}/output/{idx}`.
- New endpoint was added: `/v2/token/{id}/transactions` will return all transactions related to a token.\
  Pagination works like the new absolute mode in `/v2/transaction`, using `offset` and `items`.

### Changed
- `/v2/token/ticker/{ticker}` will now return all tokens whose ticker has the specified `{ticker}`
  as a substring (previously only exact matches were returned).

- `CURRENT_STORAGE_VERSION` was increased, full resync is required.

## [1.2.1] - 2026-02-28

No changes

## [1.2.0] - 2025-10-27

No changes

## [1.1.0] - 2025-08-21

### Added
- New endpoint was added: `/v2/address/{address}/token-authority`

### Changed
- Transactions returned by `/v2/transaction` now have a fixed global order; it is defined by the order of blocks and the
  order of transactions in each particular block.

  Also, the endpoint gained an additional parameter - `offset_mode`, which alters the meaning of the `offset` parameter.\
  The possible values are:
  - `legacy` (default); this is the original behavior, where `offset` is relative to the end of the overall transaction list.\
    I.e. `/v2/transaction?offset=0&items=10` will return the 10 latest transactions.

  - `absolute`; here `offset` is just an index in the overall transaction list.\
    Similarly to the legacy mode, `items` specifies the number of transactions *before* the specified position in the global
    transaction list. I.e. `/v2/transaction?offset_mode=absolute&offset=0&items=10` will return an empty list and
    `/v2/transaction?offset_mode=absolute&offset=1000&items=10` will return transactions with indices in the range [990, 999].

- `/v2/address/{address}` now also returns token balances for the address.

- In endpoints that return transaction info (such as `transaction/{id}`), the returned info about a spent HTLC UTXO now
  includes the HTLC secret.

- `/v2/pool` and `/v2/pool/{id}` now also return the total delegations balance.

- `/v2/token/{id}` now also returns the token's next nonce.

- Optimized database queries for the retrieval of the latest delegation states.

- `CURRENT_STORAGE_VERSION` was increased, full resync is required.

### Fixed
- Fixed the issue of `Burn` outputs being incorrectly reported as `LockThenTransfer`.

- Fixed the issue of the `MintTokens`'s `amount` being calculated using coin's decimals instead of the token's.

### Removed
- In endpoints that return transaction info (such as `transaction/{id}`), the returned info about a `FillOrder` input
  no longer includes `destination`.

## [1.0.2] - 2025-01-19

### Added
- New endpoints were added:
  - `/v2/order`
  - `/v2/order/{id}`
  - `/v2/order/pair/{asset1}_{asset2}`

### Changed
- The `/v2/nft/{id}` endpoint now also returns the owner of the NFT.
- The `/v2/order/{id}` endpoint now also returns the current nonce of the order.
- `CURRENT_STORAGE_VERSION` was increased, full resync is required.

### Fixed
- Fixed a crash in the `/v2/transaction/{id}` endpoint due to token info missing in the db after an order fill transaction
  has been processed.

## [1.0.1] - 2024-12-11

No changes

## [1.0.0] - 2024-11-15

First major release.
