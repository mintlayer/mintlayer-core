# API server changelog

All notable changes to the API server will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- New endpoint was added: `/v2/transaction/{id}/output/{idx}`.
- New endpoint was added: `/v2/token/{id}/transactions` will return all transactions related to a token

### Changed
- `/v2/token/ticker/{ticker}` will now return all tokens whose ticker has the specified `{ticker}`
  as a substring (previously only exact matches were returned).

- `CURRENT_STORAGE_VERSION` was increased, full resync is required.

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
