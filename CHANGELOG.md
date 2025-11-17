# Changelog

All notable changes to this project will be documented in this file.\
Exceptions are the API server and WASM bindings, which have their own changelogs.

[API server changelog](api-server/CHANGELOG.md)

[WASM bindings changelog](wasm-wrappers/CHANGELOG.md)

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

TODO

## [1.2.0] - 2025-10-27

### Changed

  - **A Mainnet fork is scheduled at height 517700** with the same consensus changes that previously
    happened on Testnet, namely:

    - Orders V1.
    - Change in the token id generation.
    - Transaction input commitments V1.
    - Prohibit updating staker's destination in `ProduceBlockFromStake` outputs.

    See the changelog for v1.1.0 below for extra details.

## [1.1.0] - 2025-08-21

### Changed

  - **A Testnet fork is scheduled at height 566060** with the following consensus changes:

    - Orders V1. The previous (V0) order inputs will no longer be supported, and the new (V1) ones will have
      to be used instead.\
      The main difference is that the new order commands don't use nonces. Also, an additional order-related input
      will be available - `FreezeOrder`.

    - Change in the token id generation.

      Previously, when a new token was being issued, its token id would be generated from the first input
      of the issuing transaction (which can be UTXO-based or account-based).\
      Now the token id will always be generated from the first UTXO input of the issuing transaction.

    - Transaction input commitments V1.

      Transaction signatures will now commit to additional information about the transaction (i.e. the information
      will become a part of what is being signed), namely:

      - In transactions that decommission a pool the signatures will commit to the current staker balance.
      - In transactions that fill or conclude an order the signatures will commit to the order balances.

    - Updating staker's destination in `ProduceBlockFromStake` outputs will no longer be possible.

  - `ChainstateStorageVersion` was increased, full node resync is required.

TODO: document changes not related to consensus

## [1.0.2] - 2025-01-19

No changes except for the API server, see the corresponding `CHANGELOG.md`.

## [1.0.1] - 2024-12-11

### Fixed

- Fix erroneous peer discouragement after mempool reorg.

## [1.0.0] - 2024-11-15

First major release.
