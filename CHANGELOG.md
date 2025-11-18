# Changelog

All notable changes to this project will be documented in this file.\
Exceptions are the API server and WASM bindings, which have their own changelogs.

[API server changelog](api-server/CHANGELOG.md)

[WASM bindings changelog](wasm-wrappers/CHANGELOG.md)

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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

### Added

  - Wallet:
    - Added a command to undiscourage a previously discouraged peer - `node-undiscourage-peer-address` in
      `wallet-cli`, `node_undiscourage_peer_address` in the wallet rpc.

    - Added a command to return the account's extended public key - `account-extended-public-key-as-hex` in
      `wallet-cli`, `account_extended_public_key` in the wallet rpc.

    - `staking-create-pool` now accepts two optional additional parameters - the staker address and the VRF public key.
      This allows to create a pool from a wallet other than the one that will be used for staking.

    - Added new option `--no-qr` to `wallet-cli`, which disables QR code output for wallet commands.

    - `wallet-cli` commands `transaction-list-by-address` and `transaction-list-pending` now print their output
      in the paginated mode.

    - `wallet-cli` command `address-show` now has the option `--include-change`, which makes it include the change
      addresses in the output.

    - `wallet-cli` command `address-sweep-spendable` now has the option `--all`, which makes it sweep all addresses
      of the selected account.

    - Added new `wallet-cli` command `config-broadcast`. When `config-broadcast no` is called, it prevents all
      commands that create transactions from automatically broadcasting them to the network.

    - Added support for Trezor hardware wallets (beta).

  - `node-gui` and `node-daemon` now can store info-level logs to the data directory, regardless of what is
    printed to the console. This is controlled by the `--log-to-file` option, which is enabled by default
    for `node-gui`.

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

### Fixed

  - Fixed issues in the wallet related to a transaction with an outdated nonce not being marked as conflicted.

  - `node-gui` no longer ignores the network type (i.e. "mainnet" ot "testnet") passed via the command line.

  - Fixed an issue where `node-gui` would appear stuck when opening a wallet that wasn't synced in a long time.

  - Fixed an issue in the wallet where a text summary for a token-issuing transaction would show its "is freezable"
    status incorrectly.

  - Fixed issues with transaction fee calculation in the wallet.

  - Fixes related to standalone private keys in the wallet:
    - Fixed encryption of standalone private keys when a new password is set or the existing one is changed.
    - Fixed watching/scanning for relevant public key destinations belonging to standalone private keys
      (only public key hash destinations used to work before).
    - Fixed wallet balance to show spendable UTXOs belonging to standalone private keys.

  - Various minor visual fixes in `node-gui`.

  - `wallet-cli` help output was prettified.

## [1.0.2] - 2025-01-19

No changes except for the API server, see the corresponding `CHANGELOG.md`.

## [1.0.1] - 2024-12-11

### Fixed

- Fix erroneous peer discouragement after mempool reorg.

## [1.0.0] - 2024-11-15

First major release.
