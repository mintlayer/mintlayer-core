# Changelog

All notable changes to this project will be documented in this file.\
Exceptions are the API server and WASM bindings, which have their own changelogs.

[API server changelog](api-server/CHANGELOG.md)

[WASM bindings changelog](wasm-wrappers/CHANGELOG.md)

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
  - Node RPC: new method added - `chainstate_tokens_info`, `chainstate_orders_info_by_currencies`.

  - Wallet RPC:
    - new methods added: `node_get_tokens_info`, `order_list_own`, `order_list_all_active`.

  - Wallet CLI:
    - the commands `order-create`, `order-fill`, `order-freeze`, `order-conclude` were added,
      mirroring their existing RPC counterparts;
    - other new commands added: `order-list-own`, `order-list-all-active`;

### Changed
  - Wallet RPC:
    - `wallet_info`: the structure of the returned field `extra_info` was changed.
    - `create_order`, `conclude_order`, `fill_order`, `freeze_order` were renamed to
      `order_create`, `order_conclude`, `order_fill`, `order_freeze`.

  - The format of `PartiallySignedTransaction was changed again.

  - Node RPC: the result of `chainstate_order_info` now also indicates whether the order is frozen.

### Fixed
  - p2p: when a peer sends a message that can't be decoded, it will now be discouraged (which is what
    is normally done for misbehaving peers) and the node won't try connecting to it again.\
    Also, the peer will be sent an appropriate `WillDisconnect` message prior to disconnection.

  - Wallet CLI and RPC: the commands `account-utxos` and `standalone-multisig-utxos` and their RPC
    counterparts now return correct decimal amounts for tokens with non-default number of decimals.

  - Node RPC: `chainstate_order_info` will no longer fail if one of the order's balances became zero.

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
    - Added a new `wallet-cli` command to undiscourage a previously discouraged peer - `node-undiscourage-peer-address`.

    - Added a new `wallet-cli` command to return the account's extended public key - `account-extended-public-key-as-hex`.

    - Added new `wallet-cli` command `config-broadcast`. When `config-broadcast no` is called, it prevents all
      commands that create transactions from automatically broadcasting them to the network.

    - `wallet-cli` gained a new option `--no-qr`, which disables QR code output for wallet commands.

    - Added support for Trezor hardware wallets (beta).

      Because of this, `wallet-cli` and `wallet-rpc-daemon` gained an additional parameter, `--hardware-wallet`,
      which must be used together with `--wallet-file` to indicate that the wallet file being opened corresponds to
      a hardware wallet.

  - Wallet RPC:
    - New methods: `account_extended_public_key`, `node_undiscourage_peer_address` (similar to the corresponding commands
      in `wallet-cli`) and `token_make_tx_to_send_with_intent`.

  - Node RPC: new methods - `chainstate_pool_decommission_destination`, `p2p_undiscourage`.

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

  - Wallet CLI commands:
    - `wallet-create` was split into 2 commands - `wallet-create` and `wallet-recover`. They both create a new wallet
      file and the difference is that `wallet-recover` rescans the blockchain upon creation and `wallet-create` doesn't.

    - `wallet-create`/`wallet-recover`/`wallet-open` now have a mandatory subcommand, which can be either `software` or
      `trezor`, which specifies the type of the wallet to operate on.

    - `staking-create-pool` now accepts two optional additional parameters - the staker address and the VRF public key.
      This allows to create a pool from a wallet other than the one that will be used for staking.

    - `transaction-list-by-address` and `transaction-list-pending` now print their output in paginated mode.

    - `address-show` now has the option `--include-change`, which makes it include the change addresses in the output.
      The command will now also print the coin balances of shown addresses.

    - `address-sweep-spendable` now has the option `--all`, which makes it sweep all addresses of the selected account.

  - Wallet RPC:
    - Most of the methods that create transactions, such as `address_send`, now accept an additional field in their
      `options` parameter - `broadcast_to_mempool`, which specifies whether the transaction should be sent to the mempool
      upon creation. The default is `true` (which is the old behavior).

    - Methods that create transactions now also return extra information in addition to the transaction id -
      the transaction itself (in the hex-encoded form), the info about fees paid by the transaction, whether it was
      broadcast to mempool or not.

    - `address_sweep_spendable` gained an additional boolean parameter - `all`, which may be used to force it to
      sweep all addresses from the given account.

    - `staking_create_pool` gained additional optional parameters - `staker_address` and `vrf_public_key`,
      same as the corresponding `wallet-cli` command.

    - `wallet_create` was split into `wallet_create` and `wallet_recover`, same as the corresponding `wallet-cli` command.

    - `wallet_create`, `wallet_recover` and `wallet_open` gained an additional optional parameter - `hardware_wallet`.
      This specifies the type of the hardware wallet to use (currently only trezor wallets are supported); if not set,
      the wallet is meant to be a software wallet.

      The results of `wallet_create`, `wallet_recover` and `wallet_open` now may contain additional data, to indicate
      a situation when creating/recovering/opening a hardware wallet could not be completed due to multiple potentially
      suitable devices being available.

      Also, `wallet_create` and `wallet_recover`'s result will no longer include the passphrase.

    - `wallet_info` returns an additional field `extra_info`, which specifies whether it's a software or hardware wallet;
      in the latter case the field will also contain additional information, such as the device name.

    - `address_show` gained an additional parameter - `include_change_addresses`, similar to the corresponding command
      in `wallet-cli`.

      Also, the result of the call now contains additional info - the purpose of each address ("Receive" or "Change")
      and its coins balance.

  - The format of `PartiallySignedTransaction was changed.

    Note that `PartiallySignedTransaction` is returned or accepted in the hex-encoded form by certain `wallet-cli`
    commands and their wallet RPC counterparts, such as `transaction-compose` or `account-sign-raw-transaction`.

### Fixed
  - Fixed issues in the wallet related to a transaction with an outdated nonce not being marked as conflicted.

  - `node-gui` no longer ignores the network type (i.e. "mainnet" ot "testnet") passed via the command line.

  - Fixed an issue where `node-gui` would appear stuck when opening a wallet that wasn't synced in a long time.

  - Fixed an issue in the wallet where a text summary for a token-issuing transaction would show its "freezable"
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
