# WASM bindings changelog

All notable changes to WASM bindings will be documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- New functions:
  - `encode_witness_htlc_refund_single_sig`
  - `encode_partially_signed_transaction`
  - `decode_partially_signed_transaction_to_js`
  - `encode_destination`

### Changed
- `encode_witness_htlc_secret` was renamed to `encode_witness_htlc_spend`.
- `encode_witness_htlc_multisig` was renamed to `encode_witness_htlc_refund_multisig`.

## [1.2.0] - 2025-10-27

No changes

## [1.1.0] - 2025-08-21

### Added
- New functions:
  - `decode_signed_transaction_to_js`
  - `encode_input_for_change_token_authority`
  - `encode_input_for_change_token_metadata_uri`
  - `encode_input_for_freeze_order`
  - `encode_input_for_freeze_token`
  - `encode_input_for_lock_token_supply`
  - `encode_input_for_mint_tokens`
  - `encode_input_for_unfreeze_token`
  - `encode_input_for_unmint_tokens`
  - `encode_output_produce_block_from_stake`
  - `encode_signed_transaction_intent`
  - `extended_public_key_from_extended_private_key`
  - `get_delegation_id`
  - `get_order_id`
  - `get_pool_id`
  - `make_change_address_public_key`
  - `make_receiving_address_public_key`
  - `make_transaction_intent_message_to_sign`
  - `multisig_challenge_to_address`
  - `verify_transaction_intent`

### Changed
- Functions `encode_input_for_conclude_order`, `encode_input_for_fill_order`, `get_token_id`.

  These functions gained an additional parameter - `current_block_height`. Same as for some previously existing functions,
`current_block_height` must be the height of the block into which the corresponding transaction has been, or is supposed to be, included.
  It's needed in cases when the result of the function depends on whether a certain hard fork has already happened.

- Functions `encode_witness`, `encode_witness_htlc_multisig`, `encode_witness_htlc_secret`.

  These functions also gained additional parameters: `current_block_height` (same as above) and `additional_info`.

  `additional_info` is an object containing two sub-objects - `pool_info` and `order_info`, which are maps from pool id
  and order id respectively to the corresponding info object. For the exact structure of `additional_info` see the generated
  `wasm_wrappers.d.ts`.\
  In short: the caller has to provide certain information about pools and orders referenced by the transaction's inputs.
  If the transaction inputs don't mention pools or orders, `pool_info` and `order_info` can be empty.

- Some parameters were renamed, e.g. `private_key_bytes` is now called `private_key` and the parameter that was sometimes
  called `utxos` and sometimes `inputs` is now `input_utxos`. But the meaning of these parameters didn't change.

## [1.0.2] - 2025-01-19

No changes

## [1.0.1] - 2024-12-11

No changes

## [1.0.0] - 2024-11-15

First major release.
