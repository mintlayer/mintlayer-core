### Function: `encode_outpoint_source_id`

A utxo can either come from a transaction or a block reward.
Given a source id, whether from a block reward or transaction, this function
takes a generic id with it, and returns serialized binary data of the id
with the given source id.

### Function: `make_private_key`

Generates a new, random private key from entropy

### Function: `make_default_account_privkey`

Create the default account's extended private key for a given mnemonic
derivation path: 44'/mintlayer_coin_type'/0'

### Function: `make_receiving_address`

From an extended private key create a receiving private key for a given key index
derivation path: current_derivation_path/0/key_index

### Function: `make_change_address`

From an extended private key create a change private key for a given key index
derivation path: current_derivation_path/1/key_index

### Function: `pubkey_to_pubkeyhash_address`

Given a public key (as bytes) and a network type (mainnet, testnet, etc),
return the address public key hash from that public key as an address

### Function: `public_key_from_private_key`

Given a private key, as bytes, return the bytes of the corresponding public key

### Function: `extended_public_key_from_extended_private_key`

Return the extended public key from an extended private key

### Function: `make_receiving_address_public_key`

From an extended public key create a receiving public key for a given key index
derivation path: current_derivation_path/0/key_index

### Function: `make_change_address_public_key`

From an extended public key create a change public key for a given key index
derivation path: current_derivation_path/1/key_index

### Function: `sign_message_for_spending`

Given a message and a private key, sign the message with the given private key
This kind of signature is to be used when signing spend requests, such as transaction
input witness.

### Function: `verify_signature_for_spending`

Given a digital signature, a public key and a message. Verify that
the signature is produced by signing the message with the private key
that derived the given public key.
Note that this function is used for verifying messages related to spending,
such as transaction input witness.

### Function: `sign_challenge`

Given a message and a private key, create and sign a challenge with the given private key.
This kind of signature is to be used when signing challenges.

### Function: `verify_challenge`

Given a signed challenge, an address and a message, verify that
the signature is produced by signing the message with the private key
that derived the given public key.
This function is used for verifying messages-related challenges.

Note: for signatures that were created by `sign_challenge`, the provided address must be
a 'pubkeyhash' address.

Note: currently this function never returns `false` - it either returns `true` or fails with an error.

### Function: `make_transaction_intent_message_to_sign`

Return the message that has to be signed to produce a signed transaction intent.

### Function: `encode_signed_transaction_intent`

Return a `SignedTransactionIntent` object as bytes given the message and encoded signatures.

Note: to produce a valid signed intent one is expected to sign the corresponding message by private keys
corresponding to each input of the transaction.

Parameters:
`signed_message` - this must have been produced by `make_transaction_intent_message_to_sign`.
`signatures` - this should be an array of Uint8Array, each of them representing an individual signature
of `signed_message` produced by `sign_challenge` using the private key for the corresponding input destination
of the transaction. The number of signatures must be equal to the number of inputs in the transaction.

### Function: `verify_transaction_intent`

Verify a signed transaction intent.

Parameters:
`expected_signed_message` - the message that is supposed to be signed; this must have been
produced by `make_transaction_intent_message_to_sign`.
`encoded_signed_intent` - the signed transaction intent produced by `encode_signed_transaction_intent`.
`input_destinations` - an array of addresses (strings), corresponding to the transaction's input destinations
(note that this function treats "pub key" and "pub key hash" addresses interchangeably, so it's ok to pass
one instead of the other).
`network` - the network being used (needed to decode the addresses).

### Function: `staking_pool_spend_maturity_block_count`

Given the current block height and a network type (mainnet, testnet, etc),
this function returns the number of blocks, after which a pool that decommissioned,
will have its funds unlocked and available for spending.
The current block height information is used in case a network upgrade changed the value.

### Function: `encode_lock_for_block_count`

Given a number of blocks, this function returns the output timelock
which is used in locked outputs to lock an output for a given number of blocks
since that output's transaction is included the blockchain

### Function: `encode_lock_for_seconds`

Given a number of clock seconds, this function returns the output timelock
which is used in locked outputs to lock an output for a given number of seconds
since that output's transaction is included in the blockchain

### Function: `encode_lock_until_time`

Given a timestamp represented by as unix timestamp, i.e., number of seconds since unix epoch,
this function returns the output timelock which is used in locked outputs to lock an output
until the given timestamp

### Function: `encode_lock_until_height`

Given a block height, this function returns the output timelock which is used in
locked outputs to lock an output until that block height is reached.

### Function: `encode_stake_pool_data`

This function returns the staking pool data needed to create a staking pool in an output as bytes,
given its parameters and the network type (testnet, mainnet, etc).

### Function: `fungible_token_issuance_fee`

Returns the fee that needs to be paid by a transaction for issuing a new fungible token

### Function: `nft_issuance_fee`

Given the current block height and a network type (mainnet, testnet, etc),
this will return the fee that needs to be paid by a transaction for issuing a new NFT
The current block height information is used in case a network upgrade changed the value.

### Function: `token_supply_change_fee`

Given the current block height and a network type (mainnet, testnet, etc),
this will return the fee that needs to be paid by a transaction for changing the total supply of a token
by either minting or unminting tokens
The current block height information is used in case a network upgrade changed the value.

### Function: `token_freeze_fee`

Given the current block height and a network type (mainnet, testnet, etc),
this will return the fee that needs to be paid by a transaction for freezing/unfreezing a token
The current block height information is used in case a network upgrade changed the value.

### Function: `token_change_authority_fee`

Given the current block height and a network type (mainnet, testnet, etc),
this will return the fee that needs to be paid by a transaction for changing the authority of a token
The current block height information is used in case a network upgrade changed the value.

### Function: `get_token_id`

Returns the Fungible/NFT Token ID for the given inputs of a transaction

### Function: `get_order_id`

Returns the Order ID for the given inputs of a transaction

### Function: `get_delegation_id`

Returns the Delegation ID for the given inputs of a transaction

### Function: `get_pool_id`

Returns the Pool ID for the given inputs of a transaction

### Function: `data_deposit_fee`

Returns the fee that needs to be paid by a transaction for issuing a data deposit

### Function: `extract_htlc_secret`

Given a signed transaction and input outpoint that spends an htlc utxo, extract a secret that is
encoded in the corresponding input signature

### Function: `estimate_transaction_size`

Given the inputs, along each input's destination that can spend that input
(e.g. If we are spending a UTXO in input number 1 and it is owned by address mtc1xxxx, then it is mtc1xxxx in element number 2 in the vector/list.
for Account inputs that spend from a delegation it is the owning address of that delegation,
and in the case of AccountCommand inputs which change a token it is the token's authority destination)
and the outputs, estimate the transaction size.
ScriptHash and ClassicMultisig destinations are not supported.

### Function: `encode_transaction`

Given inputs as bytes, outputs as bytes, and flags settings, this function returns
the transaction that contains them all, as bytes.

### Function: `decode_signed_transaction_to_json_str`

Decodes a signed transaction from its binary encoding into a Json string.

### Function: `encode_witness_no_signature`

Encode an input witness of the variant that contains no signature.

### Function: `encode_witness`

Sign the specified input of the transaction and encode the signature as InputWitness.

`input_utxos` must be formed as follows: for each transaction input, emit byte 0 if it's a non-UTXO input,
otherwise emit 1 followed by the corresponding transaction output encoded via the appropriate "encode_output_"
function.

`additional_info` must contain the following:
1) for each `ProduceBlockFromStake` input of the transaction, the pool info for the pool referenced by that input;
2) for each `FillOrder` and `ConcludeOrder` input of the transaction, the order info for the order referenced by
   that input.
Note:
- It doesn't matter which input witness is currently being encoded. E.g. even if you are encoding a witness
  for some UTXO-based input but another input of the same transaction is `FillOrder`, you have to include the order
  info when encoding the witness for the UTXO-based input too.
- After a certain hard fork, the produced signature will "commit" to the provided additional info, i.e. the info
  will become a part of what is being signed. So, passing invalid additional info will result in an invalid signature
  (with one small caveat: for `FillOrder` we only commit to order's initial balances and not the current ones;
  so if you only have `FillOrder` inputs, you can technically pass bogus values for the current balances and
  the resulting signature will still be valid; though it's better to avoid doing this).

### Function: `encode_witness_htlc_secret`

Given a private key, inputs and an input number to sign, and the destination that owns that output (through the utxo),
and a network type (mainnet, testnet, etc), and an htlc secret this function returns a witness to be used in a signed transaction, as bytes.

`input_utxos` and `additional_info` have the same format and requirements as in `encode_witness`.

### Function: `encode_multisig_challenge`

Given an arbitrary number of public keys as bytes, number of minimum required signatures, and a network type, this function returns
the multisig challenge, as bytes.

### Function: `multisig_challenge_to_address`

Produce a multisig address given a multisig challenge.

### Function: `encode_witness_htlc_multisig`

Given a private key, inputs and an input number to sign, and multisig challenge,
and a network type (mainnet, testnet, etc), this function returns a witness to be used in a signed transaction, as bytes.

`key_index` parameter is an index of the public key in the challenge corresponding to the specified private key.
`input_witness` parameter can be either empty or a result of previous calls to this function.

`input_utxos` and `additional_info` have the same format and requirements as in `encode_witness`.

### Function: `encode_signed_transaction`

Given an unsigned transaction and signatures, this function returns a SignedTransaction object as bytes.

### Function: `get_transaction_id`

Given a `Transaction` encoded in bytes (not a signed transaction, but a signed transaction is tolerated by ignoring the extra bytes, by choice)
this function will return the transaction id.

The second parameter, the boolean, is provided as means of asserting that the given bytes exactly match a `Transaction` object.
When set to `true`, the bytes provided must exactly match a single `Transaction` object.
When set to `false`, extra bytes can exist, but will be ignored.
This is useful when the provided bytes are of a `SignedTransaction` instead of a `Transaction`,
since the signatures are appended at the end of the `Transaction` object as a vector to create a `SignedTransaction`.
It is recommended to use a strict `Transaction` size and set the second parameter to `true`.

### Function: `effective_pool_balance`

Calculate the "effective balance" of a pool, given the total pool balance and pledge by the pool owner/staker.
The effective balance is how the influence of a pool is calculated due to its balance.

### Function: `encode_input_for_utxo`

Given an output source id as bytes, and an output index, together representing a utxo,
this function returns the input that puts them together, as bytes.

### Function: `encode_input_for_withdraw_from_delegation`

Given a delegation id, an amount and a network type (mainnet, testnet, etc), this function
creates an input that withdraws from a delegation.
A nonce is needed because this spends from an account. The nonce must be in sequence for everything in that account.

### Function: `encode_input_for_mint_tokens`

Given a token_id, an amount of tokens to mint and nonce return an encoded mint tokens input

### Function: `encode_input_for_unmint_tokens`

Given a token_id and nonce return an encoded unmint tokens input

### Function: `encode_input_for_lock_token_supply`

Given a token_id and nonce return an encoded lock_token_supply input

### Function: `encode_input_for_freeze_token`

Given a token_id, is token unfreezable and nonce return an encoded freeze token input

### Function: `encode_input_for_unfreeze_token`

Given a token_id and nonce return an encoded unfreeze token input

### Function: `encode_input_for_change_token_authority`

Given a token_id, new authority destination and nonce return an encoded change token authority input

### Function: `encode_input_for_change_token_metadata_uri`

Given a token_id, new metadata uri and nonce return an encoded change token metadata uri input

### Function: `encode_input_for_fill_order`

Given an order id and an amount in the order's ask currency, create an input that fills the order.

Note:
1) The nonce is only needed before the orders V1 fork activation. After the fork the nonce is
   ignored and any value can be passed for the parameter.
2) FillOrder inputs should not be signed, i.e. use `encode_witness_no_signature` for the inputs
   instead of `encode_witness`).
   Note that in orders v0 FillOrder inputs can technically have a signature, it's just not checked.
   But in orders V1 we actually require that those inputs don't have signatures.

### Function: `encode_input_for_freeze_order`

Given an order id create an input that freezes the order.

Note: order freezing is available only after the orders V1 fork activation.

### Function: `encode_input_for_conclude_order`

Given an order id create an input that concludes the order.

Note: the nonce is only needed before the orders V1 fork activation. After the fork the nonce is
ignored and any value can be passed for the parameter.

### Function: `encode_output_transfer`

Given a destination address, an amount and a network type (mainnet, testnet, etc), this function
creates an output of type Transfer, and returns it as bytes.

### Function: `encode_output_token_transfer`

Given a destination address, an amount, token ID (in address form) and a network type (mainnet, testnet, etc), this function
creates an output of type Transfer for tokens, and returns it as bytes.

### Function: `encode_output_lock_then_transfer`

Given a valid receiving address, and a locking rule as bytes (available in this file),
and a network type (mainnet, testnet, etc), this function creates an output of type
LockThenTransfer with the parameters provided.

### Function: `encode_output_token_lock_then_transfer`

Given a valid receiving address, token ID (in address form), a locking rule as bytes (available in this file),
and a network type (mainnet, testnet, etc), this function creates an output of type
LockThenTransfer with the parameters provided.

### Function: `encode_output_coin_burn`

Given an amount, this function creates an output (as bytes) to burn a given amount of coins

### Function: `encode_output_token_burn`

Given an amount, token ID (in address form) and network type (mainnet, testnet, etc),
this function creates an output (as bytes) to burn a given amount of tokens

### Function: `encode_output_create_delegation`

Given a pool id as string, an owner address and a network type (mainnet, testnet, etc),
this function returns an output (as bytes) to create a delegation to the given pool.
The owner address is the address that is authorized to withdraw from that delegation.

### Function: `encode_output_delegate_staking`

Given a delegation id (as string, in address form), an amount and a network type (mainnet, testnet, etc),
this function returns an output (as bytes) that would delegate coins to be staked in the specified delegation id.

### Function: `encode_output_create_stake_pool`

Given a pool id, staking data as bytes and the network type (mainnet, testnet, etc),
this function returns an output that creates that staking pool.
Note that the pool id is mandated to be taken from the hash of the first input.
It is not arbitrary.

Note: a UTXO of this kind is consumed when decommissioning a pool (provided that the pool
never staked).

### Function: `encode_output_produce_block_from_stake`

Given a pool id and a staker address, this function returns an output that is emitted
when producing a block via that pool.

Note: a UTXO of this kind is consumed when decommissioning a pool (provided that the pool
has staked at least once).

### Function: `encode_output_issue_fungible_token`

Given the parameters needed to issue a fungible token, and a network type (mainnet, testnet, etc),
this function creates an output that issues that token.

### Function: `encode_output_issue_nft`

Given the parameters needed to issue an NFT, and a network type (mainnet, testnet, etc),
this function creates an output that issues that NFT.

### Function: `encode_output_data_deposit`

Given data to be deposited in the blockchain, this function provides the output that deposits this data

### Function: `encode_output_htlc`

Given the parameters needed to create hash timelock contract, and a network type (mainnet, testnet, etc),
this function creates an output.

### Function: `encode_create_order_output`

Given ask and give amounts and a conclude key create output that creates an order.

'ask_token_id': the parameter represents a Token if it's Some and coins otherwise.
'give_token_id': the parameter represents a Token if it's Some and coins otherwise.

### Enum: `Network`

The network, for which an operation to be done. Mainnet, testnet, etc.

### Enum: `FreezableToken`

Indicates whether a token can be frozen

### Enum: `TokenUnfreezable`

Indicates whether a token can be unfrozen once frozen

### Enum: `TotalSupply`

The token supply of a specific token, set on issuance

### Enum: `SourceId`

A utxo can either come from a transaction or a block reward. This enum signifies that.

### Enum: `SignatureHashType`

The part of the transaction that will be committed in the signature. Similar to bitcoin's sighash.

### Enum: `SimpleCurrencyAmount`

An amount of coins or some token,

### Struct: `Amount`

Amount type abstraction. The amount type is stored in a string
since JavaScript number type cannot fit 128-bit integers.
The amount is given as an integer in units of "atoms".
Atoms are the smallest, indivisible amount of a coin or token.

### Struct: `SimpleAmount`

An alternative representation of `Amount`.

### Struct: `SimpleTokenAmount`

An amount of some token.

### Struct: `PoolAdditionalInfo`

Additional information for a pool.

### Struct: `OrderAdditionalInfo`

Additional information for an order.

### Struct: `TxAdditionalInfo`

Additional information for a transaction.

