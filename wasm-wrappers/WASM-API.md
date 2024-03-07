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
derivation path: 44'/mintlayer_coin_type'/0'/0/key_index

### Function: `make_change_address`

From an extended private key create a change private key for a given key index
derivation path: 44'/mintlayer_coin_type'/0'/1/key_index

### Function: `pubkey_to_pubkeyhash_address`

Given a public key (as bytes) and a network type (mainnet, testnet, etc),
return the address public key hash from that public key as an address

### Function: `public_key_from_private_key`

Given a private key, as bytes, return the bytes of the corresponding public key

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

### Function: `encode_output_transfer`

Given a destination address, an amount and a network type (mainnet, testnet, etc), this function
creates an output of type Transfer, and returns it as bytes.

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

### Function: `encode_output_lock_then_transfer`

Given a valid receiving address, and a locking rule as bytes (available in this file),
and a network type (mainnet, testnet, etc), this function creates an output of type
LockThenTransfer with the parameters provided.

### Function: `encode_output_coin_burn`

Given an amount, this function creates an output (as bytes) to burn a given amount of coins

### Function: `encode_output_create_delegation`

Given a pool id as string, an owner address and a network type (mainnet, testnet, etc),
this function returns an output (as bytes) to create a delegation to the given pool.
The owner address is the address that is authorized to withdraw from that delegation.

### Function: `encode_output_delegate_staking`

Given a delegation id (as string, in address form), an amount and a network type (mainnet, testnet, etc),
this function returns an output (as bytes) that would delegate coins to be staked in the specified delegation id.

### Function: `encode_stake_pool_data`

This function returns the staking pool data needed to create a staking pool in an output as bytes,
given its parameters and the network type (testnet, mainnet, etc).

### Function: `encode_output_create_stake_pool`

Given a pool id, staking data as bytes and the network type (mainnet, testnet, etc),
this function returns an output that creates that staking pool.
Note that the pool id is mandated to be taken from the hash of the first input.
It's not arbitrary.

### Function: `encode_output_issue_fungible_token`

Given the parameters needed to issue a fungible token, and a network type (mainnet, testnet, etc),
this function creates an output that issues that token.

### Function: `encode_output_data_deposit`

Given data to be deposited in the blockchain, this function provides the output that deposits this data

### Function: `encode_input_for_utxo`

Given an output source id as bytes, and an output index, together representing a utxo,
this function returns the input that puts them together, as bytes.

### Function: `encode_input_for_withdraw_from_delegation`

Given a delegation id, an amount and a network type (mainnet, testnet, etc), this function
creates an input that withdraws from a delegation.
A nonce is needed because this spends from an account. The nonce must be in sequence for everything in that account.

### Function: `estimate_transaction_size`

Given inputs, outputs and utxos (each encoded as `Option<TxOutput>`), estimate the transaction size.

### Function: `encode_transaction`

Given inputs as bytes, outputs as bytes, and flags settings, this function returns
the transaction that contains them all, as bytes.

### Function: `encode_witness_no_signature`

Encode an input witness of the variant that contains no signature.

### Function: `encode_witness`

Given a private key, inputs and an input number to sign, and the destination that owns that output (through the utxo),
and a network type (mainnet, testnet, etc), this function returns a witness to be used in a signed transaction, as bytes.

### Function: `encode_signed_transaction`

Given an unsigned transaction, and signatures, this function returns a SignedTransaction object as bytes.

### Function: `effective_pool_balance`

Calculate the "effective balance" of a pool, given the total pool balance and pledge by the pool owner/staker.
The effective balance is how the influence of a pool is calculated due to its balance.

### Enum: `Network`

The network, for which an operation to be done. Mainnet, testnet, etc.

### Enum: `FreezableToken`

Indicates whether a token can be frozen

### Enum: `TotalSupply`

The token supply of a specific token, set on issuance

### Enum: `SourceId`

A utxo can either come from a transaction or a block reward. This enum signifies that.

### Enum: `SignatureHashType`

The part of the transaction that will be committed in the signature. Similar to bitcoin's sighash.

### Struct: `Amount`

Amount type abstraction. The amount type is stored in a string
since JavaScript number type cannot fit 128-bit integers.
The amount is given as an integer in units of "atoms".
Atoms are the smallest, indivisible amount of a coin or token.

