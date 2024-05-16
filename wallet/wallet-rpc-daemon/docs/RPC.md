# RPC documentation for Mintlayer node wallet

Version `0.4.3`.

## Module `WalletRpc`

RPC methods available in the hot wallet mode.


### Method `wallet_sync`

Force the wallet to scan the remaining blocks from node until the tip is reached


Parameters:
```
{}
```

Returns:
```
nothing
```

### Method `wallet_rescan`

Rescan the blockchain and re-detect all operations related to the selected account in this wallet


Parameters:
```
{}
```

Returns:
```
nothing
```

### Method `wallet_best_block`

Parameters:
```
{}
```

Returns:
```
{
    "id": hex string,
    "height": number,
}
```

### Method `account_create`

Creates a new account with an optional name.
Returns an error if the last created account does not have a transaction history.


Parameters:
```
{ "name": EITHER OF
     1) string
     2) null }
```

Returns:
```
{
    "account": number,
    "name": EITHER OF
         1) string
         2) null,
}
```

### Method `account_rename`

Renames the selected account with an optional name.
If the name is not specified, it will remove any existing name for the account.


Parameters:
```
{
    "account": number,
    "name": EITHER OF
         1) string
         2) null,
}
```

Returns:
```
{
    "account": number,
    "name": EITHER OF
         1) string
         2) null,
}
```

### Method `account_balance`

Get the total balance in the selected account in this wallet. See available options to include more categories, like locked coins.


Parameters:
```
{
    "account": number,
    "with_locked": EITHER OF
         1) "Any"
         2) "Unlocked"
         3) "Locked"
         4) null,
}
```

Returns:
```
{
    "coins": {
        "atoms": number string,
        "decimal": decimal string,
    },
    "tokens": { hex string: {
        "atoms": number string,
        "decimal": decimal string,
    }, .. },
}
```

### Method `account_utxos`

Lists all the utxos owned by this account


Parameters:
```
{ "account": number }
```

Returns:
```
[ json, .. ]
```

### Method `node_submit_transaction`

Submits a transaction to mempool, and if it is valid, broadcasts it to the network


Parameters:
```
{
    "tx": hex string,
    "do_not_store": bool,
    "options": { "trust_policy": EITHER OF
         1) "Trusted"
         2) "Untrusted" },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `address_send`

Send a given coin amount to a given address. The wallet will automatically calculate the required information
Optionally, one can also mention the utxos to be used.


Parameters:
```
{
    "account": number,
    "address": bech32 string,
    "amount": EITHER OF
         1) { "atoms": number string }
         2) { "decimal": decimal string },
    "selected_utxos": [ {
        "id": EITHER OF
             1) { "Transaction": hex string }
             2) { "BlockReward": hex string },
        "index": number,
    }, .. ],
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `address_sweep_spendable`

Sweep all spendable coins or tokens from an address or addresses to a given address.
Spendable coins are any coins that are not locked, and tokens that are not frozen or locked.
The wallet will automatically calculate the required fees


Parameters:
```
{
    "account": number,
    "destination_address": bech32 string,
    "from_addresses": [ bech32 string, .. ],
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `staking_sweep_delegation`

Sweep all the coins from a delegation to a given address.
The wallet will automatically calculate the required fees


Parameters:
```
{
    "account": number,
    "destination_address": bech32 string,
    "delegation_id": bech32 string,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `transaction_create_from_cold_input`

Creates a transaction that spends from a specific address,
and returns the change to the same address (unless one is specified), without signature.
This transaction is used for "withdrawing" small amounts from a cold storage
without changing the ownership address. Once this is created,
it can be signed using account-sign-raw-transaction in the cold wallet
and then broadcast through any hot wallet.
In summary, this creates a transaction with one input and two outputs,
with one of the outputs being change returned to the same owner of the input.


Parameters:
```
{
    "account": number,
    "address": bech32 string,
    "amount": EITHER OF
         1) { "atoms": number string }
         2) { "decimal": decimal string },
    "selected_utxo": {
        "id": EITHER OF
             1) { "Transaction": hex string }
             2) { "BlockReward": hex string },
        "index": number,
    },
    "change_address": EITHER OF
         1) bech32 string
         2) null,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{
    "hex": string,
    "fees": {
        "coins": {
            "atoms": number string,
            "decimal": decimal string,
        },
        "tokens": { hex string: {
            "atoms": number string,
            "decimal": decimal string,
        }, .. },
    },
}
```

### Method `transaction_inspect`

Print the summary of the transaction


Parameters:
```
{ "transaction": hex string }
```

Returns:
```
{
    "tx": hex string,
    "fees": EITHER OF
         1) {
                "coins": {
                    "atoms": number string,
                    "decimal": decimal string,
                },
                "tokens": { hex string: {
                    "atoms": number string,
                    "decimal": decimal string,
                }, .. },
            }
         2) null,
    "stats": {
        "num_inputs": number,
        "total_signatures": number,
        "validated_signatures": EITHER OF
             1) {
                    "num_valid_signatures": number,
                    "num_invalid_signatures": number,
                }
             2) null,
    },
}
```

### Method `staking_create_pool`

Create a staking pool. The pool will be capable of creating blocks and gaining rewards,
and will be capable of taking delegations from other users and staking.
The decommission key is the key that can decommission the pool.
Cost per block, and margin ratio are parameters that control how delegators receive rewards.
The cost per block is an amount in coins to be subtracted from the total rewards in a block first,
and handed to the staking pool. After subtracting the cost per block, a fraction equal to
margin ratio is taken from what is left, and given to the staking pool. Finally, what is left
is distributed among delegators, pro-rata, based on their delegation amounts.


Parameters:
```
{
    "account": number,
    "amount": EITHER OF
         1) { "atoms": number string }
         2) { "decimal": decimal string },
    "cost_per_block": EITHER OF
         1) { "atoms": number string }
         2) { "decimal": decimal string },
    "margin_ratio_per_thousand": string,
    "decommission_address": bech32 string,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `staking_decommission_pool`

Decommission a staking pool, given its id. This assumes that the decommission key is owned
by the selected account in this wallet.


Parameters:
```
{
    "account": number,
    "pool_id": bech32 string,
    "output_address": EITHER OF
         1) bech32 string
         2) null,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `staking_decommission_pool_request`

Create a request to decommission a pool. This assumes that the decommission key is owned
by another wallet. The output of this command should be passed to account-sign-raw-transaction
in the wallet that owns the decommission key. The result from signing, assuming success, can
then be broadcast to network to commence with decommissioning.


Parameters:
```
{
    "account": number,
    "pool_id": bech32 string,
    "output_address": EITHER OF
         1) bech32 string
         2) null,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
hex string
```

### Method `delegation_create`

Create a delegation to a given pool id and the owner address/destination.
The owner of a delegation is the key authorized to withdraw from the delegation.
The delegation creation will result in creating a delegation id, where coins sent to that id will be staked by the pool id provided, automatically.
The pool, to which the delegation is made, doesn't have the authority to spend the coins.


Parameters:
```
{
    "account": number,
    "address": bech32 string,
    "pool_id": bech32 string,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{
    "tx_id": hex string,
    "delegation_id": bech32 string,
}
```

### Method `delegation_stake`

Send coins to a delegation id to be staked


Parameters:
```
{
    "account": number,
    "amount": EITHER OF
         1) { "atoms": number string }
         2) { "decimal": decimal string },
    "delegation_id": bech32 string,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `delegation_withdraw`

Send coins from a delegation id (that you own) to stop staking them.
Note that stopping the delegation requires a lock period.


Parameters:
```
{
    "account": number,
    "address": bech32 string,
    "amount": EITHER OF
         1) { "atoms": number string }
         2) { "decimal": decimal string },
    "delegation_id": bech32 string,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `staking_start`

Start staking, assuming there are staking pools in the selected account in this wallet.


Parameters:
```
{ "account": number }
```

Returns:
```
nothing
```

### Method `staking_stop`

Stop staking, assuming there are staking pools staking currently in the selected account in this wallet.


Parameters:
```
{ "account": number }
```

Returns:
```
nothing
```

### Method `staking_status`

Show the staking status for the currently selected account in this wallet.


Parameters:
```
{ "account": number }
```

Returns:
```
EITHER OF
     1) "Staking"
     2) "NotStaking"
```

### Method `staking_list_pools`

List ids of pools that are controlled by the selected account in this wallet


Parameters:
```
{ "account": number }
```

Returns:
```
[ {
    "pool_id": bech32 string,
    "pledge": {
        "atoms": number string,
        "decimal": decimal string,
    },
    "balance": {
        "atoms": number string,
        "decimal": decimal string,
    },
    "height": number,
    "block_timestamp": { "timestamp": number },
    "vrf_public_key": bech32 string,
    "decommission_key": bech32 string,
    "staker": bech32 string,
}, .. ]
```

### Method `staking_list_owned_pools_for_decommission`

List pools that can be decommissioned by the selected account in this wallet


Parameters:
```
{ "account": number }
```

Returns:
```
[ {
    "pool_id": bech32 string,
    "pledge": {
        "atoms": number string,
        "decimal": decimal string,
    },
    "balance": {
        "atoms": number string,
        "decimal": decimal string,
    },
    "height": number,
    "block_timestamp": { "timestamp": number },
    "vrf_public_key": bech32 string,
    "decommission_key": bech32 string,
    "staker": bech32 string,
}, .. ]
```

### Method `staking_pool_balance`

Print the balance of available staking pools


Parameters:
```
{ "pool_id": bech32 string }
```

Returns:
```
{ "balance": EITHER OF
     1) string
     2) null }
```

### Method `delegation_list_ids`

List delegation ids controlled by the selected account in this wallet with their balances


Parameters:
```
{ "account": number }
```

Returns:
```
[ {
    "delegation_id": bech32 string,
    "balance": {
        "atoms": number string,
        "decimal": decimal string,
    },
}, .. ]
```

### Method `staking_list_created_block_ids`

List the blocks created by the selected account in this wallet through staking/mining/etc


Parameters:
```
{ "account": number }
```

Returns:
```
[ {
    "id": hex string,
    "height": number,
    "pool_id": string,
}, .. ]
```

### Method `token_nft_issue_new`

Issue a new non-fungible token (NFT) from scratch


Parameters:
```
{
    "account": number,
    "destination_address": bech32 string,
    "metadata": {
        "media_hash": string,
        "name": EITHER OF
             1) string
             2) { "hex": hex string },
        "description": EITHER OF
             1) string
             2) { "hex": hex string },
        "ticker": string,
        "creator": EITHER OF
             1) hex string
             2) null,
        "icon_uri": EITHER OF
             1) string
             2) { "hex": hex string }
             3) null,
        "media_uri": EITHER OF
             1) string
             2) { "hex": hex string }
             3) null,
        "additional_metadata_uri": EITHER OF
             1) string
             2) { "hex": hex string }
             3) null,
    },
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{
    "token_id": bech32 string,
    "tx_id": hex string,
}
```

### Method `token_issue_new`

Issue a new fungible token from scratch.
Notice that issuing a token fills an issuers supply. To have tokens that are spendable,
the issuer must "mint" tokens to take from the supply


Parameters:
```
{
    "account": number,
    "destination_address": bech32 string,
    "metadata": {
        "token_ticker": EITHER OF
             1) string
             2) { "hex": hex string },
        "number_of_decimals": number,
        "metadata_uri": EITHER OF
             1) string
             2) { "hex": hex string },
        "token_supply": EITHER OF
             1) { "Fixed": EITHER OF
                     1) { "atoms": number string }
                     2) { "decimal": decimal string } }
             2) "Lockable"
             3) "Unlimited",
        "is_freezable": bool,
    },
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{
    "token_id": bech32 string,
    "tx_id": hex string,
}
```

### Method `token_change_authority`

Change the authority of a token; i.e., the cryptographic authority that can do all authority token operations


Parameters:
```
{
    "account": number,
    "token_id": bech32 string,
    "address": bech32 string,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `token_mint`

Given a token that is already issued, mint new tokens and increase the total supply


Parameters:
```
{
    "account": number,
    "token_id": bech32 string,
    "address": bech32 string,
    "amount": EITHER OF
         1) { "atoms": number string }
         2) { "decimal": decimal string },
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `token_unmint`

Unmint existing tokens and reduce the total supply
Unminting reduces the total supply and puts the unminted tokens back at the issuer's control.
The wallet must own the tokens that are being unminted.


Parameters:
```
{
    "account": number,
    "token_id": bech32 string,
    "amount": EITHER OF
         1) { "atoms": number string }
         2) { "decimal": decimal string },
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `token_lock_supply`

Lock the circulating supply for the token. THIS IS IRREVERSIBLE.
Tokens that can be locked will lose the ability to mint/unmint them


Parameters:
```
{
    "account_index": number,
    "token_id": bech32 string,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `token_freeze`

Freezing the token (by token authority) forbids any operation with all the tokens (except for the optional unfreeze).

After a token is frozen, no transfers, spends, or any other operation can be done.
This wallet (and selected account) must own the authority keys to be able to freeze.


Parameters:
```
{
    "account": number,
    "token_id": bech32 string,
    "is_unfreezable": bool,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `token_unfreeze`

By unfreezing the token all operations are available for the tokens again.

Notice that this is only possible if the tokens were made to be unfreezable during freezing.
This wallet (and selected account) must own the authority keys to be able to unfreeze.


Parameters:
```
{
    "account": number,
    "token_id": bech32 string,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `token_send`

Send a given token amount to a given address. The wallet will automatically calculate the required information


Parameters:
```
{
    "account": number,
    "token_id": bech32 string,
    "address": bech32 string,
    "amount": EITHER OF
         1) { "atoms": number string }
         2) { "decimal": decimal string },
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `address_deposit_data`

Store data on the blockchain, the data is provided as hex encoded string.
Note that there is a high fee for storing data on the blockchain.


Parameters:
```
{
    "account": number,
    "data": hex string,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{ "tx_id": hex string }
```

### Method `node_version`

Node version


Parameters:
```
{}
```

Returns:
```
{ "version": string }
```

### Method `node_shutdown`

Node shutdown


Parameters:
```
{}
```

Returns:
```
nothing
```

### Method `node_enable_networking`

Enable or disable p2p networking in the node


Parameters:
```
{ "enable": bool }
```

Returns:
```
nothing
```

### Method `node_connect_to_peer`

Connect to a remote peer in the node


Parameters:
```
{ "address": string }
```

Returns:
```
nothing
```

### Method `node_disconnect_peer`

Disconnected a remote peer in the node


Parameters:
```
{ "peer_id": number }
```

Returns:
```
nothing
```

### Method `node_list_banned_peers`

List banned addresses/peers in the node


Parameters:
```
{}
```

Returns:
```
[ [
    string,
    { "time": [
        secs number,
        nanos number,
    ] },
], .. ]
```

### Method `node_ban_peer_address`

Ban an address in the node for the specified duration


Parameters:
```
{
    "address": string,
    "duration": [
        secs number,
        nanos number,
    ],
}
```

Returns:
```
nothing
```

### Method `node_unban_peer_address`

Unban address in the node


Parameters:
```
{ "address": string }
```

Returns:
```
nothing
```

### Method `node_list_discouraged_peers`

List discouraged addresses/peers in the node


Parameters:
```
{}
```

Returns:
```
[ [
    string,
    { "time": [
        secs number,
        nanos number,
    ] },
], .. ]
```

### Method `node_peer_count`

Get the number of connected peer in the node


Parameters:
```
{}
```

Returns:
```
number
```

### Method `node_list_connected_peers`

Get connected peers in the node


Parameters:
```
{}
```

Returns:
```
[ {
    "peer_id": number,
    "address": string,
    "peer_role": EITHER OF
         1) "Inbound"
         2) "OutboundFullRelay"
         3) "OutboundBlockRelay"
         4) "OutboundReserved"
         5) "OutboundManual"
         6) "Feeler",
    "ban_score": number,
    "user_agent": string,
    "software_version": string,
    "ping_wait": EITHER OF
         1) number
         2) null,
    "ping_last": EITHER OF
         1) number
         2) null,
    "ping_min": EITHER OF
         1) number
         2) null,
}, .. ]
```

### Method `node_list_reserved_peers`

Get reserved peers in the node


Parameters:
```
{}
```

Returns:
```
[ string, .. ]
```

### Method `node_add_reserved_peer`

Add a reserved peer in the node


Parameters:
```
{ "address": string }
```

Returns:
```
nothing
```

### Method `node_remove_reserved_peer`

Remove a reserved peer from the node


Parameters:
```
{ "address": string }
```

Returns:
```
nothing
```

### Method `node_submit_block`

Submit a block to be included in the chain


Parameters:
```
{ "block": hex string }
```

Returns:
```
nothing
```

### Method `node_chainstate_info`

Returns the current node's chainstate (block height information and more)


Parameters:
```
{}
```

Returns:
```
{
    "best_block_height": number,
    "best_block_id": hex string,
    "best_block_timestamp": { "timestamp": number },
    "median_time": { "timestamp": number },
    "is_initial_block_download": bool,
}
```

### Method `transaction_abandon`

Abandon an unconfirmed transaction in the wallet database, and make the consumed inputs available to be used again
Note that this doesn't necessarily mean that the network will agree. This assumes the transaction is either still
not confirmed in the network or somehow invalid.


Parameters:
```
{
    "account": number,
    "transaction_id": hex string,
}
```

Returns:
```
nothing
```

### Method `transaction_list_pending`

List the pending transactions that can be abandoned


Parameters:
```
{ "account": number }
```

Returns:
```
[ hex string, .. ]
```

### Method `transaction_list_by_address`

List mainchain transactions with optional address filter


Parameters:
```
{
    "account": number,
    "address": EITHER OF
         1) bech32 string
         2) null,
    "limit": number,
}
```

Returns:
```
[ {
    "id": hex string,
    "height": number,
    "timestamp": { "timestamp": number },
}, .. ]
```

### Method `transaction_get`

Get a transaction from the wallet, if present


Parameters:
```
{
    "account": number,
    "transaction_id": hex string,
}
```

Returns:
```
json
```

### Method `transaction_get_raw`

Get a transaction from the wallet, if present, as hex encoded raw transaction


Parameters:
```
{
    "account": number,
    "transaction_id": hex string,
}
```

Returns:
```
hex string
```

### Method `transaction_get_signed_raw`

Get a signed transaction from the wallet, if present, as hex encoded raw transaction


Parameters:
```
{
    "account": number,
    "transaction_id": hex string,
}
```

Returns:
```
hex string
```

### Method `transaction_compose`

Compose a new transaction from the specified outputs and selected utxos
The transaction is returned in a hex encoded form that can be passed to account-sign-raw-transaction
and also prints the fees that will be paid by the transaction


Parameters:
```
{
    "inputs": [ {
        "id": EITHER OF
             1) { "Transaction": hex string }
             2) { "BlockReward": hex string },
        "index": number,
    }, .. ],
    "outputs": [ object, .. ],
    "only_transaction": bool,
}
```

Returns:
```
{
    "hex": string,
    "fees": {
        "coins": {
            "atoms": number string,
            "decimal": decimal string,
        },
        "tokens": { hex string: {
            "atoms": number string,
            "decimal": decimal string,
        }, .. },
    },
}
```

### Method `node_best_block_id`

Returns the current best block hash


Parameters:
```
{}
```

Returns:
```
hex string
```

### Method `node_best_block_height`

Returns the current best block height


Parameters:
```
{}
```

Returns:
```
number
```

### Method `node_block_id`

Get the block ID of the block at a given height


Parameters:
```
{ "block_height": number }
```

Returns:
```
EITHER OF
     1) hex string
     2) null
```

### Method `node_generate_block`

Generate a block with the given transactions to the specified
reward destination. If transactions are None, the block will be
generated with available transactions in the mempool


Parameters:
```
{
    "account": number,
    "transactions": [ hex string, .. ],
}
```

Returns:
```
nothing
```

### Method `node_generate_blocks`

Parameters:
```
{
    "account": number,
    "block_count": number,
}
```

Returns:
```
nothing
```

### Method `node_get_block`

Get a block by its hash, represented with hex encoded bytes


Parameters:
```
{ "block_id": hex string }
```

Returns:
```
EITHER OF
     1) hex string
     2) null
```

### Method `node_get_block_ids_as_checkpoints`

Returns mainchain block ids with heights in the range start_height..end_height using
the given step.


Parameters:
```
{
    "start_height": number,
    "end_height": number,
    "step": non-zero number,
}
```

Returns:
```
[ [
    number,
    hex string,
], .. ]
```

## Module `ColdWalletRpc`

RPC methods available in the cold wallet mode.


### Method `shutdown`

Parameters:
```
{}
```

Returns:
```
nothing
```

### Method `version`

Print the version of the wallet software and possibly the git commit hash, if found WWW!!


Parameters:
```
{}
```

Returns:
```
string
```

### Method `wallet_create`

Create new wallet


Parameters:
```
{
    "path": string,
    "store_seed_phrase": bool,
    "mnemonic": EITHER OF
         1) string
         2) null,
    "passphrase": EITHER OF
         1) string
         2) null,
}
```

Returns:
```
EITHER OF
     1) "UserProvidedMnemonic"
     2) { "NewlyGeneratedMnemonic": [
            string,
            EITHER OF
                 1) string
                 2) null,
        ] }
```

### Method `wallet_open`

Open an exiting wallet by specifying the file location of the wallet file


Parameters:
```
{
    "path": string,
    "password": EITHER OF
         1) string
         2) null,
    "force_migrate_wallet_type": EITHER OF
         1) bool
         2) null,
}
```

Returns:
```
nothing
```

### Method `wallet_close`

Close the currently open wallet file


Parameters:
```
{}
```

Returns:
```
nothing
```

### Method `wallet_info`

Check the current wallet's number of accounts and their names


Parameters:
```
{}
```

Returns:
```
{
    "wallet_id": hex string,
    "account_names": [ EITHER OF
         1) string
         2) null, .. ],
}
```

### Method `wallet_encrypt_private_keys`

Encrypts the private keys with a new password, expects the wallet to be unlocked


Parameters:
```
{ "password": string }
```

Returns:
```
nothing
```

### Method `wallet_disable_private_keys_encryption`

Completely and totally remove any existing encryption, expects the wallet to be unlocked.
WARNING: After this, your wallet file will be USABLE BY ANYONE without a password.


Parameters:
```
{}
```

Returns:
```
nothing
```

### Method `wallet_unlock_private_keys`

Unlocks the private keys for usage.


Parameters:
```
{ "password": string }
```

Returns:
```
nothing
```

### Method `wallet_lock_private_keys`

Locks the private keys so they can't be used until they are unlocked again


Parameters:
```
{}
```

Returns:
```
nothing
```

### Method `wallet_show_seed_phrase`

Show the seed phrase for the loaded wallet if it has been s


Parameters:
```
{}
```

Returns:
```
EITHER OF
     1) {
            "seed_phrase": [ string, .. ],
            "passphrase": EITHER OF
                 1) string
                 2) null,
        }
     2) null
```

### Method `wallet_purge_seed_phrase`

Delete the seed phrase from the loaded wallet's database, if it has been stored.


Parameters:
```
{}
```

Returns:
```
EITHER OF
     1) {
            "seed_phrase": [ string, .. ],
            "passphrase": EITHER OF
                 1) string
                 2) null,
        }
     2) null
```

### Method `wallet_set_lookahead_size`

Set the lookahead size for key generation.

Lookahead size (or called gap) is the number of addresses to generate and the blockchain for incoming transactions to them
after the last address that was seen to contain a transaction on the blockchain.
Do not attempt to reduce the size of this value unless you're sure there are no incoming transactions in these addresses.


Parameters:
```
{
    "lookahead_size": number,
    "i_know_what_i_am_doing": bool,
}
```

Returns:
```
nothing
```

### Method `address_show`

Show receive-addresses with their usage state.
Note that whether an address is used isn't based on the wallet,
but on the blockchain. So if an address is used in a transaction,
it will be marked as used only when the transaction is included
in a block.


Parameters:
```
{ "account": number }
```

Returns:
```
[ {
    "address": bech32 string,
    "index": string,
    "used": bool,
}, .. ]
```

### Method `address_new`

Generate a new unused address


Parameters:
```
{ "account": number }
```

Returns:
```
{
    "address": string,
    "index": string,
}
```

### Method `address_reveal_public_key`

Reveal the public key behind this address in hex encoding and address encoding.
Note that this isn't a normal address to be used in transactions.
It's preferred to take the address from address-show command


Parameters:
```
{
    "account": number,
    "address": bech32 string,
}
```

Returns:
```
{
    "public_key_hex": hex string,
    "public_key_address": bech32 string,
}
```

### Method `staking_new_vrf_public_key`

Issue a new staking VRF (Verifiable Random Function) key for this account.
VRF keys are used as a trustless mechanism to ensure the randomness of the staking process,
where no one can control the possible outcomes, to ensure decentralization.
NOTE: Under normal circumstances you don't need to generate VRF keys manually.
Creating a new staking pool will do it for you. This is available for specialized use-cases.


Parameters:
```
{ "account": number }
```

Returns:
```
{
    "vrf_public_key": bech32 string,
    "child_number": number,
    "used": bool,
}
```

### Method `staking_show_legacy_vrf_key`

Shows the legacy VRF key that uses an abandoned derivation mechanism.
This will not be used for new pools and should be avoided


Parameters:
```
{ "account": number }
```

Returns:
```
{ "vrf_public_key": string }
```

### Method `staking_show_vrf_public_keys`

Show the issued staking VRF (Verifiable Random Function) keys for this account.
These keys are generated when pools are created.
VRF keys are used as a trustless mechanism to ensure the randomness of the staking process,
where no one can control the possible outcomes, to ensure decentralization.


Parameters:
```
{ "account": number }
```

Returns:
```
[ {
    "vrf_public_key": bech32 string,
    "child_number": number,
    "used": bool,
}, .. ]
```

### Method `account_sign_raw_transaction`

Signs the inputs that are not yet signed.
The input is a special format of the transaction serialized to hex. This format is automatically used in this wallet
in functions such as staking-decommission-pool-request. Once all signatures are complete, the result can be broadcast
to the network.


Parameters:
```
{
    "account": number,
    "raw_tx": hex string,
    "options": { "in_top_x_mb": EITHER OF
         1) number
         2) null },
}
```

Returns:
```
{
    "hex": string,
    "is_complete": bool,
}
```

### Method `challenge_sign_plain`

Signs a challenge with a private key corresponding to the provided address destination.


Parameters:
```
{
    "account": number,
    "challenge": string,
    "address": bech32 string,
}
```

Returns:
```
hex string
```

### Method `challenge_sign_hex`

Signs a challenge with a private key corresponding to the provided address destination.


Parameters:
```
{
    "account": number,
    "challenge": hex string,
    "address": bech32 string,
}
```

Returns:
```
hex string
```

### Method `challenge_verify_plain`

Verifies a signed challenge against an address destination


Parameters:
```
{
    "message": string,
    "signed_challenge": hex string,
    "address": bech32 string,
}
```

Returns:
```
nothing
```

### Method `challenge_verify_hex`

Verifies a signed challenge against an address destination


Parameters:
```
{
    "message": hex string,
    "signed_challenge": hex string,
    "address": bech32 string,
}
```

Returns:
```
nothing
```

