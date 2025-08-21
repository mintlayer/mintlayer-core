# RPC documentation for Mintlayer node

Version `1.1.0`.

## Module `node`

RPC methods controlling the node.


### Method `node_shutdown`

Order the node to shutdown.


Parameters:
```
{}
```

Returns:
```
nothing
```

### Method `node_version`

Get node software version.


Parameters:
```
{}
```

Returns:
```
string
```

### Method `node_set_mock_time`

Set mock time for the node.

The value 0 is equivalent to "Nothing", making the node use real, wall-clock time.
WARNING: This function is strictly used for testing purposes. Using it will obstruct normal node functionality.


Parameters:
```
{ "time": number }
```

Returns:
```
nothing
```

## Module `chainstate`

### Method `chainstate_best_block_id`

Get the best block ID, which is the tip of the blockchain (i.e., longest chain, or mainchain).


Parameters:
```
{}
```

Returns:
```
hex string
```

### Method `chainstate_block_id_at_height`

Get block ID at a given height in the mainchain.

Returns `None` (null) if the block at the given height does not exist.


Parameters:
```
{ "height": number }
```

Returns:
```
EITHER OF
     1) hex string
     2) null
```

### Method `chainstate_get_block`

Returns a hex-encoded serialized block with the given id.

Returns `None` (null) if a block with the given id is not found.
Note that genesis cannot be retrieved with this function.


Parameters:
```
{ "id": hex string }
```

Returns:
```
EITHER OF
     1) hex string
     2) null
```

### Method `chainstate_get_block_json`

Same as get_block, but returns the block information in json format.


Parameters:
```
{ "id": hex string }
```

Returns:
```
EITHER OF
     1) json
     2) null
```

### Method `chainstate_get_mainchain_blocks`

Returns hex-encoded serialized blocks from the mainchain starting from a given block height.

The number of returned blocks can be capped using the `max_count` parameter.


Parameters:
```
{
    "from": number,
    "max_count": number,
}
```

Returns:
```
[ hex string, .. ]
```

### Method `chainstate_get_block_ids_as_checkpoints`

Returns mainchain block ids with heights in the range start_height..end_height using
the given step;


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

### Method `chainstate_get_utxo`

Returns the TxOutput for a specified UtxoOutPoint.
Returns `None` (null) if the UtxoOutPoint is not found or is already spent.


Parameters:
```
{ "outpoint": {
    "source_id": EITHER OF
         1) {
                "type": "Transaction",
                "content": { "tx_id": hex string },
            }
         2) {
                "type": "BlockReward",
                "content": { "block_id": hex string },
            },
    "index": number,
} }
```

Returns:
```
EITHER OF
     1) object
     2) null
```

### Method `chainstate_submit_block`

Submit a block to be included in the blockchain.

Note that the submission does not circumvent any validation process.
This function is used by the wallet to submit valid blocks after successful staking.


Parameters:
```
{ "block_hex": hex string }
```

Returns:
```
nothing
```

### Method `chainstate_invalidate_block`

Invalidate the specified block and its descendants.

Use this function with caution, as invalidating a block that the network approves
of can lead to staying behind.


Parameters:
```
{ "id": hex string }
```

Returns:
```
nothing
```

### Method `chainstate_reset_block_failure_flags`

Reset failure flags for the specified block and its descendants.


Parameters:
```
{ "id": hex string }
```

Returns:
```
nothing
```

### Method `chainstate_block_height_in_main_chain`

Get block height in mainchain, given a block id.


Parameters:
```
{ "block_id": hex string }
```

Returns:
```
EITHER OF
     1) number
     2) null
```

### Method `chainstate_best_block_height`

Get best block height in mainchain.


Parameters:
```
{}
```

Returns:
```
number
```

### Method `chainstate_last_common_ancestor_by_id`

Returns last common block id and height of two chains.
Returns None if no blocks are found and therefore the last common ancestor is unknown.


Parameters:
```
{
    "first_block": hex string,
    "second_block": hex string,
}
```

Returns:
```
EITHER OF
     1) [
            hex string,
            number,
        ]
     2) null
```

### Method `chainstate_stake_pool_balance`

Returns the balance of the pool associated with the given pool id.

The balance contains both delegated balance and staker balance.
Returns `None` (null) if the pool is not found.


Parameters:
```
{ "pool_address": string }
```

Returns:
```
EITHER OF
     1) { "atoms": number string }
     2) null
```

### Method `chainstate_staker_balance`

Returns the balance of the staker (pool owner) of the pool associated with the given pool address.

This excludes the delegation balances.
Returns `None` (null) if the pool is not found.


Parameters:
```
{ "pool_address": string }
```

Returns:
```
EITHER OF
     1) { "atoms": number string }
     2) null
```

### Method `chainstate_pool_decommission_destination`

Returns the pool's decommission destination associated with the given pool address.

Returns `None` (null) if the pool is not found.


Parameters:
```
{ "pool_address": string }
```

Returns:
```
EITHER OF
     1) bech32 string
     2) null
```

### Method `chainstate_delegation_share`

Given a pool defined by a pool address, and a delegation address,
returns the amount of coins owned by that delegation in that pool.


Parameters:
```
{
    "pool_address": string,
    "delegation_address": string,
}
```

Returns:
```
EITHER OF
     1) { "atoms": number string }
     2) null
```

### Method `chainstate_token_info`

Get token information, given a token id, in address form.


Parameters:
```
{ "token_id": string }
```

Returns:
```
EITHER OF
     1) {
            "type": "FungibleToken",
            "content": {
                "token_id": hex string,
                "token_ticker": {
                    "text": EITHER OF
                         1) string
                         2) null,
                    "hex": hex string,
                },
                "number_of_decimals": number,
                "metadata_uri": {
                    "text": EITHER OF
                         1) string
                         2) null,
                    "hex": hex string,
                },
                "circulating_supply": { "atoms": number string },
                "total_supply": EITHER OF
                     1) {
                            "type": "Fixed",
                            "content": { "amount": { "atoms": number string } },
                        }
                     2) { "type": "Lockable" }
                     3) { "type": "Unlimited" },
                "is_locked": bool,
                "frozen": EITHER OF
                     1) {
                            "type": "NotFrozen",
                            "content": { "freezable": bool },
                        }
                     2) {
                            "type": "Frozen",
                            "content": { "unfreezable": bool },
                        },
                "authority": bech32 string,
            },
        }
     2) {
            "type": "NonFungibleToken",
            "content": {
                "token_id": hex string,
                "creation_tx_id": hex string,
                "creation_block_id": hex string,
                "metadata": {
                    "creator": EITHER OF
                         1) hex string
                         2) null,
                    "name": {
                        "text": EITHER OF
                             1) string
                             2) null,
                        "hex": hex string,
                    },
                    "description": {
                        "text": EITHER OF
                             1) string
                             2) null,
                        "hex": hex string,
                    },
                    "ticker": {
                        "text": EITHER OF
                             1) string
                             2) null,
                        "hex": hex string,
                    },
                    "icon_uri": EITHER OF
                         1) {
                                "text": EITHER OF
                                     1) string
                                     2) null,
                                "hex": hex string,
                            }
                         2) null,
                    "additional_metadata_uri": EITHER OF
                         1) {
                                "text": EITHER OF
                                     1) string
                                     2) null,
                                "hex": hex string,
                            }
                         2) null,
                    "media_uri": EITHER OF
                         1) {
                                "text": EITHER OF
                                     1) string
                                     2) null,
                                "hex": hex string,
                            }
                         2) null,
                    "media_hash": hex string,
                },
            },
        }
     3) null
```

### Method `chainstate_order_info`

Get order information, given an order id, in address form.


Parameters:
```
{ "order_id": string }
```

Returns:
```
EITHER OF
     1) {
            "conclude_key": bech32 string,
            "initially_asked": EITHER OF
                 1) {
                        "type": "Coin",
                        "content": { "amount": { "atoms": number string } },
                    }
                 2) {
                        "type": "Token",
                        "content": {
                            "id": hex string,
                            "amount": { "atoms": number string },
                        },
                    },
            "initially_given": EITHER OF
                 1) {
                        "type": "Coin",
                        "content": { "amount": { "atoms": number string } },
                    }
                 2) {
                        "type": "Token",
                        "content": {
                            "id": hex string,
                            "amount": { "atoms": number string },
                        },
                    },
            "give_balance": { "atoms": number string },
            "ask_balance": { "atoms": number string },
            "nonce": EITHER OF
                 1) number
                 2) null,
        }
     2) null
```

### Method `chainstate_export_bootstrap_file`

Exports a "bootstrap file", which contains all blocks


Parameters:
```
{
    "file_path": string,
    "include_orphans": bool,
}
```

Returns:
```
nothing
```

### Method `chainstate_import_bootstrap_file`

Imports a bootstrap file's blocks to this node


Parameters:
```
{ "file_path": string }
```

Returns:
```
nothing
```

### Method `chainstate_info`

Return generic information about the chain, including the current best block, best block height and more.


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

### Subscription `chainstate_subscribe_to_events`

Subscribe to chainstate events, such as new tip.

After a successful subscription, the node will message the subscriber with a message on every event.


Parameters:
```
{}
```

Produces:
```
{
    "type": "NewTip",
    "content": {
        "id": hex string,
        "height": number,
    },
}
```

Unsubscribe using `chainstate_unsubscribe_to_events`.

Note: Subscriptions only work over WebSockets.

## Module `mempool`

### Method `mempool_contains_tx`

Returns True if a transaction defined by the given id is found in the mempool.


Parameters:
```
{ "tx_id": hex string }
```

Returns:
```
bool
```

### Method `mempool_contains_orphan_tx`

Returns True if a transaction defined by the given id is found in the mempool's orphans.

An orphan transaction is a transaction with one or more inputs, whose utxos cannot be found.


Parameters:
```
{ "tx_id": hex string }
```

Returns:
```
bool
```

### Method `mempool_get_transaction`

Returns the transaction defined by the provided id, given that it is in the pool.

The returned transaction is returned in an object that contains more information about the transaction.
Returns `None` (null) if the transaction is not found.


Parameters:
```
{ "tx_id": hex string }
```

Returns:
```
EITHER OF
     1) {
            "id": hex string,
            "status": EITHER OF
                 1) "InMempool"
                 2) "InMempoolDuplicate"
                 3) "InOrphanPool"
                 4) "InOrphanPoolDuplicate",
            "transaction": hex string,
        }
     2) null
```

### Method `mempool_transactions`

Get all mempool transactions in a Vec/List, with hex-encoding.

Notice that this call may be expensive. Use it with caution.
This function is mostly used for testing purposes.


Parameters:
```
{}
```

Returns:
```
[ hex string, .. ]
```

### Method `mempool_submit_transaction`

Submit a transaction to the mempool.

Note that submitting a transaction to the mempool does not guarantee broadcasting it.
Use the p2p rpc interface for that.


Parameters:
```
{
    "tx": hex string,
    "options": { "trust_policy": EITHER OF
         1) "Trusted"
         2) "Untrusted" },
}
```

Returns:
```
nothing
```

### Method `mempool_local_best_block_id`

Return the id of the best block, as seen by the mempool.

Typically this agrees with chainstate, but there could be some delay in responding to chainstate.


Parameters:
```
{}
```

Returns:
```
hex string
```

### Method `mempool_memory_usage`

The total estimated used memory by the mempool.


Parameters:
```
{}
```

Returns:
```
number
```

### Method `mempool_get_size_limit`

Get the maximum allowed size of all transactions in the mempool.


Parameters:
```
{}
```

Returns:
```
number
```

### Method `mempool_set_size_limit`

Set the maximum allowed size of all transactions in the mempool.

The parameter is either a string, can be written with proper units, such as "100 MB", or "500 KB", or an integer taken as bytes.


Parameters:
```
{ "max_size": String with units, such as MB/KB/GB, or integer for bytes }
```

Returns:
```
nothing
```

### Method `mempool_get_fee_rate`

Get the current fee rate of the mempool, that puts the transaction in the top X MBs of the mempool.
X, in this description, is provided as a parameter.


Parameters:
```
{ "in_top_x_mb": number }
```

Returns:
```
{ "amount_per_kb": { "atoms": number string } }
```

### Method `mempool_get_fee_rate_points`

Get the curve data points that represent the fee rate as a function of transaction size.


Parameters:
```
{}
```

Returns:
```
[ [
    number,
    { "amount_per_kb": { "atoms": number string } },
], .. ]
```

### Subscription `mempool_subscribe_to_events`

Subscribe to mempool events, such as tx processed.

After a successful subscription, the node will message the subscriber with a message on every event.


Parameters:
```
{}
```

Produces:
```
EITHER OF
     1) {
            "type": "NewTip",
            "content": {
                "id": hex string,
                "height": number,
            },
        }
     2) {
            "type": "TransactionProcessed",
            "content": {
                "tx_id": hex string,
                "origin": EITHER OF
                     1) {
                            "type": "Local",
                            "content": { "origin": EITHER OF
                                 1) { "type": "Mempool" }
                                 2) { "type": "P2p" }
                                 3) { "type": "PastBlock" } },
                        }
                     2) {
                            "type": "Remote",
                            "content": { "peer_id": number },
                        },
                "relay": EITHER OF
                     1) { "type": "DoRelay" }
                     2) { "type": "DontRelay" },
                "successful": bool,
            },
        }
```

Unsubscribe using `mempool_unsubscribe_to_events`.

Note: Subscriptions only work over WebSockets.

## Module `p2p`

### Method `p2p_enable_networking`

Enable or disable networking


Parameters:
```
{ "enable": bool }
```

Returns:
```
nothing
```

### Method `p2p_connect`

Attempt to connect to a remote node (just once).

For persistent connections see `add_reserved_node` should be used.
Keep in mind that `add_reserved_node` works completely differently.


Parameters:
```
{ "addr": string }
```

Returns:
```
nothing
```

### Method `p2p_disconnect`

Disconnect peer, given its id.


Parameters:
```
{ "peer_id": number }
```

Returns:
```
nothing
```

### Method `p2p_list_banned`

List banned peers and their ban expiry time.


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

### Method `p2p_ban`

Ban a peer by their address for a given amount of time.


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

### Method `p2p_unban`

Unban a banned peer by their IP address.


Parameters:
```
{ "address": string }
```

Returns:
```
nothing
```

### Method `p2p_list_discouraged`

List peers that have been discouraged.

Discouragement is similar to banning, except that inbound connections from such peers
are still allowed.

Peers are discouraged automatically if they misbehave.


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

### Method `p2p_undiscourage`

Undiscourage a previously discouraged peer by their IP address.


Parameters:
```
{ "address": string }
```

Returns:
```
nothing
```

### Method `p2p_get_peer_count`

Get the number of peers connected to this node.


Parameters:
```
{}
```

Returns:
```
number
```

### Method `p2p_get_bind_addresses`

Get p2p bind address(es) of this node.


Parameters:
```
{}
```

Returns:
```
[ string, .. ]
```

### Method `p2p_get_connected_peers`

Get details of connected peers.


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

### Method `p2p_get_reserved_nodes`

Get addresses of reserved nodes.


Parameters:
```
{}
```

Returns:
```
[ string, .. ]
```

### Method `p2p_add_reserved_node`

Add the address to the reserved nodes list.

The node will try to keep connections open to all reserved peers.
A reserved peer is a peer that you trust and you want your node to remain connected to, no matter what they do.


Parameters:
```
{ "addr": string }
```

Returns:
```
nothing
```

### Method `p2p_remove_reserved_node`

Remove the address from the reserved nodes list.

Existing connection to the peer is not closed.


Parameters:
```
{ "addr": string }
```

Returns:
```
nothing
```

### Method `p2p_submit_transaction`

Submits a transaction to mempool, and if it is valid, broadcasts it to the network as well.


Parameters:
```
{
    "tx": hex string,
    "options": { "trust_policy": EITHER OF
         1) "Trusted"
         2) "Untrusted" },
}
```

Returns:
```
nothing
```

## Module `blockprod`

### Method `blockprod_stop_all`

When called, the job manager will be notified to send a signal
to all currently running jobs to stop running to stop block production.


Parameters:
```
{}
```

Returns:
```
number
```

### Method `blockprod_stop_job`

When called, the job manager will be notified to send a signal
to the specified job to stop running.


Parameters:
```
{ "job_id": hex string }
```

Returns:
```
bool
```

### Method `blockprod_generate_block`

Generate a block with the given transactions.

Parameters:
- `input_data`: The input data for block generation, such as staking key.
- `transactions`: The transactions prioritized to be included in the block.
                  Notice that it's the responsibility of the caller to ensure that the transactions are valid.
                  If the transactions are not valid, the block will be rejected and will not be included in the blockchain.
                  It's preferable to use `transaction_ids` instead, where the mempool will ensure that the transactions are valid
                  against the current state of the blockchain.
- `transaction_ids`: The transaction IDs of the transactions to be included in the block from the mempool.
- `packing_strategy`: Whether or not to include transactions from the mempool in the block, other than the ones specified in `transaction_ids`.


Parameters:
```
{
    "input_data": hex string,
    "transactions": [ hex string, .. ],
    "transaction_ids": [ hex string, .. ],
    "packing_strategy": EITHER OF
         1) "FillSpaceFromMempool"
         2) "LeaveEmptySpace",
}
```

Returns:
```
hex string
```

### Method `blockprod_e2e_public_key`

Get the public key to be used for end-to-end encryption.


Parameters:
```
{}
```

Returns:
```
hex string
```

### Method `blockprod_generate_block_e2e`

Same as `generate_block`, but with end-to-end encryption.

The end-to-end encryption helps in protecting the signing key, so that it is much harder
for an eavesdropper to get it with pure http/websocket connection.
The e2e_public_key is the pubic key for end-to-end encryption of the client.


Parameters:
```
{
    "encrypted_input_data": [ number, .. ],
    "e2e_public_key": hex string,
    "transactions": [ hex string, .. ],
    "transaction_ids": [ hex string, .. ],
    "packing_strategy": EITHER OF
         1) "FillSpaceFromMempool"
         2) "LeaveEmptySpace",
}
```

Returns:
```
hex string
```

### Method `blockprod_collect_timestamp_search_data_e2e`

Collect the search data needed by the `timestamp_searcher` module.

See `timestamp_searcher::collect_timestamp_search_data` for the details about
the parameters.


Parameters:
```
{
    "pool_id": hex string,
    "min_height": number,
    "max_height": EITHER OF
         1) number
         2) null,
    "seconds_to_check_for_height": number,
    "all_timestamps_between_blocks": bool,
}
```

Returns:
```
hex string
```

