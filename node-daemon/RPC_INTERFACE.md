# RPC documentation for Mintlayer node

Version `0.3.0`.

## Module `node`

RPC methods controlling the node.


### Method `node_shutdown`

Order the node to shutdown


Parameters:
```
{}
```

Returns:
```
nothing
```


### Method `node_version`

Get node software version


Parameters:
```
{}
```

Returns:
```
string
```


### Method `node_set_mock_time`

Set mock time for the node (for testing purposes only)


Parameters:
```
{
    "time": number,
}
```

Returns:
```
nothing
```


## Module `chainstate`

### Method `chainstate_best_block_id`

Get the best block ID


Parameters:
```
{}
```

Returns:
```
hex string
```


### Method `chainstate_block_id_at_height`

Get block ID at given height in the mainchain


Parameters:
```
{
    "height": number,
}
```

Returns:
```
hex string OR null
```


### Method `chainstate_get_block`

Returns a hex-encoded serialized block with the given id.


Parameters:
```
{
    "id": hex string,
}
```

Returns:
```
hex string OR null
```


### Method `chainstate_get_block_json`

Returns a json-encoded serialized block with the given id.


Parameters:
```
{
    "id": hex string,
}
```

Returns:
```
json OR null
```


### Method `chainstate_get_mainchain_blocks`

Returns a hex-encoded serialized blocks from the mainchain starting from a given block height.


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


### Method `chainstate_get_utxo`

Returns the TxOutput for a specified UtxoOutPoint.


Parameters:
```
{
    "outpoint": {
        "id": {
            "BlockReward": hex string,
        } OR {
            "Transaction": hex string,
        },
        "index": number,
    },
}
```

Returns:
```
object OR null
```


### Method `chainstate_submit_block`

Submit a block to be included in the chain


Parameters:
```
{
    "block_hex": hex string,
}
```

Returns:
```
nothing
```


### Method `chainstate_invalidate_block`

Invalidate the specified block and its descendants.


Parameters:
```
{
    "id": hex string,
}
```

Returns:
```
nothing
```


### Method `chainstate_reset_block_failure_flags`

Reset failure flags for the specified block and its descendants.


Parameters:
```
{
    "id": hex string,
}
```

Returns:
```
nothing
```


### Method `chainstate_block_height_in_main_chain`

Get block height in main chain


Parameters:
```
{
    "block_id": hex string,
}
```

Returns:
```
number OR null
```


### Method `chainstate_best_block_height`

Get best block height in main chain


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
Returns None if no block indexes are found and therefore the last common ancestor is unknown.


Parameters:
```
{
    "first_block": hex string,
    "second_block": hex string,
}
```

Returns:
```
[
    hex string,
    number,
] OR null
```


### Method `chainstate_stake_pool_balance`

Parameters:
```
{
    "pool_id": hex string,
}
```

Returns:
```
{
    "val": number,
} OR null
```


### Method `chainstate_staker_balance`

Parameters:
```
{
    "pool_id": hex string,
}
```

Returns:
```
{
    "val": number,
} OR null
```


### Method `chainstate_delegation_share`

Parameters:
```
{
    "pool_id": hex string,
    "delegation_id": hex string,
}
```

Returns:
```
{
    "val": number,
} OR null
```


### Method `chainstate_token_info`

Get token information


Parameters:
```
{
    "token_id": hex string,
}
```

Returns:
```
{
    "FungibleToken": object,
} OR {
    "NonFungibleToken": object,
} OR null
```


### Method `chainstate_export_bootstrap_file`

Write blocks to disk


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

Reads blocks from disk


Parameters:
```
{
    "file_path": string,
}
```

Returns:
```
nothing
```


### Method `chainstate_info`

Return information about the chain.


Parameters:
```
{}
```

Returns:
```
{
    "best_block_height": number,
    "best_block_id": hex string,
    "best_block_timestamp": number,
    "median_time": number,
    "is_initial_block_download": bool,
}
```


### Subscription `chainstate_subscribe_events`

Parameters:
```
{}
```

Produces:
```
{
    "NewTip": {
        "id": hex string,
        "height": number,
    },
}
```

Unsubscribe using `chainstate_unsubscribe_events`.

## Module `mempool`

### Method `mempool_contains_tx`

Parameters:
```
{
    "tx_id": hex string,
}
```

Returns:
```
bool
```


### Method `mempool_contains_orphan_tx`

Parameters:
```
{
    "tx_id": hex string,
}
```

Returns:
```
bool
```


### Method `mempool_get_transaction`

Parameters:
```
{
    "tx_id": hex string,
}
```

Returns:
```
{
    "id": hex string,
    "status": string,
    "transaction": hex string,
} OR null
```


### Method `mempool_transactions`

Get all mempool transaction IDs


Parameters:
```
{}
```

Returns:
```
[ hex string, .. ]
```


### Method `mempool_submit_transaction`

Parameters:
```
{
    "tx": hex string,
    "options": {
        "trust_policy": "trusted" OR "untrusted" (default),
    },
}
```

Returns:
```
nothing
```


### Method `mempool_local_best_block_id`

Parameters:
```
{}
```

Returns:
```
hex string
```


### Method `mempool_memory_usage`

Parameters:
```
{}
```

Returns:
```
number
```


### Method `mempool_get_max_size`

Parameters:
```
{}
```

Returns:
```
number
```


### Method `mempool_set_max_size`

Parameters:
```
{
    "max_size": number,
}
```

Returns:
```
nothing
```


### Method `mempool_get_fee_rate`

Parameters:
```
{
    "in_top_x_mb": number,
}
```

Returns:
```
{
    "amount_per_kb": number,
}
```


### Method `mempool_get_fee_rate_points`

Parameters:
```
{}
```

Returns:
```
[ [
    number,
    {
        "amount_per_kb": number,
    },
], .. ]
```


## Module `p2p`

### Method `p2p_connect`

Try to connect to a remote node (just once).
For persistent connections `add_reserved_node` should be used.


Parameters:
```
{
    "addr": string,
}
```

Returns:
```
nothing
```


### Method `p2p_disconnect`

Disconnect peer


Parameters:
```
{
    "peer_id": number,
}
```

Returns:
```
nothing
```


### Method `p2p_list_banned`

Parameters:
```
{}
```

Returns:
```
[ [
    ip address string,
    {
        "time": {
            "secs": number,
            "nanos": number,
        },
    },
], .. ]
```


### Method `p2p_ban`

Parameters:
```
{
    "address": ip address string,
    "duration": {
        "secs": number,
        "nanos": number,
    },
}
```

Returns:
```
nothing
```


### Method `p2p_unban`

Parameters:
```
{
    "address": ip address string,
}
```

Returns:
```
nothing
```


### Method `p2p_list_discouraged`

Parameters:
```
{}
```

Returns:
```
[ [
    ip address string,
    {
        "time": {
            "secs": number,
            "nanos": number,
        },
    },
], .. ]
```


### Method `p2p_get_peer_count`

Get the number of peers


Parameters:
```
{}
```

Returns:
```
number
```


### Method `p2p_get_bind_addresses`

Get bind address of the local node


Parameters:
```
{}
```

Returns:
```
[ string, .. ]
```


### Method `p2p_get_connected_peers`

Get details of connected peers


Parameters:
```
{}
```

Returns:
```
[ object, .. ]
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


Parameters:
```
{
    "addr": string,
}
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
{
    "addr": string,
}
```

Returns:
```
nothing
```


### Method `p2p_submit_transaction`

Submits a transaction to mempool, and if it is valid, broadcasts it to the network.


Parameters:
```
{
    "tx": hex string,
    "options": {
        "trust_policy": "trusted" OR "untrusted" (default),
    },
}
```

Returns:
```
nothing
```


## Module `blockprod`

### Method `blockprod_stop_all`

When called, the job manager will be notified to send a signal
to all currently running jobs to stop running


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
to the specified job to stop running


Parameters:
```
{
    "job_id": hex string,
}
```

Returns:
```
bool
```


### Method `blockprod_generate_block`

Generate a block with the given transactions

If `transactions` is `None`, the block will be generated with
available transactions in the mempool


Parameters:
```
{
    "input_data": hex string,
    "transactions": [ hex string, .. ],
    "transaction_ids": [ hex string, .. ],
    "packing_strategy": "FillSpaceFromMempool" OR "LeaveEmptySpace",
}
```

Returns:
```
hex string
```


### Method `blockprod_e2e_public_key`

Parameters:
```
{}
```

Returns:
```
hex string
```


### Method `blockprod_generate_block_e2e`

Parameters:
```
{
    "encrypted_input_data": [ number, .. ],
    "public_key": hex string,
    "transactions": [ hex string, .. ],
    "transaction_ids": [ hex string, .. ],
    "packing_strategy": "FillSpaceFromMempool" OR "LeaveEmptySpace",
}
```

Returns:
```
hex string
```


## Module `test_functions`

### Method `test_functions_genesis_pool_id`

Parameters:
```
{}
```

Returns:
```
string OR null
```


### Method `test_functions_genesis_private_key`

Parameters:
```
{}
```

Returns:
```
string OR null
```


### Method `test_functions_genesis_public_key`

Parameters:
```
{}
```

Returns:
```
string OR null
```


### Method `test_functions_genesis_vrf_private_key`

Parameters:
```
{}
```

Returns:
```
string OR null
```


### Method `test_functions_genesis_vrf_public_key`

Parameters:
```
{}
```

Returns:
```
string OR null
```


### Method `test_functions_new_private_key`

Parameters:
```
{}
```

Returns:
```
string
```


### Method `test_functions_public_key_from_private_key`

Parameters:
```
{
    "private_key_hex": string,
}
```

Returns:
```
string
```


### Method `test_functions_sign_message_with_private_key`

Parameters:
```
{
    "private_key_hex": string,
    "message_hex": string,
}
```

Returns:
```
string
```


### Method `test_functions_verify_message_with_public_key`

Parameters:
```
{
    "public_key_hex": string,
    "message_hex": string,
    "signature_hex": string,
}
```

Returns:
```
bool
```


### Method `test_functions_new_vrf_private_key`

Parameters:
```
{}
```

Returns:
```
string
```


### Method `test_functions_vrf_public_key_from_private_key`

Parameters:
```
{
    "private_key_hex": string,
}
```

Returns:
```
string
```


### Method `test_functions_sign_message_with_vrf_private_key`

Parameters:
```
{
    "private_key_hex": string,
    "epoch_index": number,
    "random_seed": string,
    "block_timestamp": number,
}
```

Returns:
```
string
```


### Method `test_functions_verify_then_get_vrf_output`

Parameters:
```
{
    "epoch_index": number,
    "random_seed": string,
    "vrf_data": string,
    "vrf_public_key": string,
    "block_timestamp": number,
}
```

Returns:
```
string
```


### Method `test_functions_generate_transactions`

Parameters:
```
{
    "input_tx_id": hex string,
    "num_transactions": number,
    "amount_to_spend": number,
    "fee_per_tx": number,
}
```

Returns:
```
[ hex string, .. ]
```


### Method `test_functions_address_to_destination`

Parameters:
```
{
    "address": string,
}
```

Returns:
```
hex string
```


