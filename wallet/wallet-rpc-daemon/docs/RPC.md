# RPC documentation for Mintlayer node wallet

Version `0.3.0`.

## Module `WalletRpc`

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

Parameters:
```
{}
```

Returns:
```
string
```


### Method `wallet_create`

Parameters:
```
{
    "path": string,
    "store_seed_phrase": bool,
    "mnemonic": string OR null,
    "passphrase": string OR null,
}
```

Returns:
```
object
```


### Method `wallet_open`

Parameters:
```
{
    "path": string,
    "password": string OR null,
}
```

Returns:
```
nothing
```


### Method `wallet_close`

Parameters:
```
{}
```

Returns:
```
nothing
```


### Method `wallet_info`

Parameters:
```
{}
```

Returns:
```
{
    "wallet_id": hex string,
    "account_names": [ string OR null, .. ],
}
```


### Method `wallet_sync`

Parameters:
```
{}
```

Returns:
```
nothing
```


### Method `wallet_rescan`

Parameters:
```
{}
```

Returns:
```
nothing
```


### Method `wallet_show_seed_phrase`

Parameters:
```
{}
```

Returns:
```
{
    "seed_phrase": [ string, .. ],
    "passphrase": string OR null,
} OR null
```


### Method `wallet_purge_seed_phrase`

Parameters:
```
{}
```

Returns:
```
{
    "seed_phrase": [ string, .. ],
    "passphrase": string OR null,
} OR null
```


### Method `wallet_set_lookahead_size`

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


### Method `wallet_encrypt_private_keys`

Parameters:
```
{
    "password": string,
}
```

Returns:
```
nothing
```


### Method `wallet_disable_private_keys_encryption`

Parameters:
```
{}
```

Returns:
```
nothing
```


### Method `wallet_unlock_private_keys`

Parameters:
```
{
    "password": string,
}
```

Returns:
```
nothing
```


### Method `wallet_lock_private_keys`

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

Parameters:
```
{
    "name": string OR null,
}
```

Returns:
```
{
    "account": number,
    "name": string OR null,
}
```


### Method `account_rename`

Parameters:
```
{
    "account": number,
    "name": string OR null,
}
```

Returns:
```
{
    "account": number,
    "name": string OR null,
}
```


### Method `address_show`

Parameters:
```
{
    "account": number,
}
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

Parameters:
```
{
    "account": number,
}
```

Returns:
```
{
    "address": bech32 string,
    "index": string,
}
```


### Method `address_reveal_public_key`

Parameters:
```
{
    "account": number,
    "address": string,
}
```

Returns:
```
{
    "public_key_hex": hex string,
    "public_key_address": bech32 string,
}
```


### Method `account_balance`

Parameters:
```
{
    "account": number,
    "with_locked": "Any" OR "Unlocked" OR "Locked" OR null,
}
```

Returns:
```
{
    "coins": decimal string,
    "tokens": { hex string: decimal string, .. },
}
```


### Method `account_utxos`

Parameters:
```
{
    "account": number,
}
```

Returns:
```
[ json, .. ]
```


### Method `node_submit_transaction`

Parameters:
```
{
    "tx": hex string,
    "do_not_store": bool,
    "options": {
        "trust_policy": "Trusted" OR "Untrusted",
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `address_send`

Parameters:
```
{
    "account": number,
    "address": string,
    "amount": decimal string,
    "selected_utxos": [ {
        "id": {
            "BlockReward": hex string,
        } OR {
            "Transaction": hex string,
        },
        "index": number,
    }, .. ],
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `transaction_create_from_cold_input`

Parameters:
```
{
    "account": number,
    "address": string,
    "amount_str": decimal string,
    "selected_utxo": {
        "id": {
            "BlockReward": hex string,
        } OR {
            "Transaction": hex string,
        },
        "index": number,
    },
    "change_address": string OR null,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "hex": hex string,
    "fees": {
        "coins": decimal string,
        "tokens": { hex string: decimal string, .. },
    },
}
```


### Method `transaction_inspect`

Parameters:
```
{
    "transaction": string,
}
```

Returns:
```
{
    "tx": hex string,
    "fees": {
        "coins": decimal string,
        "tokens": { hex string: decimal string, .. },
    } OR null,
    "stats": object,
}
```


### Method `staking_create_pool`

Parameters:
```
{
    "account": number,
    "amount": decimal string,
    "cost_per_block": decimal string,
    "margin_ratio_per_thousand": string,
    "decommission_address": string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `staking_decommission_pool`

Parameters:
```
{
    "account": number,
    "pool_id": string,
    "output_address": string OR null,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `staking_decommission_pool_request`

Parameters:
```
{
    "account": number,
    "pool_id": string,
    "output_address": string OR null,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
hex string
```


### Method `delegation_create`

Parameters:
```
{
    "account": number,
    "address": string,
    "pool_id": string,
    "options": {
        "in_top_x_mb": number,
    },
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

Parameters:
```
{
    "account": number,
    "amount": decimal string,
    "delegation_id": string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `delegation_withdraw`

Parameters:
```
{
    "account": number,
    "address": string,
    "amount": decimal string,
    "delegation_id": string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `staking_start`

Parameters:
```
{
    "account": number,
}
```

Returns:
```
nothing
```


### Method `staking_stop`

Parameters:
```
{
    "account": number,
}
```

Returns:
```
nothing
```


### Method `staking_status`

Parameters:
```
{
    "account": number,
}
```

Returns:
```
"Staking" OR "NotStaking"
```


### Method `staking_list_pool_ids`

Parameters:
```
{
    "account": number,
}
```

Returns:
```
[ object, .. ]
```


### Method `staking_pool_balance`

Parameters:
```
{
    "pool_id": string,
}
```

Returns:
```
{
    "balance": string OR null,
}
```


### Method `delegation_list_ids`

Parameters:
```
{
    "account": number,
}
```

Returns:
```
[ {
    "delegation_id": bech32 string,
    "balance": decimal string,
}, .. ]
```


### Method `staking_list_created_block_ids`

Parameters:
```
{
    "account": number,
}
```

Returns:
```
[ {
    "id": hex string,
    "height": number,
    "pool_id": bech32 string,
}, .. ]
```


### Method `staking_new_vrf_public_key`

Parameters:
```
{
    "account": number,
}
```

Returns:
```
{
    "vrf_public_key": hex string,
    "child_number": number,
    "used": bool,
}
```


### Method `staking_show_legacy_vrf_key`

Parameters:
```
{
    "account": number,
}
```

Returns:
```
{
    "vrf_public_key": hex string,
}
```


### Method `staking_show_vrf_public_keys`

Parameters:
```
{
    "account": number,
}
```

Returns:
```
[ {
    "vrf_public_key": hex string,
    "child_number": number,
    "used": bool,
}, .. ]
```


### Method `token_nft_issue_new`

Parameters:
```
{
    "account": number,
    "destination_address": string,
    "metadata": object,
    "options": {
        "in_top_x_mb": number,
    },
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

Parameters:
```
{
    "account": number,
    "destination_address": string,
    "metadata": object,
    "options": {
        "in_top_x_mb": number,
    },
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

Parameters:
```
{
    "account": number,
    "token_id": string,
    "address": string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `token_mint`

Parameters:
```
{
    "account": number,
    "token_id": string,
    "address": string,
    "amount": decimal string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `token_unmint`

Parameters:
```
{
    "account": number,
    "token_id": string,
    "amount": decimal string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `token_lock_supply`

Parameters:
```
{
    "account_index": number,
    "token_id": string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `token_freeze`

Parameters:
```
{
    "account": number,
    "token_id": string,
    "is_unfreezable": bool,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `token_unfreeze`

Parameters:
```
{
    "account": number,
    "token_id": string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `token_send`

Parameters:
```
{
    "account": number,
    "token_id": string,
    "address": string,
    "amount": decimal string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `address_deposit_data`

Parameters:
```
{
    "account": number,
    "data": string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "tx_id": hex string,
}
```


### Method `node_version`

Parameters:
```
{}
```

Returns:
```
string
```


### Method `node_shutdown`

Parameters:
```
{}
```

Returns:
```
nothing
```


### Method `node_connect_to_peer`

Parameters:
```
{
    "address": string,
}
```

Returns:
```
nothing
```


### Method `node_disconnect_peer`

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


### Method `node_list_banned_peers`

Parameters:
```
{}
```

Returns:
```
[ [
    ip address string,
    {
        "time": [
            secs number,
            nanos number,
        ],
    },
], .. ]
```


### Method `node_ban_peer_address`

Parameters:
```
{
    "address": ip address string,
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


### Method `node_list_discouraged_peers`

Parameters:
```
{}
```

Returns:
```
[ [
    ip address string,
    {
        "time": [
            secs number,
            nanos number,
        ],
    },
], .. ]
```


### Method `node-peer-count`

Parameters:
```
{}
```

Returns:
```
number
```


### Method `node_list_connected_peers`

Parameters:
```
{}
```

Returns:
```
[ object, .. ]
```


### Method `node_list_reserved_peers`

Parameters:
```
{}
```

Returns:
```
[ string, .. ]
```


### Method `node_add_reserved_peer`

Parameters:
```
{
    "address": string,
}
```

Returns:
```
nothing
```


### Method `node_remove_reserved_peer`

Parameters:
```
{
    "address": string,
}
```

Returns:
```
nothing
```


### Method `node_submit_block`

Parameters:
```
{
    "block": hex string,
}
```

Returns:
```
nothing
```


### Method `node_chainstate_info`

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


### Method `transaction_abandon`

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

Parameters:
```
{
    "account": number,
}
```

Returns:
```
[ hex string, .. ]
```


### Method `transaction_list_by_address`

Parameters:
```
{
    "account": number,
    "address": string OR null,
    "limit": number,
}
```

Returns:
```
[ {
    "id": hex string,
    "height": number,
    "timestamp": number,
}, .. ]
```


### Method `transaction_get`

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

Parameters:
```
{
    "account": number,
    "transaction_id": hex string,
}
```

Returns:
```
string
```


### Method `account_sign_raw_transaction`

Parameters:
```
{
    "account": number,
    "raw_tx": string,
    "options": {
        "in_top_x_mb": number,
    },
}
```

Returns:
```
{
    "hex": hex string,
    "is_complete": bool,
}
```


### Method `account_sign_challenge_plain`

Parameters:
```
{
    "account": number,
    "challenge": string,
    "address": string,
}
```

Returns:
```
string
```


### Method `account_sign_challenge_hex`

Parameters:
```
{
    "account": number,
    "challenge": string,
    "address": string,
}
```

Returns:
```
string
```


### Method `verify_challenge_plain`

Parameters:
```
{
    "message": string,
    "signed_challenge": string,
    "address": string,
}
```

Returns:
```
nothing
```


### Method `verify_challenge_hex`

Parameters:
```
{
    "message": string,
    "signed_challenge": string,
    "address": string,
}
```

Returns:
```
nothing
```


### Method `transaction_get_signed_raw`

Parameters:
```
{
    "account": number,
    "transaction_id": hex string,
}
```

Returns:
```
string
```


### Method `transaction_compose`

Parameters:
```
{
    "inputs": [ {
        "id": {
            "BlockReward": hex string,
        } OR {
            "Transaction": hex string,
        },
        "index": number,
    }, .. ],
    "outputs": [ object, .. ],
    "only_transaction": bool,
}
```

Returns:
```
{
    "hex": hex string,
    "fees": {
        "coins": decimal string,
        "tokens": { hex string: decimal string, .. },
    },
}
```


### Method `node_best_block_id`

Parameters:
```
{}
```

Returns:
```
hex string
```


### Method `node_best_block_height`

Parameters:
```
{}
```

Returns:
```
number
```


### Method `node_block_id`

Parameters:
```
{
    "block_height": number,
}
```

Returns:
```
hex string OR null
```


### Method `node_generate_block`

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

Parameters:
```
{
    "block_id": string,
}
```

Returns:
```
string OR null
```


