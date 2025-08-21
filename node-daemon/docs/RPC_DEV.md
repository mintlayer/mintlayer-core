# RPC documentation for Mintlayer node developer functions

Version `1.1.0`.

These functions are used for testing and only enabled in regtest.

## Module `test_functions`

### Method `test_functions_genesis_pool_id`

Parameters:
```
{}
```

Returns:
```
EITHER OF
     1) string
     2) null
```

### Method `test_functions_genesis_private_key`

Parameters:
```
{}
```

Returns:
```
EITHER OF
     1) string
     2) null
```

### Method `test_functions_genesis_public_key`

Parameters:
```
{}
```

Returns:
```
EITHER OF
     1) string
     2) null
```

### Method `test_functions_genesis_vrf_private_key`

Parameters:
```
{}
```

Returns:
```
EITHER OF
     1) string
     2) null
```

### Method `test_functions_genesis_vrf_public_key`

Parameters:
```
{}
```

Returns:
```
EITHER OF
     1) string
     2) null
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
{ "private_key_hex": string }
```

Returns:
```
string
```

### Method `test_functions_public_key_to_public_key_address`

Parameters:
```
{ "public_key_hex": string }
```

Returns:
```
string
```

### Method `test_functions_public_key_to_public_key_hash_address`

Parameters:
```
{ "public_key_hex": string }
```

Returns:
```
string
```

### Method `test_functions_produce_message_challenge_for_arbitrary_message_signature`

Return the actual message that is signed when producing an arbitrary message signature.

Note that the result is returned as a hex-encoded `Vec<u8>`, which is suitable for passing
to `sign_message_with_private_key` and `verify_message_with_public_key`.


Parameters:
```
{ "message_hex": string }
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
{ "private_key_hex": string }
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
    "block_timestamp": { "timestamp": number },
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
    "input_idx": number,
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
{ "address": string }
```

Returns:
```
hex string
```

### Method `test_functions_dehexify_all_addresses`

Parameters:
```
{ "input": string }
```

Returns:
```
string
```

### Method `test_functions_partially_signed_tx_to_signed_tx`

Parameters:
```
{ "input": hex string }
```

Returns:
```
EITHER OF
     1) hex string
     2) null
```

### Method `test_functions_reveal_token_id`

Parameters:
```
{ "token_id": string }
```

Returns:
```
hex string
```

### Method `test_functions_extract_htlc_secret`

Parameters:
```
{
    "signed_tx_hex": string,
    "htlc_outpoint": {
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
    },
}
```

Returns:
```
EITHER OF
     1) string
     2) null
```

