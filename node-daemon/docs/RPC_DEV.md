# RPC documentation for Mintlayer node developer functions

Version `0.5.1`.

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

