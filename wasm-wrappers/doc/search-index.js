var searchIndex = new Map(JSON.parse('[\
["wasm_wrappers",{"doc":"","t":"PPPPGPPPGPPPGPGPGPPPNNNNNNNNNNNNNNNNNNNNHHHHHHHHHHHHHHHHHHHHCHNNNNNNNNNNNNNNNNNNNNNNNNNHHHHNNNNNHHNNNNNHHNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNHNNNNNGPPPPPPPPPPPPPPPPPNNNNNNNNNNNNNNNNN","n":["ALL","ANYONECANPAY","BlockReward","Fixed","FreezableToken","Lockable","Mainnet","NONE","Network","No","Regtest","SINGLE","SignatureHashType","Signet","SourceId","Testnet","TotalSupply","Transaction","Unlimited","Yes","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","describe","describe","describe","describe","describe","describe_vector","describe_vector","describe_vector","describe_vector","describe_vector","encode_input_for_utxo","encode_input_for_withdraw_from_delegation","encode_lock_for_block_count","encode_lock_for_seconds","encode_lock_until_height","encode_lock_until_time","encode_outpoint_source_id","encode_output_coin_burn","encode_output_create_delegation","encode_output_create_stake_pool","encode_output_data_deposit","encode_output_delegate_staking","encode_output_issue_fungible_token","encode_output_lock_then_transfer","encode_output_transfer","encode_signed_transaction","encode_stake_pool_data","encode_transaction","encode_witness","encode_witness_no_signature","error","estimate_transaction_size","from","from","from","from","from","from_abi","from_abi","from_abi","from_abi","from_abi","into","into","into","into","into","into_abi","into_abi","into_abi","into_abi","into_abi","is_none","is_none","is_none","is_none","is_none","make_change_address","make_default_account_privkey","make_private_key","make_receiving_address","none","none","none","none","none","pubkey_to_pubkeyhash_address","public_key_from_private_key","return_abi","return_abi","return_abi","return_abi","return_abi","sign_message_for_spending","staking_pool_spend_maturity_block_count","try_as_ref","try_as_ref","try_as_ref","try_as_ref","try_as_ref","try_from","try_from","try_from","try_from","try_from","try_from_js_value","try_from_js_value","try_from_js_value","try_from_js_value","try_from_js_value","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","vector_from_abi","vector_from_abi","vector_from_abi","vector_from_abi","vector_from_abi","vector_into_abi","vector_into_abi","vector_into_abi","vector_into_abi","vector_into_abi","verify_signature_for_spending","vzip","vzip","vzip","vzip","vzip","Error","InvalidAddressable","InvalidAmount","InvalidInput","InvalidKeyIndex","InvalidMnemonic","InvalidOutpointId","InvalidOutput","InvalidPerThousedns","InvalidPrivateKeyEncoding","InvalidPublicKeyEncoding","InvalidSignatureEncoding","InvalidStakePoolData","InvalidTimeLock","InvalidTransaction","InvalidWitness","InvalidWitnessCount","SignatureError","borrow","borrow_mut","clone","clone_into","fmt","fmt","from","from","into","source","to_owned","to_string","try_as_ref","try_from","try_into","type_id","vzip"],"q":[[0,"wasm_wrappers"],[146,"wasm_wrappers::error"],[181,"alloc::vec"],[182,"core::result"],[183,"alloc::string"],[184,"core::option"],[185,"wasm_bindgen"],[186,"core::any"],[187,"alloc::boxed"],[188,"core::fmt"],[189,"core::fmt"],[190,"core::error"]],"d":["","","","On issuance, the total number of coins is fixed","Indicates whether a token can be frozen","Can be issued with no limit, but then can be locked to …","","","","","","","","","A utxo can either come from a transaction or a block …","","The token supply of a specific token, set on issuance","","Unlimited supply, no limits except for numeric limits due …","","","","","","","","","","","","","","","","","","","","","","Given an output source id as bytes, and an output index, …","Given a delegation id, an amount and a network type …","Given a number of blocks, this function returns the output …","Given a number of clock seconds, this function returns the …","Given a block height, this function returns the output …","Given a timestamp represented by as unix timestamp, i.e., …","A utxo can either come from a transaction or a block …","Given an amount, this function creates an output (as …","Given a pool id as string, an owner address and a network …","Given a pool id, staking data as bytes and the network …","Given data to be deposited in the blockchain, this …","Given a delegation id (as string, in address form), an …","Given the parameters needed to issue a fungible token, and …","Given a valid receiving address, and a locking rule as …","Given a destination address, an amount and a network type …","Given an unsigned transaction, and signatures, this …","This function returns the staking pool data needed to …","Given inputs as bytes, outputs as bytes, and flags …","Given a private key, inputs and an input number to sign, …","Encode an input witness of the variant that contains no …","","Given inputs, outputs and utxos (each encoded as …","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","Returns the argument unchanged.","","","","","","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","Calls <code>U::from(self)</code>.","","","","","","","","","","","From an extended private key create a change private key …","Create the default account’s extended private key for a …","Generates a new, random private key from entropy","From an extended private key create a receiving private …","","","","","","Given a public key (as bytes) and a network type (mainnet, …","Given a private key, as bytes, return the bytes of the …","","","","","","Given a message and a private key, sign the message with …","Given the current block height and a network type …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Given a digital signature, a public key and a message. …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Returns the argument unchanged.","","Calls <code>U::from(self)</code>.","","","","","","","",""],"i":[15,15,11,12,0,12,10,15,0,13,10,15,0,10,0,10,0,11,12,13,10,13,12,11,15,10,13,12,11,15,10,13,12,11,15,10,13,12,11,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10,13,12,11,15,10,13,12,11,15,10,13,12,11,15,10,13,12,11,15,10,13,12,11,15,0,0,0,0,10,13,12,11,15,0,0,10,13,12,11,15,0,0,10,13,12,11,15,10,13,12,11,15,10,13,12,11,15,10,13,12,11,15,10,13,12,11,15,10,13,12,11,15,10,13,12,11,15,0,10,13,12,11,15,0,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6],"f":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[[],1],[[],1],[[],1],[[],1],[[],1],[[],1],[[],1],[[],1],[[],1],[[],1],[[[3,[2]],4],[[7,[[5,[2]],6]]]],[[8,8,9,10],[[7,[[5,[2]],6]]]],[9,[[5,[2]]]],[9,[[5,[2]]]],[9,[[5,[2]]]],[9,[[5,[2]]]],[[[3,[2]],11],[[5,[2]]]],[8,[[7,[[5,[2]],6]]]],[[8,8,10],[[7,[[5,[2]],6]]]],[[8,[3,[2]],10],[[7,[[5,[2]],6]]]],[[[3,[2]]],[[7,[[5,[2]],6]]]],[[8,8,10],[[7,[[5,[2]],6]]]],[[8,[3,[2]],[3,[2]],2,12,8,13,10],[[7,[[5,[2]],6]]]],[[8,8,[3,[2]],10],[[7,[[5,[2]],6]]]],[[8,8,10],[[7,[[5,[2]],6]]]],[[[3,[2]],[3,[2]]],[[7,[[5,[2]],6]]]],[[8,8,8,8,14,8,10],[[7,[[5,[2]],6]]]],[[[3,[2]],[3,[2]],9],[[7,[[5,[2]],6]]]],[[15,[3,[2]],8,[3,[2]],[3,[2]],4,10],[[7,[[5,[2]],6]]]],[[],[[5,[2]]]],0,[[[3,[2]],[3,[2]],[3,[2]]],[[7,[16,6]]]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[-1,-1,[]],[4,10],[4,13],[4,12],[4,11],[4,15],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[10,4],[13,4],[12,4],[11,4],[15,4],[4,17],[4,17],[4,17],[4,17],[4,17],[[[3,[2]],4],[[7,[[5,[2]],6]]]],[[8,10],[[7,[[5,[2]],6]]]],[[],[[5,[2]]]],[[[3,[2]],4],[[7,[[5,[2]],6]]]],[[],-1,[]],[[],-1,[]],[[],-1,[]],[[],-1,[]],[[],-1,[]],[[[3,[2]],10],[[7,[18,6]]]],[[[3,[2]]],[[7,[[5,[2]],6]]]],[-1,[],[]],[-1,[],[]],[-1,[],[]],[-1,[],[]],[-1,[],[]],[[[3,[2]],[3,[2]]],[[7,[[5,[2]],6]]]],[[9,10],9],[-1,[[19,[-2]]],[],[]],[-1,[[19,[-2]]],[],[]],[-1,[[19,[-2]]],[],[]],[-1,[[19,[-2]]],[],[]],[-1,[[19,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[20,[[7,[10]]]],[20,[[7,[13]]]],[20,[[7,[12]]]],[20,[[7,[11]]]],[20,[[7,[15]]]],[-1,[[7,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[-1,21,[]],[-1,21,[]],[-1,21,[]],[-1,21,[]],[-1,21,[]],[-1,[[22,[[3,[10]]]]],[]],[-1,[[22,[[3,[13]]]]],[]],[-1,[[22,[[3,[12]]]]],[]],[-1,[[22,[[3,[11]]]]],[]],[-1,[[22,[[3,[15]]]]],[]],[[[22,[[3,[10]]]]],-1,[]],[[[22,[[3,[13]]]]],-1,[]],[[[22,[[3,[12]]]]],-1,[]],[[[22,[[3,[11]]]]],-1,[]],[[[22,[[3,[15]]]]],-1,[]],[[[3,[2]],[3,[2]],[3,[2]]],[[7,[17,6]]]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],[-1,-2,[],[]],0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,[-1,-2,[],[]],[-1,-2,[],[]],[6,6],[[-1,-2],1,[],[]],[[6,23],24],[[6,23],24],[-1,-1,[]],[25,6],[-1,-2,[],[]],[6,[[19,[26]]]],[-1,-2,[],[]],[-1,18,[]],[-1,[[19,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[-1,[[7,[-2]]],[],[]],[-1,21,[]],[-1,-2,[],[]]],"c":[],"p":[[1,"tuple"],[1,"u8"],[1,"slice"],[1,"u32"],[5,"Vec",181],[6,"Error",146],[6,"Result",182],[1,"str"],[1,"u64"],[6,"Network",0],[6,"SourceId",0],[6,"TotalSupply",0],[6,"FreezableToken",0],[1,"u16"],[6,"SignatureHashType",0],[1,"usize"],[1,"bool"],[5,"String",183],[6,"Option",184],[5,"JsValue",185],[5,"TypeId",186],[5,"Box",187],[5,"Formatter",188],[8,"Result",188],[6,"SignatureError",189],[10,"Error",190]],"b":[[168,"impl-Display-for-Error"],[169,"impl-Debug-for-Error"]]}]\
]'));
if (typeof exports !== 'undefined') exports.searchIndex = searchIndex;
else if (window.initSearch) window.initSearch(searchIndex);