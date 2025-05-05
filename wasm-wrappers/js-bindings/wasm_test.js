// Use ES module import syntax to import functionality from the module
// that we have compiled.
//
// Note that the `default` import is an initialization function which
// will "boot" the module and make it ready to use. Currently browsers
// don't support natively imported WebAssembly as an ES module, but
// eventually the manual initialization won't be required!
import {
  make_private_key,
  public_key_from_private_key,
  sign_message_for_spending,
  verify_signature_for_spending,
  make_default_account_privkey,
  make_receiving_address,
  make_change_address,
  pubkey_to_pubkeyhash_address,
  make_receiving_address_public_key,
  make_change_address_public_key,
  extended_public_key_from_extended_private_key,
  Network,
  encode_input_for_utxo,
  encode_output_coin_burn,
  encode_output_token_burn,
  encode_transaction,
  encode_witness_no_signature,
  encode_signed_transaction,
  encode_lock_until_height,
  encode_output_create_stake_pool,
  encode_output_token_transfer,
  encode_output_lock_then_transfer,
  encode_output_token_lock_then_transfer,
  encode_stake_pool_data,
  encode_output_htlc,
  encode_witness,
  encode_witness_htlc_secret,
  encode_multisig_challenge,
  encode_witness_htlc_multisig,
  extract_htlc_secret,
  encode_create_order_output,
  encode_input_for_fill_order,
  encode_input_for_conclude_order,
  SignatureHashType,
  encode_input_for_withdraw_from_delegation,
  estimate_transaction_size,
  staking_pool_spend_maturity_block_count,
  get_transaction_id,
  effective_pool_balance,
  Amount,
  TotalSupply,
  FreezableToken,
  encode_output_issue_nft,
  encode_output_issue_fungible_token,
  sign_challenge,
  verify_challenge,
  get_token_id,
  make_transaction_intent_message_to_sign,
  encode_signed_transaction_intent,
  verify_transaction_intent,
  encode_input_for_mint_tokens,
  encode_input_for_unmint_tokens,
  encode_input_for_lock_token_supply,
  encode_input_for_freeze_token,
  TokenUnfreezable,
  encode_input_for_unfreeze_token,
  encode_input_for_change_token_authority,
  encode_input_for_change_token_metadata_uri,
} from "../pkg/wasm_wrappers.js";

function assert_eq_arrays(arr1, arr2) {
  assert(arr1.length == arr2.length, "array lengths are different");

  arr1.forEach((elem, idx) => {
    assert(elem == arr2[idx], `element at index ${idx} is different`);
  });
}

function assert(condition, message) {
  if (!condition) {
    throw Error('Assertion failed: ' + (message || ''));
  }
}

function run_one_test(test_func) {
  console.log(`>> Running ${test_func.name}`);
  test_func();
  console.log(`<< Done running ${test_func.name}`);
}

export async function run_test() {
  // Try signature verification
  const priv_key = make_private_key();
  console.log(`priv key = ${priv_key}`);
  const pub_key = public_key_from_private_key(priv_key);
  console.log(`pub key = ${pub_key}`);
  const message = "Hello, world!";
  const signature = sign_message_for_spending(priv_key, message);
  console.log(`signature = ${signature}`);
  const verified = verify_signature_for_spending(pub_key, signature, message);
  console.log(`verified valid message with correct key = ${verified}`);
  if (!verified) {
    throw new Error("Signature verification failed!");
  }
  const verified_bad = verify_signature_for_spending(
    pub_key,
    signature,
    "bro!"
  );
  if (verified_bad) {
    throw new Error("Invalid message signature verification passed!");
  }

  // Attempt to use a bad private key to get a public key (test returned Result<> object, which will become a string error)
  const bad_priv_key = "bad";
  try {
    public_key_from_private_key(bad_priv_key);
    throw new Error("Invalid private key worked somehow!");
  } catch (e) {
    if (!e.includes("Invalid private key encoding")) {
      throw new Error(
        "Invalid private key resulted in an unexpected error message!"
      );
    }
    console.log("Tested decoding bad private key successfully");
  }

  try {
    const invalid_mnemonic = "asd asd";
    make_default_account_privkey(invalid_mnemonic, Network.Mainnet);
    throw new Error("Invalid mnemonic worked somehow!");
  } catch (e) {
    if (!e.includes("Invalid mnemonic string")) {
      throw e;
    }
    console.log("Tested invalid mnemonic successfully");
  }

  {
    let challenge = sign_challenge(priv_key, message);
    let address = pubkey_to_pubkeyhash_address(pub_key, Network.Testnet);
    let result = verify_challenge(address, Network.Testnet, challenge, message);
    if (!result) {
      throw new Error("Invalid sing and verify challenge");
    }

    const different_priv_key = make_private_key();
    const different_pub_key = public_key_from_private_key(different_priv_key);
    let different_address = pubkey_to_pubkeyhash_address(different_pub_key, Network.Testnet);
    try {
      verify_challenge(different_address, Network.Testnet, challenge, message);
    } catch (e) {
      if (!e.includes("Public key to public key hash mismatch")) {
        throw e;
      }
      console.log("Tested verify with different address successfully");
    }
  }

  try {
    make_receiving_address(bad_priv_key, 0);
    throw new Error("Invalid private key worked somehow!");
  } catch (e) {
    if (!e.includes("Invalid private key encoding")) {
      throw e;
    }
    console.log("Tested decoding bad account private key successfully");
  }

  try {
    make_change_address(bad_priv_key, 0);
    throw new Error("Invalid private key worked somehow!");
  } catch (e) {
    if (!e.includes("Invalid private key encoding")) {
      throw e;
    }
    console.log("Tested decoding bad account private key successfully");
  }

  const mnemonic =
    "walk exile faculty near leg neutral license matrix maple invite cupboard hat opinion excess coffee leopard latin regret document core limb crew dizzy movie";
  {
    const account_private_key = make_default_account_privkey(
      mnemonic,
      Network.Mainnet
    );
    console.log(`acc private key = ${account_private_key}`);

    const extended_public_key = extended_public_key_from_extended_private_key(account_private_key);

    const receiving_privkey = make_receiving_address(account_private_key, 0);
    console.log(`receiving privkey = ${receiving_privkey}`);

    // test bad key index
    try {
      make_receiving_address(account_private_key, 1 << 31);
      throw new Error("Invalid key index worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid key index, MSB bit set")) {
        throw e;
      }
      console.log("Tested invalid key index with set MSB bit successfully");
    }

    const receiving_pubkey = public_key_from_private_key(receiving_privkey);
    const receiving_pubkey2 = make_receiving_address_public_key(extended_public_key, 0);
    assert_eq_arrays(receiving_pubkey, receiving_pubkey2);

    const address = pubkey_to_pubkeyhash_address(
      receiving_pubkey,
      Network.Mainnet
    );
    console.log(`address = ${address}`);
    if (address != "mtc1qyqmdpxk2w42w37qsdj0e8g54ysvnlvpny3svzqx") {
      throw new Error("Incorrect address generated");
    }

    const change_privkey = make_change_address(account_private_key, 0);
    console.log(`change privkey = ${change_privkey}`);

    // test bad key index
    try {
      make_change_address(account_private_key, 1 << 31);
      throw new Error("Invalid key index worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid key index, MSB bit set")) {
        throw e;
      }
      console.log("Tested invalid key index with set MSB bit successfully");
    }

    const change_pubkey = public_key_from_private_key(change_privkey);
    const change_pubkey2 = make_change_address_public_key(extended_public_key, 0);
    assert_eq_arrays(change_pubkey, change_pubkey2);

    const caddress = pubkey_to_pubkeyhash_address(
      change_pubkey,
      Network.Mainnet
    );
    console.log(`address = ${caddress}`);
    if (caddress != "mtc1qxyhrpytqrvjalg2dzw4tdvzt2zz8ps6nyav2n56") {
      throw new Error("Incorrect address generated");
    }
  }

  {
    // Test generating an address for Testnet
    const account_private_key = make_default_account_privkey(
      mnemonic,
      Network.Testnet
    );
    console.log(`acc private key = ${account_private_key}`);

    const receiving_privkey = make_receiving_address(account_private_key, 0);
    console.log(`receiving privkey = ${receiving_privkey}`);

    const receiving_pubkey = public_key_from_private_key(receiving_privkey);
    const address = pubkey_to_pubkeyhash_address(
      receiving_pubkey,
      Network.Testnet
    );
    console.log(`address = ${address}`);
    if (address != "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n") {
      throw new Error("Incorrect address generated");
    }
  }

  {
    const lock_for_blocks = staking_pool_spend_maturity_block_count(
      BigInt(1000)
    );
    console.log(`lock for blocks ${lock_for_blocks}`);
    if (lock_for_blocks != 7200) {
      throw new Error("Incorrect lock for blocks");
    }
  }

  {
    try {
      encode_input_for_utxo("asd", 1);
      throw new Error("Invalid outpoint encoding worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid outpoint ID encoding")) {
        throw e;
      }
      console.log("Tested invalid outpoint ID successfully");
    }
    try {
      encode_input_for_withdraw_from_delegation(
        "invalid delegation id",
        Amount.from_atoms("1"),
        BigInt(1),
        Network.Mainnet
      );
      throw new Error("Invalid delegation id encoding worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid addressable")) {
        throw e;
      }
      console.log("Tested invalid delegation id in account successfully");
    }

    // Test encoding full transaction
    const tx_outpoint = new Uint8Array(33).fill(0);
    const tx_input = encode_input_for_utxo(tx_outpoint, 1);
    const deleg_id =
      "mdelg1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqut3aj8";
    const tx_input2 = encode_input_for_withdraw_from_delegation(
      deleg_id,
      Amount.from_atoms("1"),
      BigInt(1),
      Network.Mainnet
    );
    const inputs = [...tx_input, ...tx_input2];
    const expected_inputs = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
    ];

    assert_eq_arrays(inputs, expected_inputs);

    try {
      get_token_id([], BigInt(1), Network.Testnet);
      throw "Token Id generated without a UTXO input somehow!";
    } catch (e) {
      if (!(e.includes("No UTXO inputs for token id creation") ||
            e.includes("No inputs for token id creation"))) {
        throw e;
      }
      console.log("Tested no UTXO inputs for token ID successfully");
    }

    {
      const expected_token_id =
        "tmltk13cncdptay55g9ajhrkaw0fp46r0tspq9kptul8vj2q7yvd69n4zsl24gea";
      const token_id = get_token_id(inputs, BigInt(1), Network.Testnet);
      console.log(token_id);

      if (token_id != expected_token_id) {
        throw new Error("Different token id");
      }

    }

    const token_id =
      "tmltk15tgfrs49rv88v8utcllqh0nvpaqtgvn26vdxhuner5m6ewg9c3msn9fxns";
    try {
      encode_output_coin_burn(Amount.from_atoms("invalid amount"));
      throw new Error("Invalid value for amount worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid atoms amount")) {
        throw e;
      }
      console.log("Tested invalid amount successfully");
    }
    try {
      encode_output_token_burn(
        Amount.from_atoms("invalid amount"),
        token_id,
        Network.Testnet
      );
      throw new Error("Invalid value for amount worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid atoms amount")) {
        throw e;
      }
      console.log("Tested invalid amount successfully");
    }
    try {
      const invalid_token_id = "asd";
      encode_output_token_burn(
        Amount.from_atoms("100"),
        invalid_token_id,
        Network.Testnet
      );
      throw new Error("Invalid token id worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid addressable")) {
        throw e;
      }
      console.log("Tested invalid token id successfully for token burn");
    }

    const token_burn = encode_output_token_burn(
      Amount.from_atoms("100"),
      token_id,
      Network.Testnet
    );
    const expected_token_burn = [
      2, 2, 162, 208, 145, 194, 165, 27, 14, 118, 31, 139, 199, 254, 11, 190,
      108, 15, 64, 180, 50, 106, 211, 26, 107, 242, 121, 29, 55, 172, 185, 5,
      196, 119, 145, 1,
    ];
    assert_eq_arrays(token_burn, expected_token_burn);

    const address = "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n";

    try {
      const invalid_lock = "invalid lock";
      encode_output_lock_then_transfer(
        Amount.from_atoms("100"),
        address,
        invalid_lock,
        Network.Testnet
      );
      throw new Error("Invalid lock worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid time lock encoding")) {
        throw e;
      }
      console.log("Tested invalid lock successfully");
    }

    try {
      const invalid_lock = "invalid lock";
      encode_output_token_lock_then_transfer(
        Amount.from_atoms("100"),
        address,
        token_id,
        invalid_lock,
        Network.Testnet
      );
      throw new Error("Invalid lock worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid time lock encoding")) {
        throw e;
      }
      console.log("Tested invalid token lock successfully");
    }

    try {
      const invalid_token_id = "asd";
      const lock = encode_lock_until_height(BigInt(100));
      encode_output_token_lock_then_transfer(
        Amount.from_atoms("100"),
        address,
        invalid_token_id,
        lock,
        Network.Testnet
      );
      throw new Error("Invalid token id worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid addressable")) {
        throw e;
      }
      console.log("Tested invalid token id successfully");
    }

    const lock = encode_lock_until_height(BigInt(100));
    const output = encode_output_lock_then_transfer(
      Amount.from_atoms("100"),
      address,
      lock,
      Network.Testnet
    );

    const token_lock_transfer_out = encode_output_token_lock_then_transfer(
      Amount.from_atoms("100"),
      address,
      token_id,
      lock,
      Network.Testnet
    );
    const expected_token_lock_transfer_out = [
      1, 2, 162, 208, 145, 194, 165, 27, 14, 118, 31, 139, 199, 254, 11, 190,
      108, 15, 64, 180, 50, 106, 211, 26, 107, 242, 121, 29, 55, 172, 185, 5,
      196, 119, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91,
      4, 195, 202, 103, 207, 80, 217, 178, 0, 145, 1,
    ];
    assert_eq_arrays(token_lock_transfer_out, expected_token_lock_transfer_out);

    try {
      const invalid_address = "invalid address";
      encode_output_token_transfer(
        Amount.from_atoms("100"),
        invalid_address,
        token_id,
        Network.Testnet
      );
      throw new Error("Invalid address worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid addressable")) {
        throw e;
      }
      console.log(
        "Tested invalid address in encode output token transfer successfully"
      );
    }

    try {
      const invalid_token_id = "invalid token";
      encode_output_token_transfer(
        Amount.from_atoms("100"),
        address,
        invalid_token_id,
        Network.Testnet
      );
      throw new Error("Invalid token id worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid addressable")) {
        throw e;
      }
      console.log(
        "Tested invalid token id successfully in output token transfer"
      );
    }

    const token_transfer_out = encode_output_token_transfer(
      Amount.from_atoms("100"),
      address,
      token_id,
      Network.Testnet
    );
    const expected_token_transfer_out = [
      0, 2, 162, 208, 145, 194, 165, 27, 14, 118, 31, 139, 199, 254, 11, 190,
      108, 15, 64, 180, 50, 106, 211, 26, 107, 242, 121, 29, 55, 172, 185, 5,
      196, 119, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91,
      4, 195, 202, 103, 207, 80, 217, 178,
    ];

    assert_eq_arrays(token_transfer_out, expected_token_transfer_out);

    const vrf_public_key =
      "tvrfpk1qpk0t6np4gyl084fv328h6ahjvwcsaktrzfrs0xeqtrzpp0l7p28knrnn57";

    try {
      const invalid_margin_ratio_per_thousand = 2000;
      encode_stake_pool_data(
        Amount.from_atoms("40000"),
        address,
        vrf_public_key,
        address,
        invalid_margin_ratio_per_thousand,
        Amount.from_atoms("0"),
        Network.Testnet
      );
      throw new Error("Invalid margin_ratio_per_thousand worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid per thousand 2000, valid range is [0, 1000]")) {
        throw e;
      }
      console.log("Tested invalid margin_ratio_per_thousand successfully");
    }

    const pool_data = encode_stake_pool_data(
      Amount.from_atoms("40000"),
      address,
      vrf_public_key,
      address,
      100,
      Amount.from_atoms("0"),
      Network.Testnet
    );
    const expected_pool_data = [
      2, 113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4,
      195, 202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247, 158,
      169, 100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60, 217,
      2, 198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6, 194,
      41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0,
    ];

    assert_eq_arrays(pool_data, expected_pool_data);

    let encoded_fungible_token = encode_output_issue_fungible_token(
      address,
      "XXX",
      "http://uri.com",
      2,
      TotalSupply.Unlimited,
      null,
      FreezableToken.Yes,
      BigInt(1),
      Network.Testnet
    );

    const expected_fungible_token = [
      7, 1, 12, 88, 88, 88, 2, 56, 104, 116,
      116, 112, 58, 47, 47, 117, 114, 105, 46, 99,
      111, 109, 2, 1, 91, 58, 110, 176, 100, 207,
      6, 194, 41, 193, 30, 91, 4, 195, 202, 103,
      207, 80, 217, 178, 1
    ];

    assert_eq_arrays(encoded_fungible_token, expected_fungible_token);

    const account_pubkey = make_default_account_privkey(
      mnemonic,
      Network.Testnet
    );
    const receiving_privkey = make_receiving_address(account_pubkey, 0);
    const receiving_pubkey = public_key_from_private_key(receiving_privkey);

    let encoded_nft = encode_output_issue_nft(
      token_id,
      address,
      "nft",
      "XXX",
      "desc",
      "1234",
      receiving_pubkey,
      "http://uri",
      "http://icon",
      "http://foo",
      BigInt(1),
      Network.Testnet
    );

    const expected_nft_encoding = [
      8, 162, 208, 145, 194, 165, 27, 14, 118, 31, 139, 199,
      254, 11, 190, 108, 15, 64, 180, 50, 106, 211, 26, 107,
      242, 121, 29, 55, 172, 185, 5, 196, 119, 0, 1, 0,
      2, 227, 252, 33, 195, 223, 44, 38, 35, 73, 145, 212,
      180, 49, 115, 4, 150, 204, 250, 205, 123, 131, 201, 114,
      130, 186, 209, 98, 181, 118, 233, 133, 89, 12, 110, 102,
      116, 16, 100, 101, 115, 99, 12, 88, 88, 88, 44, 104,
      116, 116, 112, 58, 47, 47, 105, 99, 111, 110, 40, 104,
      116, 116, 112, 58, 47, 47, 102, 111, 111, 40, 104, 116,
      116, 112, 58, 47, 47, 117, 114, 105, 16, 1, 2, 3,
      4, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193,
      30, 91, 4, 195, 202, 103, 207, 80, 217, 178
    ];

    assert_eq_arrays(encoded_nft, expected_nft_encoding);

    try {
      const invalid_token_id = "asd";
      encode_output_issue_nft(
        invalid_token_id,
        address,
        "nft",
        "XXX",
        "desc",
        "12345",
        undefined,
        undefined,
        undefined,
        undefined,
        BigInt(1),
        Network.Testnet
      );
      throw new Error("Invalid token id worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid addressable")) {
        throw e;
      }
      console.log("Tested invalid token id successfully");
    }

    try {
      const creator_public_key_hash = address;
      encode_output_issue_nft(
        token_id,
        address,
        "nft",
        "XXX",
        "desc",
        "123",
        creator_public_key_hash,
        undefined,
        undefined,
        undefined,
        BigInt(1),
        Network.Testnet
      );
      throw new Error("Invalid creator worked somehow!");
    } catch (e) {
      if (!e.includes("Cannot decode NFT creator as a public key")) {
        throw e;
      }
      console.log("Tested invalid creator successfully");
    }

    try {
      const empty_ticker = "";
      encode_output_issue_nft(
        token_id,
        address,
        "nft",
        empty_ticker,
        "desc",
        "123",
        undefined,
        undefined,
        undefined,
        undefined,
        BigInt(1),
        Network.Testnet
      );
      throw new Error("Invalid ticker worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid ticker length")) {
        throw e;
      }
      console.log("Tested invalid ticker successfully");
    }

    try {
      const empty_name = "";
      encode_output_issue_nft(
        token_id,
        address,
        empty_name,
        "xxx",
        "desc",
        "123",
        undefined,
        undefined,
        undefined,
        undefined,
        BigInt(1),
        Network.Testnet
      );
      throw new Error("Invalid name worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid name length")) {
        throw e;
      }
      console.log("Tested invalid name successfully");
    }

    try {
      const empty_description = "";
      encode_output_issue_nft(
        token_id,
        address,
        "name",
        "XXX",
        empty_description,
        "123",
        undefined,
        undefined,
        undefined,
        undefined,
        BigInt(1),
        Network.Testnet
      );
      throw new Error("Invalid description worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid description length")) {
        throw e;
      }
      console.log("Tested invalid description successfully");
    }

    const pool_id =
      "tpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqza035u";
    try {
      const invalid_pool_data = "invalid pool data";
      encode_output_create_stake_pool(
        pool_id,
        invalid_pool_data,
        Network.Testnet
      );
      throw new Error("Invalid pool data worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid stake pool data encoding")) {
        throw e;
      }
      console.log("Tested invalid pool data successfully");
    }
    const stake_pool_output = encode_output_create_stake_pool(
      pool_id,
      pool_data,
      Network.Testnet
    );
    const outputs = [...output, ...stake_pool_output];

    const expected_outputs = [
      1, 0, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4,
      195, 202, 103, 207, 80, 217, 178, 0, 145, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
      113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4, 195,
      202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247, 158, 169,
      100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60, 217, 2,
      198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6, 194,
      41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0,
    ];

    assert_eq_arrays(outputs, expected_outputs);

    const secret = [0, 229, 233, 72, 110, 22, 64, 36, 69, 188, 238, 51, 130, 168, 185, 241, 73, 48, 120, 151, 140, 45, 46, 39, 50, 207, 18, 50, 243, 30, 115, 93]
    const secret_hash = "b5a48c7780e597de8012346fb30761965248e3f2"

    const htlc_coins_output = encode_output_htlc(
      Amount.from_atoms("40000"),
      undefined,
      secret_hash,
      address,
      address,
      encode_lock_until_height(BigInt(100)),
      Network.Testnet
    );
    console.log("htlc with coins encoding ok");

    const htlc_tokens_output = encode_output_htlc(
      Amount.from_atoms("40000"),
      token_id,
      secret_hash,
      address,
      address,
      encode_lock_until_height(BigInt(100)),
      Network.Testnet
    );
    console.log("htlc with tokens encoding ok");

    const mint_tokens_input = encode_input_for_mint_tokens(
      token_id,
      Amount.from_atoms("100"),
      BigInt(1),
      Network.Testnet
    );
    const expected_mint_tokens_input = [
      2, 4, 0, 162, 208, 145, 194, 165, 27,
      14, 118, 31, 139, 199, 254, 11, 190, 108,
      15, 64, 180, 50, 106, 211, 26, 107, 242,
      121, 29, 55, 172, 185, 5, 196, 119, 145,
      1
    ];

    assert_eq_arrays(mint_tokens_input, expected_mint_tokens_input);
    console.log("mint tokens encoding ok");

    const unmint_tokens_input = encode_input_for_unmint_tokens(
      token_id,
      BigInt(2),
      Network.Testnet
    );
    const expected_unmint_tokens_input = [
      2, 8, 1, 162, 208, 145, 194, 165,
      27, 14, 118, 31, 139, 199, 254, 11,
      190, 108, 15, 64, 180, 50, 106, 211,
      26, 107, 242, 121, 29, 55, 172, 185,
      5, 196, 119
    ];

    assert_eq_arrays(unmint_tokens_input, expected_unmint_tokens_input);
    console.log("unmint tokens encoding ok");

    const lock_token_supply_input = encode_input_for_lock_token_supply(
      token_id,
      BigInt(2),
      Network.Testnet
    );
    const expected_lock_token_supply_input = [
      2, 8, 2, 162, 208, 145, 194, 165,
      27, 14, 118, 31, 139, 199, 254, 11,
      190, 108, 15, 64, 180, 50, 106, 211,
      26, 107, 242, 121, 29, 55, 172, 185,
      5, 196, 119
    ];

    assert_eq_arrays(lock_token_supply_input, expected_lock_token_supply_input);
    console.log("lock token supply encoding ok");

    const freeze_token_input = encode_input_for_freeze_token(
      token_id,
      TokenUnfreezable.Yes,
      BigInt(2),
      Network.Testnet
    );
    const expected_freeze_token_input = [
      2, 8, 3, 162, 208, 145, 194, 165,
      27, 14, 118, 31, 139, 199, 254, 11,
      190, 108, 15, 64, 180, 50, 106, 211,
      26, 107, 242, 121, 29, 55, 172, 185,
      5, 196, 119, 1
    ];

    assert_eq_arrays(freeze_token_input, expected_freeze_token_input);
    console.log("freeze token encoding ok");

    const unfreeze_token_input = encode_input_for_unfreeze_token(
      token_id,
      BigInt(2),
      Network.Testnet
    );
    const expected_unfreeze_token_input = [
      2, 8, 4, 162, 208, 145, 194, 165,
      27, 14, 118, 31, 139, 199, 254, 11,
      190, 108, 15, 64, 180, 50, 106, 211,
      26, 107, 242, 121, 29, 55, 172, 185,
      5, 196, 119
    ];

    assert_eq_arrays(unfreeze_token_input, expected_unfreeze_token_input);
    console.log("unfreeze token encoding ok");

    const change_token_authority_input = encode_input_for_change_token_authority(
      token_id,
      address,
      BigInt(2),
      Network.Testnet
    );
    const expected_change_token_authority_input = [
      2, 8, 5, 162, 208, 145, 194, 165, 27, 14, 118,
      31, 139, 199, 254, 11, 190, 108, 15, 64, 180, 50,
      106, 211, 26, 107, 242, 121, 29, 55, 172, 185, 5,
      196, 119, 1, 91, 58, 110, 176, 100, 207, 6, 194,
      41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217,
      178
    ];

    assert_eq_arrays(change_token_authority_input, expected_change_token_authority_input);
    console.log("change token authority encoding ok");

    const change_token_metadata_uri = encode_input_for_change_token_metadata_uri(
      token_id,
      address,
      BigInt(2),
      Network.Testnet
    );
    const expected_change_token_metadata_uri = [
      2, 8, 8, 162, 208, 145, 194, 165, 27, 14, 118, 31,
      139, 199, 254, 11, 190, 108, 15, 64, 180, 50, 106, 211,
      26, 107, 242, 121, 29, 55, 172, 185, 5, 196, 119, 176,
      116, 109, 116, 49, 113, 57, 100, 110, 53, 109, 52, 115,
      118, 110, 56, 115, 100, 115, 51, 102, 99, 121, 48, 57,
      107, 112, 120, 114, 101, 102, 110, 117, 55, 53, 120, 101,
      107, 103, 114, 53, 119, 97, 51, 110
    ];

    assert_eq_arrays(change_token_metadata_uri, expected_change_token_metadata_uri);
    console.log("change token metadata uri encoding ok");

    const order_output = encode_create_order_output(
      Amount.from_atoms("40000"),
      undefined,
      Amount.from_atoms("10000"),
      token_id,
      address,
      Network.Testnet
    );
    const expected_order_output = [
      11, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41,
      193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178,
      0, 2, 113, 2, 0, 2, 162, 208, 145, 194, 165,
      27, 14, 118, 31, 139, 199, 254, 11, 190, 108, 15,
      64, 180, 50, 106, 211, 26, 107, 242, 121, 29, 55,
      172, 185, 5, 196, 119, 65, 156
    ];

    assert_eq_arrays(order_output, expected_order_output);
    console.log("create order coins for tokens encoding ok");

    const create_order_output_2 = encode_create_order_output(
      Amount.from_atoms("10000"),
      token_id,
      Amount.from_atoms("40000"),
      undefined,
      address,
      Network.Testnet
    );
    const expected_create_order_output_2 = [
      11, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41,
      193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178,
      2, 162, 208, 145, 194, 165, 27, 14, 118, 31, 139,
      199, 254, 11, 190, 108, 15, 64, 180, 50, 106, 211,
      26, 107, 242, 121, 29, 55, 172, 185, 5, 196, 119,
      65, 156, 0, 2, 113, 2, 0
    ];

    assert_eq_arrays(create_order_output_2, expected_create_order_output_2);
    console.log("create order tokens for coins encoding ok");

    const order_id = "tordr1xxt0avjtt4flkq0tnlyphmdm4aaj9vmkx5r2m4g863nw3lgf7nzs7mlkqc";
    const fill_order_input = encode_input_for_fill_order(
      order_id,
      Amount.from_atoms("40000"),
      address,
      BigInt(1),
      Network.Testnet
    );
    const expected_fill_order_input = [
      2, 4, 7, 49, 150, 254, 178, 75, 93, 83, 251,
      1, 235, 159, 200, 27, 237, 187, 175, 123, 34, 179,
      118, 53, 6, 173, 213, 7, 212, 102, 232, 253, 9,
      244, 197, 2, 113, 2, 0, 1, 91, 58, 110, 176,
      100, 207, 6, 194, 41, 193, 30, 91, 4, 195, 202,
      103, 207, 80, 217, 178
    ];

    assert_eq_arrays(fill_order_input, expected_fill_order_input);
    console.log("fill order encoding ok");

    const conclude_order_input = encode_input_for_conclude_order(
      order_id,
      BigInt(1),
      Network.Testnet
    );
    const expected_conclude_order_input = [
      2, 4, 6, 49, 150, 254, 178, 75,
      93, 83, 251, 1, 235, 159, 200, 27,
      237, 187, 175, 123, 34, 179, 118, 53,
      6, 173, 213, 7, 212, 102, 232, 253,
      9, 244, 197
    ];

    assert_eq_arrays(conclude_order_input, expected_conclude_order_input);
    console.log("conclude order encoding ok");

    try {
      const invalid_inputs = "invalid inputs";
      encode_transaction(invalid_inputs, outputs, BigInt(0));
      throw new Error("Invalid inputs worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid transaction input encoding")) {
        throw e;
      }
      console.log("Tested invalid inputs successfully");
    }

    try {
      const invalid_outputs = "invalid outputs";
      encode_transaction(inputs, invalid_outputs, BigInt(0));
      throw new Error("Invalid outputs worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid transaction output encoding")) {
        throw e;
      }
      console.log("Tested invalid outputs successfully");
    }

    const tx = encode_transaction(inputs, outputs, BigInt(0));
    const expected_tx = [
      1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 4, 8, 1, 0, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30,
      91, 4, 195, 202, 103, 207, 80, 217, 178, 0, 145, 1, 3, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 2, 113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91,
      4, 195, 202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247,
      158, 169, 100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60,
      217, 2, 198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6,
      194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0,
    ];
    assert_eq_arrays(tx, expected_tx);
    console.log("tx encoding ok");

    const witness = encode_witness_no_signature();
    const expected_no_signature_witness = [0, 0];
    assert_eq_arrays(witness, expected_no_signature_witness);
    console.log("empty witness encoding ok");

    const opt_utxos = [1, ...output, 1, ...stake_pool_output];

    try {
      const invalid_private_key = "invalid private key";
      encode_witness(
        SignatureHashType.ALL,
        invalid_private_key,
        address,
        tx,
        opt_utxos,
        0,
        Network.Testnet
      );
      throw new Error("Invalid private key worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid private key encoding")) {
        throw e;
      }
      console.log("Tested invalid private key in encode witness successfully");
    }
    try {
      const invalid_address = "invalid address";
      encode_witness(
        SignatureHashType.ALL,
        receiving_privkey,
        invalid_address,
        tx,
        opt_utxos,
        0,
        Network.Testnet
      );
      throw new Error("Invalid address worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid addressable")) {
        throw e;
      }
      console.log("Tested invalid address in encode witness successfully");
    }
    try {
      const invalid_tx = "invalid tx";
      encode_witness(
        SignatureHashType.ALL,
        receiving_privkey,
        address,
        invalid_tx,
        opt_utxos,
        0,
        Network.Testnet
      );
      throw new Error("Invalid transaction worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid transaction encoding")) {
        throw e;
      }
      console.log("Tested invalid transaction in encode witness successfully");
    }
    try {
      // Note: if "invalid utxos" were passed to `encode_witness` directly (i.e. as a string instead
      // of an array), the `inputs: &[u8]` parameter of `encode_witness` would contain 13 zeroes,
      // which would be parsed as 13 `Option::None` and the error would be about an incorrect witness
      // count.
      const invalid_utxos = [...Buffer.from("invalid utxos")]
      encode_witness(
        SignatureHashType.ALL,
        receiving_privkey,
        address,
        tx,
        invalid_utxos,
        0,
        Network.Testnet
      );
      throw new Error("Invalid utxo worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid transaction input encoding")) {
        throw e;
      }
      console.log("Tested invalid utxo in encode witness successfully");
    }
    try {
      const invalid_utxos_count = [0];
      encode_witness(
        SignatureHashType.ALL,
        receiving_privkey,
        address,
        tx,
        invalid_utxos_count,
        0,
        Network.Testnet
      );
      throw new Error("Invalid utxo worked somehow!");
    } catch (e) {
      if (!e.includes("Utxos count does not match inputs count")) {
        throw e;
      }
      console.log("Tested invalid utxo count in encode witness successfully");
    }
    try {
      const invalid_input_idx = 999;
      encode_witness(
        SignatureHashType.ALL,
        receiving_privkey,
        address,
        tx,
        opt_utxos,
        invalid_input_idx,
        Network.Testnet
      );
      throw new Error("Invalid address worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid input index")) {
        throw e;
      }
      console.log("Tested invalid input index in encode witness successfully");
    }
    // all ok
    encode_witness(
      SignatureHashType.ALL,
      receiving_privkey,
      address,
      tx,
      opt_utxos,
      0,
      Network.Testnet
    );

    // as signatures are random, hardcode one so we can test the encodings for the signed transaction
    const random_witness2 = [
      1, 1, 141, 1, 0, 2, 227, 252, 33, 195, 223, 44, 38, 35, 73, 145, 212, 180,
      49, 115, 4, 150, 204, 250, 205, 123, 131, 201, 114, 130, 186, 209, 98,
      181, 118, 233, 133, 89, 0, 99, 87, 109, 227, 15, 21, 164, 83, 151, 14,
      235, 106, 83, 230, 40, 64, 146, 112, 52, 103, 203, 31, 216, 54, 141, 223,
      27, 175, 133, 164, 172, 239, 122, 121, 17, 88, 114, 99, 6, 19, 220, 156,
      167, 40, 17, 211, 196, 45, 209, 111, 170, 161, 2, 254, 122, 169, 127, 235,
      158, 62, 127, 177, 12, 228,
    ];

    try {
      const invalid_witnesses = "invalid witnesses";
      encode_signed_transaction(tx, invalid_witnesses);
      throw new Error("Invalid witnesses worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid transaction witness encoding")) {
        throw e;
      }
      console.log("Tested invalid witnesses successfully");
    }

    try {
      encode_signed_transaction(tx, witness);
      throw new Error("Invalid number of witnesses worked somehow!");
    } catch (e) {
      if (
        !e.includes(
          "The number of signatures does not match the number of inputs"
        )
      ) {
        throw e;
      }
      console.log("Tested invalid number of witnesses successfully");
    }

    try {
      const invalid_tx = "invalid tx";
      encode_signed_transaction(invalid_tx, witness);
      throw new Error("Invalid transaction worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid transaction encoding")) {
        throw e;
      }
      console.log("Tested invalid transaction successfully");
    }

    let witnesses = [...random_witness2, ...random_witness2];
    const signed_tx = encode_signed_transaction(tx, witnesses);
    const expected_signed_tx = [
      1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 4, 8, 1, 0, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30,
      91, 4, 195, 202, 103, 207, 80, 217, 178, 0, 145, 1, 3, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 2, 113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91,
      4, 195, 202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247,
      158, 169, 100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60,
      217, 2, 198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6,
      194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0, 8,
      1, 1, 141, 1, 0, 2, 227, 252, 33, 195, 223, 44, 38, 35, 73, 145, 212, 180,
      49, 115, 4, 150, 204, 250, 205, 123, 131, 201, 114, 130, 186, 209, 98,
      181, 118, 233, 133, 89, 0, 99, 87, 109, 227, 15, 21, 164, 83, 151, 14,
      235, 106, 83, 230, 40, 64, 146, 112, 52, 103, 203, 31, 216, 54, 141, 223,
      27, 175, 133, 164, 172, 239, 122, 121, 17, 88, 114, 99, 6, 19, 220, 156,
      167, 40, 17, 211, 196, 45, 209, 111, 170, 161, 2, 254, 122, 169, 127, 235,
      158, 62, 127, 177, 12, 228, 1, 1, 141, 1, 0, 2, 227, 252, 33, 195, 223,
      44, 38, 35, 73, 145, 212, 180, 49, 115, 4, 150, 204, 250, 205, 123, 131,
      201, 114, 130, 186, 209, 98, 181, 118, 233, 133, 89, 0, 99, 87, 109, 227,
      15, 21, 164, 83, 151, 14, 235, 106, 83, 230, 40, 64, 146, 112, 52, 103,
      203, 31, 216, 54, 141, 223, 27, 175, 133, 164, 172, 239, 122, 121, 17, 88,
      114, 99, 6, 19, 220, 156, 167, 40, 17, 211, 196, 45, 209, 111, 170, 161,
      2, 254, 122, 169, 127, 235, 158, 62, 127, 177, 12, 228,
    ];
    assert_eq_arrays(signed_tx, expected_signed_tx);

    const opt_htlc_utxos = [1, ...htlc_coins_output, 1, ...htlc_tokens_output];
    const htlc_tx = encode_transaction(inputs, outputs, BigInt(0));
    // encode witness with secret
    const witness_with_htlc_secret = encode_witness_htlc_secret(
      SignatureHashType.ALL,
      receiving_privkey,
      address,
      htlc_tx,
      opt_htlc_utxos,
      0,
      secret,
      Network.Testnet
    );
    console.log("Tested encode witness with htlc secret successfully");

    // encode multisig challenge
    const alice_sk = make_private_key();
    const alice_pk = public_key_from_private_key(alice_sk);
    const bob_sk = make_private_key();
    const bob_pk = public_key_from_private_key(bob_sk);
    let challenge = encode_multisig_challenge([...alice_pk, ...bob_pk], 2, Network.Testnet);
    console.log("Tested multisig challenge successfully");

    // encode mutlisig witness
    const witness_with_htlc_multisig_1 = encode_witness_htlc_multisig(
      SignatureHashType.ALL,
      alice_sk,
      0,
      new Uint8Array([]),
      challenge,
      tx,
      opt_htlc_utxos,
      1,
      Network.Testnet
    );
    console.log("Tested encode multisig witness 0 successfully");

    const witness_with_htlc_multisig = encode_witness_htlc_multisig(
      SignatureHashType.ALL,
      bob_sk,
      1,
      witness_with_htlc_multisig_1,
      challenge,
      tx,
      opt_htlc_utxos,
      1,
      Network.Testnet
    );
    console.log("Tested encode multisig witness 1 successfully");

    // encode signed tx with secret and multi
    const htlc_signed_tx = encode_signed_transaction(htlc_tx, [...witness_with_htlc_secret, ...witness_with_htlc_multisig]);
    // extract secret from signed tx
    const secret_extracted = extract_htlc_secret(htlc_signed_tx, true, tx_outpoint, 1);
    assert_eq_arrays(secret, secret_extracted);

    const estimated_size = estimate_transaction_size(
      inputs,
      [address, address],
      outputs,
      Network.Testnet
    );
    if (estimated_size != expected_signed_tx.length) {
      throw new Error("wrong estimated size");
    }
    console.log(
      `estimated size ${estimated_size} vs real ${expected_signed_tx.length}`
    );
  }

  {
    const eff_bal = effective_pool_balance(
      Network.Mainnet,
      Amount.from_atoms("0"),
      Amount.from_atoms("0")
    );
    if (eff_bal.atoms() != "0") {
      throw new Error(`Effective balance test failed ${eff_bal}`);
    }
  }

  {
    const eff_bal = effective_pool_balance(
      Network.Mainnet,
      Amount.from_atoms("4000000000000000"),
      Amount.from_atoms("20000000000000000")
    );
    if (eff_bal.atoms() != "18679147907594054") {
      throw new Error(`Effective balance test failed ${eff_bal}`);
    }
  }

  {
    // capped
    const eff_bal = effective_pool_balance(
      Network.Mainnet,
      Amount.from_atoms("59999080000000000"),
      Amount.from_atoms("59999080000000000")
    );
    if (eff_bal.atoms() != "59999080000000000") {
      throw new Error(`Effective balance test failed ${eff_bal}`);
    }
  }

  {
    // over capped
    const over_capped = Math.floor(Math.random() * 4);
    const capped = 6 + over_capped;
    const eff_bal = effective_pool_balance(
      Network.Mainnet,
      Amount.from_atoms(`${capped}0000000000000000`),
      Amount.from_atoms(`${capped}0000000000000000`)
    );
    if (eff_bal.atoms() != "59999080000000000") {
      throw new Error(`Effective balance test failed ${eff_bal}`);
    }
  }

  run_one_test(test_get_transaction_id);
  run_one_test(test_signed_transaction_intent);
}

function test_get_transaction_id() {
  const tx_bin = [
    1, 0, 4, 0, 0, 255, 93, 154, 148, 57, 14, 233, 114, 8, 211, 26, 165, 195,
    181, 221, 189, 141, 249, 211, 8, 6, 157, 242, 235, 245, 40, 63, 124, 227,
    228, 38, 20, 1, 0, 0, 0, 8, 3, 64, 249, 146, 78, 77, 160, 175, 125, 200,
    197, 190, 113, 169, 201, 224, 89, 98, 199, 191, 78, 249, 97, 39, 253, 231,
    167, 180, 225, 70, 158, 72, 98, 15, 0, 128, 224, 55, 121, 195, 17, 2, 0, 3,
    101, 128, 126, 59, 65, 71, 203, 151, 139, 120, 113, 94, 96, 96, 96, 146,
    248, 157, 199, 105, 88, 110, 152, 69, 104, 80, 189, 59, 68, 156, 135, 180,
    0, 32, 48, 21, 233, 239, 159, 193, 66, 86, 158, 15, 150, 107, 192, 24, 132,
    100, 250, 113, 42, 132, 30, 20, 0, 46, 15, 233, 82, 160, 118, 162, 108, 1,
    229, 57, 197, 240, 206, 186, 146, 122, 184, 248, 245, 95, 39, 74, 247, 57,
    206, 78, 239, 55, 0, 0, 11, 0, 32, 74, 169, 209, 1, 0, 0, 11, 64, 158, 76,
    53, 93, 1, 1, 153, 228, 236, 58, 91, 23, 97, 64, 239, 156, 213, 140, 125,
    53, 121, 253, 176, 236, 178, 26,
  ];

  const tx_signed_bin = [
    1, 0, 4, 0, 0, 255, 93, 154, 148, 57, 14, 233, 114, 8, 211, 26, 165, 195,
    181, 221, 189, 141, 249, 211, 8, 6, 157, 242, 235, 245, 40, 63, 124, 227,
    228, 38, 20, 1, 0, 0, 0, 8, 3, 64, 249, 146, 78, 77, 160, 175, 125, 200,
    197, 190, 113, 169, 201, 224, 89, 98, 199, 191, 78, 249, 97, 39, 253, 231,
    167, 180, 225, 70, 158, 72, 98, 15, 0, 128, 224, 55, 121, 195, 17, 2, 0, 3,
    101, 128, 126, 59, 65, 71, 203, 151, 139, 120, 113, 94, 96, 96, 96, 146,
    248, 157, 199, 105, 88, 110, 152, 69, 104, 80, 189, 59, 68, 156, 135, 180,
    0, 32, 48, 21, 233, 239, 159, 193, 66, 86, 158, 15, 150, 107, 192, 24, 132,
    100, 250, 113, 42, 132, 30, 20, 0, 46, 15, 233, 82, 160, 118, 162, 108, 1,
    229, 57, 197, 240, 206, 186, 146, 122, 184, 248, 245, 95, 39, 74, 247, 57,
    206, 78, 239, 55, 0, 0, 11, 0, 32, 74, 169, 209, 1, 0, 0, 11, 64, 158, 76,
    53, 93, 1, 1, 153, 228, 236, 58, 91, 23, 97, 64, 239, 156, 213, 140, 125,
    53, 121, 253, 176, 236, 178, 26, 4, 1, 1, 141, 1, 0, 2, 237, 221, 0, 59,
    251, 99, 51, 18, 62, 104, 42, 190, 105, 35, 218, 29, 56, 250, 164, 240, 224,
    217, 226, 238, 66, 213, 170, 70, 193, 82, 163, 72, 0, 167, 73, 163, 12, 140,
    156, 51, 105, 108, 228, 7, 252, 20, 94, 188, 152, 36, 225, 123, 119, 141,
    13, 156, 204, 129, 41, 190, 82, 243, 123, 116, 22, 14, 96, 246, 104, 154,
    194, 244, 129, 7, 30, 26, 99, 217, 207, 15, 110, 171, 132, 194, 112, 59, 94,
    159, 34, 156, 216, 24, 140, 224, 146, 237, 212,
  ];

  const expected_tx_id =
    "35a7938c2a2aad5ae324e7d0536de245bf9e439169aa3c16f1492be117e5d0e0";

  {
    const tx_id = get_transaction_id(tx_bin, true);
    if (tx_id != expected_tx_id) {
      throw new Error(
        `Decoded transaction id mismatch: ${tx_id} != ${expected_tx_id}`
      );
    }
  }

  {
    const tx_id = get_transaction_id(tx_bin, false);
    if (tx_id != expected_tx_id) {
      throw new Error(
        `Decoded transaction id mismatch: ${tx_id} != ${expected_tx_id}`
      );
    }
  }

  {
    const tx_id = get_transaction_id(tx_signed_bin, false);
    if (tx_id != expected_tx_id) {
      throw new Error(
        `Decoded transaction id mismatch: ${tx_id} != ${expected_tx_id}`
      );
    }
  }

  {
    try {
      get_transaction_id(tx_signed_bin, true);
      throw new Error("Invalid witnesses worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid transaction encoding")) {
        throw new Error(
          "Invalid transaction encoding resulted in an unexpected error message!"
        );
      }
    }
  }
}

function test_signed_transaction_intent() {
  try {
    const invalid_tx_id = "invalid tx id";
    make_transaction_intent_message_to_sign("intent", invalid_tx_id);
    throw new Error("Invalid tx id worked somehow!");
  } catch (e) {
    if (!e.includes("Error parsing transaction id")) {
      throw e;
    }
  }

  const tx_id = "DFC2BB0CC4C7F3ED3FE682A48EE9F78BCD4962E55E7BC239BD340EC22AFF8657";
  const message = make_transaction_intent_message_to_sign("the intent", tx_id);
  const expected_message = new TextEncoder().encode(
    "<tx_id:dfc2bb0cc4c7f3ed3fe682a48ee9f78bcd4962e55e7bc239bd340ec22aff8657;intent:the intent>");
  assert_eq_arrays(message, expected_message);

  try {
    const invalid_signatures = "invalid signatures";
    encode_signed_transaction_intent(message, invalid_signatures);
    throw new Error("Invalid signatures worked somehow!");
  } catch (e) {
    if (!e.includes("Error decoding a JsValue as an array of arrays of bytes")) {
      throw e;
    }
  }

  {
    const prv_key1 = [
      0, 142, 11, 183, 83, 79, 207, 79, 18, 172, 116, 88, 251, 128, 146, 254, 82,
      156, 229, 110, 160, 187, 104, 237, 182, 59, 95, 108, 203, 22, 138, 173, 147
    ];
    const pubkey_addr1 = "rpmt1qgqqxtunp0gdsysq9g3fke9pesl4w8xg3t7ynssfrvqetae0d9nqn3prq3mdt7";
    const pubkeyhash_addr1 = "rmt1qxtlh84a7fflmeem9g4wtmyp2px42gnxwqprnjlw";
    const prv_key2 = [
      0, 52, 13, 17, 187, 88, 27, 23, 211, 24, 13, 103, 68, 60, 205, 11, 221,
      141, 15, 97, 7, 234, 184, 222, 38, 85, 151, 118, 0, 154, 109, 134, 42
    ];
    const pubkey_addr2 = "rpmt1qgqqylj755w0rlejn3cjadtrhskkzyxqs9nq7mura3z467fkaam7ppxkjr77n7";
    const pubkeyhash_addr2 = "rmt1qx0y7ktusde6d4hf9474z28dwcsys3uk5qxphddl";

    const signature1 = sign_challenge(prv_key1, message);
    const signature2 = sign_challenge(prv_key2, message);

    const signed_intent = encode_signed_transaction_intent(message, [Array.from(signature1), Array.from(signature2)]);

    verify_transaction_intent(message, signed_intent, [pubkey_addr1, pubkeyhash_addr2], Network.Regtest);
    verify_transaction_intent(message, signed_intent, [pubkeyhash_addr1, pubkey_addr2], Network.Regtest);

    try {
      verify_transaction_intent(message, signed_intent, [pubkeyhash_addr2, pubkey_addr1], Network.Regtest);
      throw new Error("Mismatched addresses worked somehow!");
    } catch (e) {
      if (!e.includes("Public key to public key hash mismatch")) {
        throw e;
      }
    }

    const bad_signature1 = sign_challenge(prv_key1, [...message, 123]);
    const bad_signed_intent = encode_signed_transaction_intent(message, [Array.from(bad_signature1), Array.from(signature2)]);

    try {
      verify_transaction_intent(message, bad_signed_intent, [pubkey_addr1, pubkey_addr2], Network.Regtest);
      throw new Error("Bad signature worked somehow!");
    } catch (e) {
      if (!e.includes("Signature verification failed")) {
        throw e;
      }
    }
  }

  {
    // Encode some predefined signatures to ensure stability of the encoding.
    const signature1 = [
      0, 3, 47, 147, 11, 208, 216, 18, 0, 42, 34, 155, 100, 161, 204, 63, 87, 28, 200, 138, 252, 73, 194, 9, 27, 1, 149,
      247, 47, 105, 102, 9, 196, 35, 0, 39, 178, 200, 173, 176, 46, 47, 239, 158, 172, 197, 47, 79, 211, 132, 128, 244,
      14, 233, 201, 16, 104, 217, 125, 222, 7, 28, 131, 135, 238, 49, 90, 92, 189, 165, 162, 198, 61, 220, 5, 246, 6,
      124, 53, 201, 124, 194, 7, 45, 119, 49, 69, 224, 32, 150, 128, 29, 230, 95, 107, 173, 190, 82, 163
    ];
    const signature2 = [
      0, 2, 126, 94, 165, 28, 241, 255, 50, 156, 113, 46, 181, 99, 188, 45, 97, 16, 192, 129, 102, 15, 111, 131, 236,
      69, 93, 121, 54, 239, 119, 224, 132, 214, 0, 145, 218, 82, 46, 32, 182, 94, 12, 204, 233, 111, 75, 242, 206, 57,
      9, 21, 200, 244, 222, 219, 172, 85, 205, 117, 95, 76, 200, 144, 172, 226, 162, 65, 26, 15, 93, 181, 72, 45, 209,
      98, 248, 161, 3, 119, 149, 13, 159, 125, 218, 166, 130, 144, 62, 160, 91, 216, 160, 88, 126, 229, 68, 158, 240
    ];
    const expected_encoded_signed_intent = [
      105, 1, 60, 116, 120, 95, 105, 100, 58, 100, 102, 99, 50, 98, 98, 48, 99, 99, 52, 99, 55, 102, 51, 101, 100, 51,
      102, 101, 54, 56, 50, 97, 52, 56, 101, 101, 57, 102, 55, 56, 98, 99, 100, 52, 57, 54, 50, 101, 53, 53, 101, 55,
      98, 99, 50, 51, 57, 98, 100, 51, 52, 48, 101, 99, 50, 50, 97, 102, 102, 56, 54, 53, 55, 59, 105, 110, 116, 101,
      110, 116, 58, 116, 104, 101, 32, 105, 110, 116, 101, 110, 116, 62, 8, 141, 1, 0, 3, 47, 147, 11, 208, 216, 18,
      0, 42, 34, 155, 100, 161, 204, 63, 87, 28, 200, 138, 252, 73, 194, 9, 27, 1, 149, 247, 47, 105, 102, 9, 196, 35,
      0, 39, 178, 200, 173, 176, 46, 47, 239, 158, 172, 197, 47, 79, 211, 132, 128, 244, 14, 233, 201, 16, 104, 217,
      125, 222, 7, 28, 131, 135, 238, 49, 90, 92, 189, 165, 162, 198, 61, 220, 5, 246, 6, 124, 53, 201, 124, 194, 7, 45,
      119, 49, 69, 224, 32, 150, 128, 29, 230, 95, 107, 173, 190, 82, 163, 141, 1, 0, 2, 126, 94, 165, 28, 241, 255, 50,
      156, 113, 46, 181, 99, 188, 45, 97, 16, 192, 129, 102, 15, 111, 131, 236, 69, 93, 121, 54, 239, 119, 224, 132,
      214, 0, 145, 218, 82, 46, 32, 182, 94, 12, 204, 233, 111, 75, 242, 206, 57, 9, 21, 200, 244, 222, 219, 172, 85,
      205, 117, 95, 76, 200, 144, 172, 226, 162, 65, 26, 15, 93, 181, 72, 45, 209, 98, 248, 161, 3, 119, 149, 13, 159,
      125, 218, 166, 130, 144, 62, 160, 91, 216, 160, 88, 126, 229, 68, 158, 240
    ];

    const encoded_signed_intent =
      encode_signed_transaction_intent(message, [signature1, signature2]);
    assert_eq_arrays(encoded_signed_intent, expected_encoded_signed_intent);
  }
}
