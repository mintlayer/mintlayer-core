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
  encode_witness,
  SignatureHashType,
  encode_input_for_withdraw_from_delegation,
  estimate_transaction_size,
  staking_pool_spend_maturity_block_count,
  get_transaction_id,
  effective_pool_balance,
  Amount,
  encode_output_issue_nft,
} from "../pkg/wasm_wrappers.js";

function assert_eq_arrays(arr1, arr2) {
  if (arr1.length != arr2.length) {
    throw new Error("array lengths are different");
  }

  arr1.forEach((elem, idx) => {
    if (elem != arr2[idx]) {
      throw new Error(`Element at index ${idx} is different`);
    }
  });
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
    const bad_pub_key = public_key_from_private_key(bad_priv_key);
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
    console.log("Tested invalid menemonic successfully");
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
    const account_pubkey = make_default_account_privkey(
      mnemonic,
      Network.Mainnet
    );
    console.log(`acc pubkey = ${account_pubkey}`);

    const receiving_privkey = make_receiving_address(account_pubkey, 0);
    console.log(`receiving privkey = ${receiving_privkey}`);

    // test bad key index
    try {
      make_receiving_address(account_pubkey, 1 << 31);
      throw new Error("Invalid key index worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid key index, MSB bit set")) {
        throw e;
      }
      console.log("Tested invalid key index with set MSB bit successfully");
    }

    const receiving_pubkey = public_key_from_private_key(receiving_privkey);
    const address = pubkey_to_pubkeyhash_address(
      receiving_pubkey,
      Network.Mainnet
    );
    console.log(`address = ${address}`);
    if (address != "mtc1qyqmdpxk2w42w37qsdj0e8g54ysvnlvpny3svzqx") {
      throw new Error("Incorrect address generated");
    }

    const change_privkey = make_change_address(account_pubkey, 0);
    console.log(`receiving privkey = ${change_privkey}`);

    // test bad key index
    try {
      make_change_address(account_pubkey, 1 << 31);
      throw new Error("Invalid key index worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid key index, MSB bit set")) {
        throw e;
      }
      console.log("Tested invalid key index with set MSB bit successfully");
    }

    const change_pubkey = public_key_from_private_key(change_privkey);
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
    const account_pubkey = make_default_account_privkey(
      mnemonic,
      Network.Testnet
    );
    console.log(`acc pubkey = ${account_pubkey}`);

    const receiving_privkey = make_receiving_address(account_pubkey, 0);
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
      if (!e.includes("Invalid addressable encoding")) {
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

    const token_id = "tmltk15tgfrs49rv88v8utcllqh0nvpaqtgvn26vdxhuner5m6ewg9c3msn9fxns";
    try {
      encode_output_coin_burn(Amount.from_atoms("invalid amount"));
      throw new Error("Invalid value for amount worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid amount")) {
        throw e;
      }
      console.log("Tested invalid amount successfully");
    }
    try {
      encode_output_token_burn(Amount.from_atoms("invalid amount"), token_id, Network.Testnet);
      throw new Error("Invalid value for amount worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid amount")) {
        throw e;
      }
      console.log("Tested invalid amount successfully");
    }
    try {
      const invalid_token_id = "asd";
      encode_output_token_burn(Amount.from_atoms("100"), invalid_token_id, Network.Testnet);
      throw new Error("Invalid token id worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid addressable encoding")) {
        throw e;
      }
      console.log("Tested invalid token id successfully for token burn");
    }

    const token_burn = encode_output_token_burn(Amount.from_atoms("100"), token_id, Network.Testnet);
    const expected_token_burn = [
      2, 2, 162, 208, 145, 194, 165, 27,
      14, 118, 31, 139, 199, 254, 11, 190,
      108, 15, 64, 180, 50, 106, 211, 26,
      107, 242, 121, 29, 55, 172, 185, 5,
      196, 119, 145, 1
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
      console.log("Tested invalid lock successfully");
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
      console.log(`err: ${e}`);
      if (!e.includes("Invalid addressable encoding")) {
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
      1, 2, 162, 208, 145, 194, 165, 27, 14, 118, 31,
      139, 199, 254, 11, 190, 108, 15, 64, 180, 50, 106,
      211, 26, 107, 242, 121, 29, 55, 172, 185, 5, 196,
      119, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6,
      194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80,
      217, 178, 0, 145, 1
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
      if (!e.includes("Invalid addressable encoding")) {
        throw e;
      }
      console.log("Tested invalid address in encode output token transfer successfully");
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
      console.log(`err: ${e}`);
      if (!e.includes("Invalid addressable encoding")) {
        throw e;
      }
      console.log("Tested invalid token id successfully in output token transfer");
    }

    const token_transfer_out = encode_output_token_transfer(
      Amount.from_atoms("100"),
      address,
      token_id,
      Network.Testnet
    );
    const expected_token_transfer_out = [
      0, 2, 162, 208, 145, 194, 165, 27, 14, 118, 31,
      139, 199, 254, 11, 190, 108, 15, 64, 180, 50, 106,
      211, 26, 107, 242, 121, 29, 55, 172, 185, 5, 196,
      119, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6,
      194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80,
      217, 178
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
      if (!e.includes("Invalid per thousand 2000 valid range is [0, 1000]")) {
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

    try {
      const invalid_token_id = "asd";
      encode_output_issue_nft(invalid_token_id, address, "nft", "XXX", "desc", "123", undefined, undefined, undefined, undefined, Network.Testnet);
      throw new Error("Invalid token id worked somehow!");
    } catch (e) {
      console.log(`err: ${e}`);
      if (!e.includes("Invalid addressable encoding")) {
        throw e;
      }
      console.log("Tested invalid token id successfully");
    }

    try {
      console.log("Testing invalid creator successfully..");
      const creator_public_key_hash = address;
      encode_output_issue_nft(token_id, address, "nft", "XXX", "desc", "123", creator_public_key_hash, undefined, undefined, undefined, Network.Testnet);
      throw new Error("Invalid creator worked somehow!");
    } catch (e) {
      if (!e.includes("NFT Creator needs to be a public key address")) {
        throw e;
      }
      console.log("Tested invalid creator successfully");
    }

    try {
      console.log("Testing invalid nft ticker successfully..");
      const empty_ticker = "";
      encode_output_issue_nft(token_id, address, "nft", empty_ticker, "desc", "123", undefined, undefined, undefined, undefined, Network.Testnet);
      throw new Error("Invalid ticker worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid ticker length")) {
        throw e;
      }
      console.log("Tested invalid ticker successfully");
    }

    try {
      console.log("Testing invalid nft name successfully..");
      const empty_name = "";
      encode_output_issue_nft(token_id, address, empty_name, "xxx", "desc", "123", undefined, undefined, undefined, undefined, Network.Testnet);
      throw new Error("Invalid name worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid name length")) {
        throw e;
      }
      console.log("Tested invalid name successfully");
    }

    try {
      console.log("Testing invalid nft description successfully..");
      const empty_description = "";
      encode_output_issue_nft(token_id, address, "name", "XXX", empty_description, "123", undefined, undefined, undefined, undefined, Network.Testnet);
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

    try {
      const invalid_inputs = "invalid inputs";
      encode_transaction(invalid_inputs, outputs, BigInt(0));
      throw new Error("Invalid inputs worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid Transaction input encoding")) {
        throw e;
      }
      console.log("Tested invalid inputs successfully");
    }

    try {
      const invalid_outputs = "invalid outputs";
      encode_transaction(inputs, invalid_outputs, BigInt(0));
      throw new Error("Invalid outputs worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid Transaction output encoding")) {
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

    const account_pubkey = make_default_account_privkey(
      mnemonic,
      Network.Testnet
    );
    const receiving_privkey = make_receiving_address(account_pubkey, 0);

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
      if (!e.includes("Invalid addressable encoding")) {
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
      const invalid_utxos = "invalid utxos";
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
      if (!e.includes("Invalid Transaction witness encoding")) {
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
      if (!e.includes("Invalid Transaction witness encoding")) {
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
      if (!e.includes("Invalid Transaction witness encoding")) {
        throw e;
      }
      console.log("Tested invalid utxo in encode witness successfully");
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
      if (!e.includes("Invalid Transaction witness encoding")) {
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
}

// get_transaction_id tests
{
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
          "Invalid transaction encodeing resulted in an unexpected error message!"
        );
      }
    }
  }
}
