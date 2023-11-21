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
  sign_message,
  verify_signature,
  make_default_account_privkey,
  make_receiving_address,
  pubkey_to_string,
  Network,
  encode_input_utxo,
  encode_output_burn,
  encode_transaction,
  encode_witness_no_signature,
  encode_signed_transaction,
  encode_lock_until_height,
  encode_output_create_stake_pool,
  encode_output_lock_then_transfer,
  encode_stake_pool_data,
  encode_witness,
  SignatureHashType,
} from "../pkg/wasm_crypto.js";

function assert_eq_arrays(arr1, arr2) {
  if (arr1.length != arr2.length) {
    throw new Error("array lengths are different");
  }

  arr1.forEach((elem, idx) => {
    if (elem != arr2[idx]) {
      throw new Error(`Element at index ${idx} is different`)
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
  const signature = sign_message(priv_key, message);
  console.log(`signature = ${signature}`);
  const verified = verify_signature(pub_key, signature, message);
  console.log(`verified valid message with correct key = ${verified}`);
  if (!verified) {
    throw new Error("Signature verification failed!");
  }
  const verified_bad = verify_signature(pub_key, signature, "bro!");
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
    throw new Error("Invalid public key worked somehow!");
  } catch (e) {
    if (!e.includes("Invalid public key encoding")) {
      throw e;
    }
    console.log("Tested decoding bad account public key successfully");
  }

  const mnemonic = "walk exile faculty near leg neutral license matrix maple invite cupboard hat opinion excess coffee leopard latin regret document core limb crew dizzy movie";
  {
    const account_pubkey = make_default_account_privkey(mnemonic, Network.Mainnet);
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
    const address = pubkey_to_string(receiving_pubkey, Network.Mainnet);
    console.log(`address = ${address}`);
    if (address != "mtc1qyqmdpxk2w42w37qsdj0e8g54ysvnlvpny3svzqx") {
      throw new Error("Incorrect address generated");
    }
  }


  {
    // Test generating an address for Testnet
    const account_pubkey = make_default_account_privkey(mnemonic, Network.Testnet);
    console.log(`acc pubkey = ${account_pubkey}`);

    const receiving_privkey = make_receiving_address(account_pubkey, 0);
    console.log(`receiving privkey = ${receiving_privkey}`);

    const receiving_pubkey = public_key_from_private_key(receiving_privkey);
    const address = pubkey_to_string(receiving_pubkey, Network.Testnet);
    console.log(`address = ${address}`);
    if (address != "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n") {
      throw new Error("Incorrect address generated");
    }
  }

  {
    try {
      encode_input_utxo("asd", 1);
      throw new Error("Invalid outpoint encoding worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid outpoint ID encoding")) {
        throw e;
      }
      console.log("Tested invalid outpoint ID successfully");
    }
    // Test encoding full transaction
    const tx_outpoint = (new Uint8Array(33)).fill(0);
    const tx_input = encode_input_utxo(tx_outpoint, 1);
    const tx_input2 = encode_input_utxo(tx_outpoint, 2);
    const inputs = [...tx_input, ...tx_input2];
    const expected_inputs = [
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      2, 0, 0, 0
    ];

    assert_eq_arrays(inputs, expected_inputs);

    try {
      encode_output_burn("invalid amount");
      throw new Error("Invalid value for amount worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid amount")) {
        throw e;
      }
      console.log("Tested invalid amount successfully");
    }

    const address = "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n";

    try {
      const invalid_lock = "invalid lock";
      encode_output_lock_then_transfer("100", address, invalid_lock, Network.Testnet);
      throw new Error("Invalid lock worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid time lock encoding")) {
        throw e;
      }
      console.log("Tested invalid lock successfully");
    }

    const lock = encode_lock_until_height(BigInt(100));
    const output = encode_output_lock_then_transfer("100", address, lock, Network.Testnet);

    const vrf_public_key = "tvrfpk1qpk0t6np4gyl084fv328h6ahjvwcsaktrzfrs0xeqtrzpp0l7p28knrnn57";

    try {
      const invalid_margin_ratio_per_thousand = 2000;
      encode_stake_pool_data("40000", address, vrf_public_key, address, invalid_margin_ratio_per_thousand, "0", Network.Testnet);
      throw new Error("Invalid margin_ratio_per_thousand worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid per thousand 2000 valid range is [0, 1000]")) {
        throw e;
      }
      console.log("Tested invalid margin_ratio_per_thousand successfully");
    }

    const pool_data = encode_stake_pool_data("40000", address, vrf_public_key, address, 100, "0", Network.Testnet);
    const expected_pool_data = [
      2, 113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6,
      194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217,
      178, 0, 108, 245, 234, 97, 170, 9, 247, 158, 169, 100,
      84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56,
      60, 217, 2, 198, 32, 133, 255, 240, 84, 123, 1, 91,
      58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4,
      195, 202, 103, 207, 80, 217, 178, 100, 0, 0
    ];

    assert_eq_arrays(pool_data, expected_pool_data)

    const pool_id = "tpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqza035u";
    try {
      const invalid_pool_data = "invalid pool data";
      encode_output_create_stake_pool(pool_id, invalid_pool_data, Network.Testnet);
      throw new Error("Invalid pool data worked somehow!");
    } catch (e) {
      if (!e.includes("Invalid stake pool data encoding")) {
        throw e;
      }
      console.log("Tested invalid pool data successfully");
    }
    const stake_pool_output = encode_output_create_stake_pool(pool_id, pool_data, Network.Testnet);
    const outputs = [...output, ...stake_pool_output];

    const expected_outputs = [1, 0, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6,
      194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 0, 145, 1, 3,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 2, 113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194,
      41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97,
      170, 9, 247, 158, 169, 100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24,
      146, 56, 60, 217, 2, 198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176,
      100, 207, 6, 194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0];

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
    const expected_tx = [1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 8, 1, 0, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 0, 145, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247, 158, 169, 100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60, 217, 2, 198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0];
    assert_eq_arrays(tx, expected_tx);


    const witness = encode_witness_no_signature();
    const expected_no_signature_witness = [0, 0];
    assert_eq_arrays(witness, expected_no_signature_witness);
    const witness2 = encode_witness(SignatureHashType.ALL, "signature_bytes");
    const expected_witness2 = [1, 1, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq_arrays(witness2, expected_witness2);

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
      if (!e.includes("The number of signatures does not match the number of inputs")) {
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

    let witnesses = [...witness, ...witness2];
    const signed_tx = encode_signed_transaction(tx, witnesses);
    const expected_signed_tx = [1, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 8, 1, 0, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 0, 145, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247, 158, 169, 100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60, 217, 2, 198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0, 8, 0, 0, 1, 1, 60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq_arrays(signed_tx, expected_signed_tx);
  }
}
