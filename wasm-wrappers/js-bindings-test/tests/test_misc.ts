// Copyright (c) 2021-2025 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/mintlayer/mintlayer-core/blob/master/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import {
  make_private_key,
  public_key_from_private_key,
  sign_message_for_spending,
  verify_signature_for_spending,
  make_default_account_privkey,
  pubkey_to_pubkeyhash_address,
  Network,
  staking_pool_spend_maturity_block_count,
  get_transaction_id,
  effective_pool_balance,
  Amount,
  sign_challenge,
  verify_challenge,
  get_token_id,
} from "../../pkg/wasm_wrappers.js";

import {
  TEXT_ENCODER,
  run_one_test,
  get_err_msg,
} from "./utils.js";

import {
  get_predefined_prv_key,
  get_predefined_pub_key,
} from "./defs.js";
import {
  INPUTS,
} from "./test_encode_other_inputs.js";

export async function test_misc() {
  run_one_test(test_verify_signature_for_spending);
  run_one_test(test_public_key_from_bad_private_key);
  run_one_test(test_make_default_account_privkey_from_bad_mnemonic);
  run_one_test(test_sign_challenge);
  run_one_test(test_staking_pool_spend_maturity_block_count);
  run_one_test(test_get_token_id);
  run_one_test(test_effective_pool_balance);
  run_one_test(test_get_transaction_id);
}

async function test_verify_signature_for_spending() {
  const prv_key = get_predefined_prv_key();
  const pub_key = get_predefined_pub_key();
  const message = TEXT_ENCODER.encode("Hello, world!");

  const signature = sign_message_for_spending(prv_key, message);

  const verified = verify_signature_for_spending(pub_key, signature, message);

  if (!verified) {
    throw new Error("Signature verification failed!");
  }
  const verified_bad = verify_signature_for_spending(
    pub_key,
    signature,
    TEXT_ENCODER.encode("bro!")
  );
  if (verified_bad) {
    throw new Error("Invalid message signature verification passed!");
  }
}

async function test_public_key_from_bad_private_key() {
  // Attempt to use a bad private key to get a public key (test returned Result<> object, which will become a string error)
  const bad_priv_key = TEXT_ENCODER.encode("bad");
  try {
    public_key_from_private_key(bad_priv_key);
    throw new Error("Invalid private key worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid private key encoding")) {
      throw new Error(
        "Invalid private key resulted in an unexpected error message!"
      );
    }
    console.log("Tested decoding bad private key successfully");
  }
}

async function test_make_default_account_privkey_from_bad_mnemonic() {
  try {
    const invalid_mnemonic = "asd asd";
    make_default_account_privkey(invalid_mnemonic, Network.Mainnet);
    throw new Error("Invalid mnemonic worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid mnemonic string")) {
      throw e;
    }
    console.log("Tested invalid mnemonic successfully");
  }
}

async function test_sign_challenge() {
  const prv_key = get_predefined_prv_key();
  const pub_key = get_predefined_pub_key();
  const message = TEXT_ENCODER.encode("Hello, world!");

  let challenge = sign_challenge(prv_key, message);
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
    if (!get_err_msg(e).includes("Public key to public key hash mismatch")) {
      throw e;
    }
    console.log("Tested verify with different address successfully");
  }
}

async function test_staking_pool_spend_maturity_block_count() {
  const lock_for_blocks = staking_pool_spend_maturity_block_count(
    BigInt(1000),
    Network.Mainnet
  );
  console.log(`lock for blocks ${lock_for_blocks}`);
  if (lock_for_blocks != BigInt(7200)) {
    throw new Error("Incorrect lock for blocks");
  }
}

async function test_get_token_id() {
  try {
    get_token_id(new Uint8Array(), BigInt(1), Network.Testnet);
    throw "Token Id generated without a UTXO input somehow!";
  } catch (e) {
    const msg = get_err_msg(e);
    if (!(msg.includes("No UTXO inputs for token id creation") ||
      msg.includes("No inputs for token id creation"))) {
      throw e;
    }
    console.log("Tested no UTXO inputs for token ID successfully");
  }

  {
    const expected_token_id =
      "tmltk13cncdptay55g9ajhrkaw0fp46r0tspq9kptul8vj2q7yvd69n4zsl24gea";
    const token_id = get_token_id(Uint8Array.from(INPUTS), BigInt(1), Network.Testnet);
    console.log(token_id);

    if (token_id != expected_token_id) {
      throw new Error("Different token id");
    }
  }
}

async function test_effective_pool_balance() {
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
    const tx_id = get_transaction_id(Uint8Array.from(tx_bin), true);
    if (tx_id != expected_tx_id) {
      throw new Error(
        `Decoded transaction id mismatch: ${tx_id} != ${expected_tx_id}`
      );
    }
  }

  {
    const tx_id = get_transaction_id(Uint8Array.from(tx_bin), false);
    if (tx_id != expected_tx_id) {
      throw new Error(
        `Decoded transaction id mismatch: ${tx_id} != ${expected_tx_id}`
      );
    }
  }

  {
    const tx_id = get_transaction_id(Uint8Array.from(tx_signed_bin), false);
    if (tx_id != expected_tx_id) {
      throw new Error(
        `Decoded transaction id mismatch: ${tx_id} != ${expected_tx_id}`
      );
    }
  }

  {
    try {
      get_transaction_id(Uint8Array.from(tx_signed_bin), true);
      throw new Error("Invalid witnesses worked somehow!");
    } catch (e) {
      if (!get_err_msg(e).includes("Invalid transaction encoding")) {
        throw new Error(
          "Invalid transaction encoding resulted in an unexpected error message!"
        );
      }
    }
  }
}
