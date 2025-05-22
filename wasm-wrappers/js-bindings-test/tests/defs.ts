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

// Here we have some definitions that are used by other tests, as well as tests
// that check those definitions (if needed).

import {
  Amount,
  Network,
  make_private_key,
  public_key_from_private_key,
  make_default_account_privkey,
  make_receiving_address,
  pubkey_to_pubkeyhash_address,
  encode_input_for_utxo,
  encode_input_for_withdraw_from_delegation,
  encode_lock_until_height,
  encode_output_lock_then_transfer,
  encode_output_create_stake_pool,
  encode_stake_pool_data,
} from "../../pkg/wasm_wrappers.js";

import {
  TEXT_ENCODER,
  assert_eq_arrays,
  get_err_msg,
} from "./utils.js";

// Taken from TESTNET_FORK_HEIGHT_5_ORDERS_V1 in common/src/chain/config/builder.rs.
// This will be updated to the actual height after we choose one.
export const ORDERS_V1_TESTNET_FORK_HEIGHT = 999_999_999;

export const MNEMONIC =
  "walk exile faculty near leg neutral license matrix maple invite cupboard hat opinion excess coffee leopard latin regret document core limb crew dizzy movie";

// A random private key that is generated only once and printed to the console.
// Note: simply putting `const PRIVATE_KEY = make_private_key()` to the global scope won't
// work if the tests are run in the browser.
export const get_predefined_prv_key = (function () {
  let PRIVATE_KEY: Uint8Array | null = null;
  return function () {
    if (!PRIVATE_KEY) {
      PRIVATE_KEY = make_private_key();
      console.log(`PRIVATE_KEY = ${PRIVATE_KEY}`);
    }
    return PRIVATE_KEY;
  }
})();

// The public key corresponding to get_predefined_prv_key().
export const get_predefined_pub_key = (function () {
  let PUBLIC_KEY: Uint8Array | null = null;
  return function () {
    if (!PUBLIC_KEY) {
      PUBLIC_KEY = public_key_from_private_key(get_predefined_prv_key());
      console.log(`PUBLIC_KEY = ${PUBLIC_KEY}`);
    }
    return PUBLIC_KEY;
  }
})();

// Some address.
// It corresponds to `make_receiving_address(make_default_account_privkey(MNEMONIC,Network.Testnet), 0)`,
// but most tests don't care.
export const ADDRESS = "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n";

// Some token id.
export const TOKEN_ID =
  "tmltk15tgfrs49rv88v8utcllqh0nvpaqtgvn26vdxhuner5m6ewg9c3msn9fxns";

// Some test inputs - a UTXO and a delegation withdrawal
export const INPUTS = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
];

// OutpointSourceId used in INPUTS.
export const TX_OUTPOINT = new Uint8Array(33).fill(0)

export const OUTPUT_LOCK_THEN_TRANSFER = [
  1, 0, 145, 1, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4,
  195, 202, 103, 207, 80, 217, 178, 0, 145, 1
];

export const OUTPUT_CREATE_STAKE_POOL = [
  3, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
  113, 2, 0, 1, 91, 58, 110, 176, 100, 207, 6, 194, 41, 193, 30, 91, 4, 195,
  202, 103, 207, 80, 217, 178, 0, 108, 245, 234, 97, 170, 9, 247, 158, 169,
  100, 84, 123, 235, 183, 147, 29, 136, 118, 203, 24, 146, 56, 60, 217, 2,
  198, 32, 133, 255, 240, 84, 123, 1, 91, 58, 110, 176, 100, 207, 6, 194,
  41, 193, 30, 91, 4, 195, 202, 103, 207, 80, 217, 178, 100, 0, 0,
];

// Some tx outputs - LockThenTransfer and CreateStakePool
export const OUTPUTS = [...OUTPUT_LOCK_THEN_TRANSFER, ...OUTPUT_CREATE_STAKE_POOL];

export async function test_predefined_address() {
  const account_private_key = make_default_account_privkey(
    MNEMONIC,
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
  if (address != ADDRESS) {
    throw new Error("Incorrect address generated");
  }
}

export async function test_encode_predefined_inputs() {
  const tx_input = encode_input_for_utxo(TX_OUTPOINT, 1);
  const deleg_id =
    "mdelg1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqut3aj8";
  const tx_input2 = encode_input_for_withdraw_from_delegation(
    deleg_id,
    Amount.from_atoms("1"),
    BigInt(1),
    Network.Mainnet
  );
  const inputs = [...tx_input, ...tx_input2];
  assert_eq_arrays(inputs, INPUTS);
}

export async function test_encode_predefined_outputs() {
  const vrf_public_key =
    "tvrfpk1qpk0t6np4gyl084fv328h6ahjvwcsaktrzfrs0xeqtrzpp0l7p28knrnn57";

  const pool_data = encode_stake_pool_data(
    Amount.from_atoms("40000"),
    ADDRESS,
    vrf_public_key,
    ADDRESS,
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

  const lock = encode_lock_until_height(BigInt(100));
  const output = encode_output_lock_then_transfer(
    Amount.from_atoms("100"),
    ADDRESS,
    lock,
    Network.Testnet
  );

  const pool_id =
    "tpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqza035u";
  try {
    const invalid_pool_data = TEXT_ENCODER.encode("invalid pool data");
    encode_output_create_stake_pool(
      pool_id,
      invalid_pool_data,
      Network.Testnet
    );
    throw new Error("Invalid pool data worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid stake pool data encoding")) {
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

  assert_eq_arrays(outputs, OUTPUTS);
}
