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

// Here we test inputs encoding, except for orders and htlcs, which have their separate test files.

import {
  Amount,
  encode_input_for_change_token_authority,
  encode_input_for_change_token_metadata_uri,
  encode_input_for_freeze_token,
  encode_input_for_lock_token_supply,
  encode_input_for_mint_tokens,
  encode_input_for_unfreeze_token,
  encode_input_for_unmint_tokens,
  encode_input_for_utxo,
  encode_input_for_withdraw_from_delegation,
  Network,
  TokenUnfreezable,
} from "../../pkg/wasm_wrappers.js";

import {
  assert_eq_arrays,
  get_err_msg,
  run_one_test,
  TEXT_ENCODER,
} from "./utils.js";

import {
  TOKEN_ID,
} from "./defs.js";
import {
  ADDRESS
} from "./test_address_generation.js";

// Some test inputs - a UTXO and a delegation withdrawal
export const INPUTS = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4,
];

// OutpointSourceId and index used in INPUTS.
export const TX_OUTPOINT_SOURCE_ID = new Uint8Array(33).fill(0);
export const TX_OUTPOINT_INDEX = 1;

export function test_encode_other_inputs() {
  run_one_test(predefined_inputs_test);
  run_one_test(general_test);
}

function predefined_inputs_test() {
  const tx_input = encode_input_for_utxo(TX_OUTPOINT_SOURCE_ID, TX_OUTPOINT_INDEX);
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

export function general_test() {
  try {
    encode_input_for_utxo(TEXT_ENCODER.encode("asd"), 1);
    throw new Error("Invalid outpoint encoding worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Invalid outpoint ID encoding")) {
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
    if (!get_err_msg(e).includes("Invalid addressable")) {
      throw e;
    }
    console.log("Tested invalid delegation id in account successfully");
  }

  const mint_tokens_input = encode_input_for_mint_tokens(
    TOKEN_ID,
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
    TOKEN_ID,
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
    TOKEN_ID,
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
    TOKEN_ID,
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
    TOKEN_ID,
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
    TOKEN_ID,
    ADDRESS,
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
    TOKEN_ID,
    ADDRESS,
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
}
