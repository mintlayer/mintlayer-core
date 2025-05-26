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
  Amount,
  encode_create_order_output,
  encode_input_for_conclude_order,
  encode_input_for_fill_order,
  encode_input_for_freeze_order,
  Network,
} from "../../pkg/wasm_wrappers.js";

import {
  assert_eq_arrays,
  gen_random_int,
  get_err_msg,
} from "./utils.js";

import {
  ORDER_ID,
  ORDERS_V1_TESTNET_FORK_HEIGHT,
  TOKEN_ID,
} from "./defs.js";
import {
  ADDRESS
} from "./test_address_generation.js";

export async function test_orders() {
  const order_output = encode_create_order_output(
    Amount.from_atoms("40000"),
    undefined,
    Amount.from_atoms("10000"),
    TOKEN_ID,
    ADDRESS,
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
    TOKEN_ID,
    Amount.from_atoms("40000"),
    undefined,
    ADDRESS,
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

  // Note: the exact heights don't matter as long as they are at the "correct side" of the fork.
  const order_v0_height = gen_random_int(0, ORDERS_V1_TESTNET_FORK_HEIGHT - 1, "order_v0_height");
  const order_v1_height = order_v0_height + ORDERS_V1_TESTNET_FORK_HEIGHT;
  // Note: the nonce is ignored since orders v1.
  const order_v1_nonce = gen_random_int(0, 1000000, "order_v1_nonce");
  const fill_order_v0_input = encode_input_for_fill_order(
    ORDER_ID,
    Amount.from_atoms("40000"),
    ADDRESS,
    BigInt(1),
    BigInt(order_v0_height),
    Network.Testnet
  );
  const expected_fill_order_v0_input = [
    2, 4, 7, 49, 150, 254, 178, 75, 93, 83, 251,
    1, 235, 159, 200, 27, 237, 187, 175, 123, 34, 179,
    118, 53, 6, 173, 213, 7, 212, 102, 232, 253, 9,
    244, 197, 2, 113, 2, 0, 1, 91, 58, 110, 176,
    100, 207, 6, 194, 41, 193, 30, 91, 4, 195, 202,
    103, 207, 80, 217, 178
  ];

  assert_eq_arrays(fill_order_v0_input, expected_fill_order_v0_input);
  console.log("fill order v0 encoding ok");

  const fill_order_v1_input = encode_input_for_fill_order(
    ORDER_ID,
    Amount.from_atoms("40000"),
    ADDRESS,
    BigInt(order_v1_nonce),
    BigInt(order_v1_height),
    Network.Testnet
  );
  const expected_fill_order_v1_input = [
    3, 0, 49, 150, 254, 178, 75, 93,
    83, 251, 1, 235, 159, 200, 27, 237,
    187, 175, 123, 34, 179, 118, 53, 6,
    173, 213, 7, 212, 102, 232, 253, 9,
    244, 197, 2, 113, 2, 0, 1, 91,
    58, 110, 176, 100, 207, 6, 194, 41,
    193, 30, 91, 4, 195, 202, 103, 207,
    80, 217, 178
  ];

  assert_eq_arrays(fill_order_v1_input, expected_fill_order_v1_input);
  console.log("fill order v1 encoding ok");

  const conclude_order_v0_input = encode_input_for_conclude_order(
    ORDER_ID,
    BigInt(1),
    BigInt(order_v0_height),
    Network.Testnet
  );
  const expected_conclude_order_v0_input = [
    2, 4, 6, 49, 150, 254, 178, 75,
    93, 83, 251, 1, 235, 159, 200, 27,
    237, 187, 175, 123, 34, 179, 118, 53,
    6, 173, 213, 7, 212, 102, 232, 253,
    9, 244, 197
  ];

  assert_eq_arrays(conclude_order_v0_input, expected_conclude_order_v0_input);
  console.log("conclude order v0 encoding ok");

  const conclude_order_v1_input = encode_input_for_conclude_order(
    ORDER_ID,
    BigInt(order_v1_nonce),
    BigInt(order_v1_height),
    Network.Testnet
  );
  const expected_conclude_order_v1_input = [
    3, 2, 49, 150, 254, 178, 75, 93,
    83, 251, 1, 235, 159, 200, 27, 237,
    187, 175, 123, 34, 179, 118, 53, 6,
    173, 213, 7, 212, 102, 232, 253, 9,
    244, 197
  ];

  assert_eq_arrays(conclude_order_v1_input, expected_conclude_order_v1_input);
  console.log("conclude order v1 encoding ok");

  const freeze_order_input = encode_input_for_freeze_order(
    ORDER_ID,
    BigInt(order_v1_height),
    Network.Testnet
  );
  const expected_freeze_order_input = [
    3, 1, 49, 150, 254, 178, 75, 93,
    83, 251, 1, 235, 159, 200, 27, 237,
    187, 175, 123, 34, 179, 118, 53, 6,
    173, 213, 7, 212, 102, 232, 253, 9,
    244, 197
  ];

  assert_eq_arrays(freeze_order_input, expected_freeze_order_input);
  console.log("freeze order encoding ok");

  try {
    encode_input_for_freeze_order(
      ORDER_ID,
      BigInt(order_v0_height),
      Network.Testnet
    );
    throw new Error("Freezing an order before v1 worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Orders V1 not activated")) {
      throw e;
    }
    console.log("Tested order freezing before v1 successfully");
  }
}
