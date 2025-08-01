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
  run_one_test,
} from "./utils.js";

import { test_address_generation } from "./test_address_generation.js";
import { test_encode_other_inputs } from "./test_encode_other_inputs.js";
import { test_encode_other_outputs } from "./test_encode_other_outputs.js";
import { test_htlc } from "./test_htlc.js";
import { test_input_commitments } from "./test_input_commitments.js";
import { test_misc } from "./test_misc.js";
import { test_orders } from "./test_orders.js";
import { test_signed_transaction_intent } from "./test_signed_transaction_intent.js";
import { test_transaction_and_witness_encoding } from "./test_transaction_and_witness_encoding.js";

/** @public */
export function run_all_tests() {
  run_one_test(test_address_generation);
  run_one_test(test_encode_other_inputs);
  run_one_test(test_encode_other_outputs);
  run_one_test(test_htlc);
  run_one_test(test_input_commitments);
  run_one_test(test_misc);
  run_one_test(test_orders);
  run_one_test(test_signed_transaction_intent);
  run_one_test(test_transaction_and_witness_encoding);
}
