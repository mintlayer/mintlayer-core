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
  encode_transaction,
  decode_transaction_to_js,
  Network,
} from "../../pkg/wasm_wrappers.js";

import { assert_eq_vals } from "./utils.js";
import { INPUTS } from "./test_encode_other_inputs.js";
import { OUTPUTS } from "./test_encode_other_outputs.js";

export function test_decode_transaction_to_js() {
  const tx = encode_transaction(
    Uint8Array.from(INPUTS),
    Uint8Array.from(OUTPUTS),
    BigInt(0),
  );

  const decoded_tx = decode_transaction_to_js(tx, Network.Testnet);

  const expected_decoded_tx = {
    V1: {
      version: 1,
      flags: 0,
      inputs: [
        {
          Utxo: {
            id: {
              Transaction:
                "0000000000000000000000000000000000000000000000000000000000000000",
            },
            index: 1,
          },
        },
        {
          Account: {
            nonce: 1,
            account: {
              DelegationBalance: [
                "tdelg1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqnu8zn4",
                { atoms: "1" },
              ],
            },
          },
        },
      ],
      outputs: [
        {
          LockThenTransfer: [
            { Coin: { atoms: "100" } },
            "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n",
            { type: "UntilHeight", content: 100 },
          ],
        },
        {
          CreateStakePool: [
            "tpool1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqza035u",
            {
              pledge: { atoms: "40000" },
              staker:
                "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n",
              vrf_public_key:
                "006cf5ea61aa09f79ea964547bebb7931d8876cb1892383cd902c62085fff0547b",
              decommission_key:
                "tmt1q9dn5m4svn8sds3fcy09kpxrefnu75xekgr5wa3n",
              margin_ratio_per_thousand: "10%",
              cost_per_block: { atoms: "0" },
            },
          ],
        },
      ],
    },
  };

  assert_eq_vals(
    JSON.stringify(decoded_tx),
    JSON.stringify(expected_decoded_tx),
  );

  console.log("unsigned transaction decoding ok");
}