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
  encode_signed_transaction_intent,
  make_transaction_intent_message_to_sign,
  Network,
  sign_challenge,
  verify_transaction_intent,
} from "../../pkg/wasm_wrappers.js";

import {
  get_err_msg,
  assert_eq_arrays,
  TEXT_ENCODER,
} from "./utils.js";

export function test_signed_transaction_intent() {
  try {
    const invalid_tx_id = "invalid tx id";
    make_transaction_intent_message_to_sign("intent", invalid_tx_id);
    throw new Error("Invalid tx id worked somehow!");
  } catch (e) {
    if (!get_err_msg(e).includes("Error parsing transaction id")) {
      throw e;
    }
  }

  const tx_id = "DFC2BB0CC4C7F3ED3FE682A48EE9F78BCD4962E55E7BC239BD340EC22AFF8657";
  const message = make_transaction_intent_message_to_sign("the intent", tx_id);
  const expected_message = TEXT_ENCODER.encode(
    "<tx_id:dfc2bb0cc4c7f3ed3fe682a48ee9f78bcd4962e55e7bc239bd340ec22aff8657;intent:the intent>");
  assert_eq_arrays(message, expected_message);

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

    const signature1 = sign_challenge(Uint8Array.from(prv_key1), message);
    const signature2 = sign_challenge(Uint8Array.from(prv_key2), message);

    const signed_intent = encode_signed_transaction_intent(message, [signature1, signature2]);

    verify_transaction_intent(message, signed_intent, [pubkey_addr1, pubkeyhash_addr2], Network.Regtest);
    verify_transaction_intent(message, signed_intent, [pubkeyhash_addr1, pubkey_addr2], Network.Regtest);

    try {
      verify_transaction_intent(message, signed_intent, [pubkeyhash_addr2, pubkey_addr1], Network.Regtest);
      throw new Error("Mismatched addresses worked somehow!");
    } catch (e) {
      if (!get_err_msg(e).includes("Public key to public key hash mismatch")) {
        throw e;
      }
    }

    const bad_signature1 = sign_challenge(Uint8Array.from(prv_key1), Uint8Array.from([...message, 123]));
    const bad_signed_intent = encode_signed_transaction_intent(message, [bad_signature1, signature2]);

    try {
      verify_transaction_intent(message, bad_signed_intent, [pubkey_addr1, pubkey_addr2], Network.Regtest);
      throw new Error("Bad signature worked somehow!");
    } catch (e) {
      if (!get_err_msg(e).includes("Signature verification failed")) {
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
      encode_signed_transaction_intent(message, [Uint8Array.from(signature1), Uint8Array.from(signature2)]);
    assert_eq_arrays(encoded_signed_intent, expected_encoded_signed_intent);
  }
}
