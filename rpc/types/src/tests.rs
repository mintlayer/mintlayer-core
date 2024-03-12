// Copyright (c) 2024 RBB S.r.l
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

use serde_json::json;

use super::*;

#[rstest::rstest]
#[case(&[0xab], "ab")]
#[case(&[0xab, 0xcd], "abcd")]
#[case(&[0x20, 0x80], "2080")]
#[case(&[0x22, 0x90], "2290")]
fn invalid_utf8(#[case] bytes: &[u8], #[case] hex: &str) {
    let rpc_out = RpcStringOut::from_bytes(bytes.to_vec());

    let json = serde_json::to_value(rpc_out).unwrap();
    let expected_json = json!({ "hex": hex, "text": null });
    assert_eq!(json, expected_json);

    let rpc_in_hex = json!({ "hex": hex });
    let rpc_in: RpcStringIn = serde_json::from_value(rpc_in_hex.clone()).unwrap();
    assert_eq!(rpc_in.as_ref(), bytes);
    assert_eq!(serde_json::to_value(&rpc_in).unwrap(), rpc_in_hex);
}

#[rstest::rstest]
#[case("", "")]
#[case(" ", "20")]
#[case("\t", "09")]
#[case("Hello!", "48656c6c6f21")]
fn valid_utf8(#[case] in_str: &str, #[case] hex: &str) {
    let rpc_out = RpcStringOut::from_string(in_str.to_string());
    let rpc_out_from_bytes = RpcStringOut::from_bytes(in_str.as_bytes().to_vec());
    assert_eq!(rpc_out, rpc_out_from_bytes);

    let json = serde_json::to_value(rpc_out).unwrap();
    let expected_json = json!({ "hex": hex, "text": in_str });
    assert_eq!(json, expected_json);

    let rpc_in_hex = json!({ "hex": hex });
    let rpc_in_hex_obj: RpcStringIn = serde_json::from_value(rpc_in_hex.clone()).unwrap();
    assert_eq!(rpc_in_hex_obj.as_ref(), in_str.as_bytes());
    assert_eq!(serde_json::to_value(&rpc_in_hex_obj).unwrap(), rpc_in_hex);

    let rpc_in_str = json!({ "text": in_str });
    let rpc_in_str_obj: RpcStringIn = serde_json::from_value(rpc_in_str).unwrap();
    assert_eq!(rpc_in_str_obj, rpc_in_hex_obj);

    let rpc_in_str_bare = serde_json::Value::from(in_str);
    let rpc_in_str_bare_obj: RpcStringIn = serde_json::from_value(rpc_in_str_bare).unwrap();
    assert_eq!(rpc_in_str_bare_obj, rpc_in_hex_obj);
}
