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

use serde_json::{from_value, json};

use super::*;

#[rstest::rstest]
#[case(&[0xab], "ab")]
#[case(&[0xab, 0xcd], "abcd")]
#[case(&[0x20, 0x80], "2080")]
#[case(&[0x22, 0x90], "2290")]
fn invalid_utf8(#[case] bytes: &[u8], #[case] hex: &str) {
    let rpc_str = RpcString::from_bytes(bytes.to_vec());

    let json = serde_json::to_value(rpc_str).unwrap();
    let expected_json = json!({ "hex": hex, "text": null });
    assert_eq!(json, expected_json);

    let from_json: RpcString = from_value(json).unwrap();
    assert_eq!(from_json.as_ref(), bytes);
}

#[rstest::rstest]
#[case("", "")]
#[case(" ", "20")]
#[case("\t", "09")]
#[case("Hello!", "48656c6c6f21")]
fn valid_utf8(#[case] in_str: &str, #[case] hex: &str) {
    let from_bytes = RpcString::from_bytes(hex::decode(hex).unwrap());
    let from_str = RpcString::from_string(in_str.to_string());
    assert_eq!(from_str, from_bytes);

    let json = json!({ "hex": hex, "text": in_str });
    assert_eq!(serde_json::to_value(&from_str).unwrap(), json);
    assert_eq!(from_value::<RpcString>(json).unwrap(), from_str);

    let hex_json = json!({ "hex": hex });
    assert_eq!(from_value::<RpcString>(hex_json).unwrap(), from_str);

    let text_json = json!({ "text": in_str });
    assert_eq!(from_value::<RpcString>(text_json).unwrap(), from_str);

    let str_json = in_str.to_string().into();
    assert_eq!(from_value::<RpcString>(str_json).unwrap(), from_str);
}

#[rstest::rstest]
#[case("", "00")]
#[case(" ", "21")]
#[case("Hello!", "48656c6c6f")]
fn hex_text_mismatch(#[case] in_str: &str, #[case] hex: &str) {
    let json = json!({ "hex": hex, "text": in_str });
    assert!(from_value::<RpcString>(json).is_err());
}

#[test]
fn empty_obj() {
    assert!(from_value::<RpcString>(json!({})).is_err());
}
