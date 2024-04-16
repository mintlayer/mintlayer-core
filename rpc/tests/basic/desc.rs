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

//! RPC description tests

use rpc::description::{Described, HasValueHint, Module, ValueHint as VH};

use expect_test::expect_file;
use serde_json::json;

#[test]
fn value_hint_trivial() {
    // Check trivial corner cases
    assert_eq!(VH::Prim("x").to_string(), "x");
    assert_eq!(VH::Choice(&[]).to_string(), "impossible");
    assert_eq!(VH::Object(&[]).to_string(), "{}");
}

#[test]
fn value_hint_render() {
    // Set up a rather convoluted value hint, check what its string representation is

    const AUTH_HINT: VH = VH::Choice(&[
        &VH::Object(&[
            ("username", &VH::Prim("string")),
            (
                "password",
                &VH::Choice(&[
                    &VH::STRING,
                    &VH::NULL,
                    &VH::Object(&[
                        ("password_file", &VH::STRING),
                        ("key", &VH::Choice(&[&VH::STRING, &VH::NUMBER, &VH::NULL])),
                    ]),
                ]),
            ),
        ]),
        &VH::Object(&[("cookie_file", &VH::STRING)]),
        &VH::NULL,
    ]);

    const COMMAND_HINT: VH = VH::Choice(&[
        &VH::Object(&[("launch_missiles", &VH::NUMBER)]),
        &VH::Prim("\"check_missile_stock\""),
    ]);

    const HINT: VH = VH::Object(&[("auth", &AUTH_HINT), ("command", &COMMAND_HINT)]);

    expect_file!["./HINT_RENDER.md"].assert_eq(&format!("{HINT}\n"));
}

#[test]
fn value_hint_tagged_plain() {
    #[derive(HasValueHint, serde::Serialize)]
    #[allow(unused)]
    enum Tagged {
        One,
        Two,
    }

    let actual = Tagged::HINT_SER.to_string();
    expect_file!["./HINT_TAGGED.txt"].assert_eq(&actual);
}

#[test]
fn value_hint_untagged() {
    #[derive(HasValueHint, serde::Serialize)]
    #[serde(untagged)]
    #[allow(unused)]
    enum Untagged {
        Int(u64),
        String(String),
    }

    let actual = Untagged::HINT_SER.to_string();
    expect_file!["./HINT_UNTAGGED.txt"].assert_eq(&actual);
}

#[test]
fn value_hint_adjacently_tagged() {
    #[derive(Debug, PartialEq, Eq, HasValueHint, serde::Serialize, serde::Deserialize)]
    #[allow(unused)]
    struct BigObject {
        field: String,
        maybe_number: Option<u64>,
        flag: bool,
    }

    #[derive(Debug, PartialEq, Eq, HasValueHint, serde::Serialize, serde::Deserialize)]
    #[serde(tag = "type", content = "content")]
    #[allow(unused)]
    enum AdjacentlyTagged {
        Hello,
        World,
        String { value: String },
        BigObject(BigObject),
    }

    let json_hello = serde_json::to_value(AdjacentlyTagged::Hello).unwrap();
    assert_eq!(json_hello, json!({"type": "Hello"}));
    assert_eq!(
        serde_json::from_value::<AdjacentlyTagged>(json_hello).unwrap(),
        AdjacentlyTagged::Hello
    );

    let json_string = serde_json::to_value(AdjacentlyTagged::String { value: "x".into() }).unwrap();
    assert_eq!(
        json_string,
        json!({"type": "String", "content": {"value": "x"}})
    );

    let hint = AdjacentlyTagged::HINT_SER.to_string();
    expect_file!["./HINT_ADJACENTLY_TAGGED.txt"].assert_eq(&hint);
}

#[test]
fn interface_description() {
    const DESC: &Module = &super::SubsystemRpcDescription::DESCRIPTION;
    expect_file!["./SUBSYS_RPC.md"].assert_eq(&format!("{DESC}\n"));
}
