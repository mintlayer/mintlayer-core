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
fn value_hint_tagged() {
    #[derive(HasValueHint, serde::Serialize)]
    #[allow(unused)]
    enum Tagged {
        Int(u64),
        String(String),
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
fn interface_description() {
    const DESC: &Module = &super::SubsystemRpcDescription::DESCRIPTION;
    expect_file!["./SUBSYS_RPC.md"].assert_eq(&format!("{DESC}\n"));
}
