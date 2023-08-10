// Copyright (c) 2023 RBB S.r.l
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

use std::{fmt::Display, str::FromStr};

/// Wrapper that serializes objects as json encoded string for `serde`
#[derive(Debug, Clone)]
pub struct JsonEncoded<T>(T);

impl<T> JsonEncoded<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn take(self) -> T {
        self.0
    }
}

impl<'de, T: serde::Deserialize<'de>> JsonEncoded<T> {
    // We cannot use FromStr because of the lifetime limitation
    pub fn from_string_slice(s: &'de str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }
}

impl<T> AsRef<T> for JsonEncoded<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for JsonEncoded<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: serde::Serialize> serde::Serialize for JsonEncoded<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<T: for<'de> serde::Deserialize<'de>> FromStr for JsonEncoded<T> {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s).map(Self)
    }
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for JsonEncoded<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self)
    }
}

impl<T: serde::Serialize> Display for JsonEncoded<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            &serde_json::to_string(&self.0).unwrap_or("<Json serialization error>".to_string()),
        )
    }
}
