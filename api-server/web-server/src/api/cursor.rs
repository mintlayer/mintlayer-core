// Copyright (c) 2023 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://opensource.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Opaque keyset pagination cursors.
//!
//! A cursor marks the position of the last item of a page within the sorted result
//! set of a listing endpoint: the next page consists of the items strictly following
//! that position. A cursor carries the sort keys of the item as strings plus a
//! tie-break id and is rendered as an URL-safe, unpadded base64 encoding of its JSON
//! form, so that the internal sort order of the endpoint does not leak to the clients
//! and stays free to change.

use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::ApiServerWebServerClientError;

#[derive(Debug, Serialize, Deserialize)]
pub struct Cursor {
    /// Sort keys of the item the cursor points to.
    keys: Vec<String>,
    /// Unique tie-break id of the item.
    id: String,
}

impl Cursor {
    pub fn new(keys: Vec<String>, id: String) -> Self {
        Self { keys, id }
    }

    pub fn into_parts(self) -> (Vec<String>, String) {
        (self.keys, self.id)
    }

    pub fn encode(&self) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_string(self).expect("serialization must not fail"))
    }

    pub fn decode(encoded: &str) -> Result<Self, ApiServerWebServerClientError> {
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ApiServerWebServerClientError::InvalidCursor)?;
        serde_json::from_slice(&decoded).map_err(|_| ApiServerWebServerClientError::InvalidCursor)
    }

    /// Decodes a cursor request parameter. An empty value starts the listing from the
    /// beginning, so that a client can walk all the pages of a result set uniformly.
    pub fn decode_start(encoded: &str) -> Result<Option<Self>, ApiServerWebServerClientError> {
        if encoded.is_empty() {
            Ok(None)
        } else {
            Self::decode(encoded).map(Some)
        }
    }
}

/// Renders the listing response of a cursor-based request: the items of the page plus
/// the cursor of the last returned item, `null` when the result set is exhausted.
pub fn paged_response(
    items: Vec<serde_json::Value>,
    next_cursor: Option<Cursor>,
) -> serde_json::Value {
    serde_json::json!({
        "items": items,
        "next_cursor": next_cursor.map(|cursor| cursor.encode()),
    })
}
