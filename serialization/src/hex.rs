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

use serialization_core::{Decode, DecodeAll, Encode};

#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum HexError {
    #[error("Scale codec decode error: {0}")]
    ScaleDecodeError(#[from] serialization_core::Error),
    #[error("Hex decode error: {0}")]
    HexDecodeError(#[from] hex::FromHexError),
}

pub trait HexEncode: Encode + Sized {
    #[must_use]
    fn hex_encode(&self) -> String {
        hex::encode(self.encode())
    }
}

pub trait HexDecode: Decode + Sized {
    fn hex_decode_all<T: AsRef<str>>(data: T) -> Result<Self, HexError> {
        let unhexed = hex::decode(data.as_ref())?;
        let decoded = Self::decode_all(&mut unhexed.as_slice())?;
        Ok(decoded)
    }
}

impl<T: Encode + Sized> HexEncode for T {}
impl<T: Decode + Sized> HexDecode for T {}
