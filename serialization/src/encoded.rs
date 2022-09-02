// Copyright (c) 2022 RBB S.r.l
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

use super::{Decode, DecodeAll, Encode, EncodeLike};

/// A valid SCALE-encoded representation of some type T
///
/// The user can basically do two useful things with this:
/// 1. Ask for raw encoding as a byte string using [Self::bytes]
/// 2. Get the decoded value using [Self::decode]
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Encoded<E, T> {
    bytes: E,
    _phantom: std::marker::PhantomData<fn() -> T>,
}

impl<T: Encode> Encoded<Vec<u8>, T> {
    /// Create from an object
    pub fn new<O: EncodeLike<T>>(obj: O) -> Self {
        let bytes = obj.encode();
        let _phantom = Default::default();
        Self { bytes, _phantom }
    }
}

impl<E: AsRef<[u8]>, T: Decode> Encoded<E, T> {
    /// Create `Encoded` from raw encoding. It is responsibility of the caller to ensure the byte
    /// sequence constitutes a valid encoding of an object of type `T`.
    pub fn from_bytes_unchecked(bytes: E) -> Self {
        let _phantom = Default::default();
        let this = Self { bytes, _phantom };
        debug_assert!(T::decode_all(&mut this.bytes()).is_ok());
        this
    }

    /// Take encoded byte representation
    pub fn take_bytes(self) -> E {
        self.bytes
    }

    /// Get encoded byte representation
    pub fn bytes(&self) -> &[u8] {
        self.as_ref()
    }

    /// Get the decoded object
    pub fn decode(&self) -> T {
        T::decode_all(&mut self.bytes()).expect("to be a valid encoding")
    }
}

impl<E: AsRef<[u8]>, T> AsRef<[u8]> for Encoded<E, T> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}
