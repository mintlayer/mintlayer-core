// Copyright (c) 2022 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Hash an object by its encoding

use crypto::hash::StreamHasher;
use serialization::Encode;

/// Feed an encoded version of the object into a stream hasher
pub fn hash_encoded_to<T: Encode, H: StreamHasher>(val: &T, hasher: &mut H) {
    val.encode_to(&mut HashWriter(hasher))
}

// A bridge from std::io::Write to HashStream. Private as to not expose the Writer methods
// externally to avoid exposing (potentially platform-specific) formatting methods.
struct HashWriter<'a, H: StreamHasher>(&'a mut H);

impl<'a, H: StreamHasher> std::io::Write for HashWriter<'a, H> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
