// Copyright (c) 2021 RBB S.r.l
// opensource@mintlayer.org
// SPDX-License-Identifier: MIT
// Licensed under the MIT License;
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://spdx.org/licenses/MIT
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Author(s): S. Afach

// there's not particular reason for using blake2 here,
// but this saves us from adding digest manually to cargo
// and managing a different version
pub use blake2::digest::{
    generic_array::GenericArray, Digest, FixedOutputReset, OutputSizeUser, Reset, Update,
};

pub fn hash<D: Digest, T: AsRef<[u8]>>(
    in_bytes: T,
) -> GenericArray<u8, <D as OutputSizeUser>::OutputSize> {
    let mut hasher = D::new();
    hasher.update(in_bytes);
    hasher.finalize()
}

#[derive(Clone)]
pub struct InternalStreamHasher<D: Digest + Reset + FixedOutputReset> {
    hasher: D,
}

impl<D: Digest + Reset + FixedOutputReset> InternalStreamHasher<D> {
    pub fn new() -> Self {
        Self { hasher: D::new() }
    }

    pub fn write<T: AsRef<[u8]>>(&mut self, in_bytes: T) {
        Digest::update(&mut self.hasher, in_bytes);
    }

    pub fn reset(&mut self) {
        Digest::reset(&mut self.hasher)
    }

    pub fn finalize(&mut self) -> GenericArray<u8, <D as OutputSizeUser>::OutputSize> {
        self.hasher.finalize_reset()
    }
}
